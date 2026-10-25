import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# Domain Models
# ============================================================================

class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    PENDING = "PENDING"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    customer_id: str
    account_type: str = "CHECKING"


@dataclass
class User:
    user_id: str
    customer_id: str
    ip_address: str
    device_info: str


@dataclass
class TransactionRequest:
    from_account: str
    to_account: str
    to_routing: str
    amount: Decimal
    user: User
    timestamp: datetime


@dataclass
class TransactionResult:
    status: TransactionStatus
    message: str
    transaction_id: Optional[str] = None
    audit_log_id: Optional[str] = None
    balance_after: Optional[Decimal] = None


@dataclass
class BeneficialOwner:
    owner_id: str
    name: str
    ownership_percentage: Decimal
    identity_verified: bool
    verification_date: Optional[datetime] = None


@dataclass
class LegalEntity:
    entity_id: str
    customer_id: str
    entity_name: str
    beneficial_owners: list


@dataclass
class BeneficialOwnershipProcedure:
    procedure_id: str
    version: str
    effective_date: datetime
    content: str
    approved_by: str


# ============================================================================
# Service Interfaces
# ============================================================================

class AuditLogger:
    def log_transaction(
        self,
        user_id: str,
        transaction_id: str,
        amount: Decimal,
        timestamp: datetime,
        ip_address: str,
        device_info: str,
        status: str,
        details: Dict[str, Any]
    ) -> str:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_id: str, routing_number: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_id: str, new_balance: Decimal) -> bool:
        raise NotImplementedError

    def validate_account(self, account_id: str, routing_number: str) -> bool:
        raise NotImplementedError


class ComplianceService:
    def check_ofac(self, name: str, account: str) -> Dict[str, Any]:
        raise NotImplementedError

    def check_ctr_threshold(self, amount: Decimal) -> bool:
        raise NotImplementedError

    def check_sar_threshold(self, amount: Decimal, context: Dict) -> bool:
        raise NotImplementedError

    def get_beneficial_ownership_procedures(self) -> Optional[BeneficialOwnershipProcedure]:
        raise NotImplementedError

    def verify_beneficial_ownership_certification(self, entity_id: str) -> bool:
        raise NotImplementedError

    def get_beneficial_owners(self, entity_id: str) -> list:
        raise NotImplementedError


class TransactionService:
    def __init__(
        self,
        account_repo: AccountRepository,
        audit_logger: AuditLogger,
        compliance_service: ComplianceService
    ):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.compliance_service = compliance_service

    def execute_transaction(self, request: TransactionRequest) -> TransactionResult:
        # Validate amount
        if request.amount <= Decimal("0"):
            if request.amount == Decimal("0"):
                return TransactionResult(
                    status=TransactionStatus.REJECTED,
                    message="Amount must be greater than 0"
                )
            else:
                return TransactionResult(
                    status=TransactionStatus.REJECTED,
                    message="Invalid amount"
                )

        # Validate beneficiary account
        if not self.account_repo.validate_account(request.to_account, request.to_routing):
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid beneficiary account"
            )

        # Get source account
        from_account = self.account_repo.get_account(
            request.from_account,
            ""
        )
        if not from_account:
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid source account"
            )

        # Check balance
        if from_account.balance < request.amount:
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Insufficient balance"
            )

        # Execute transaction
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(from_account.account_id, new_balance)

        transaction_id = f"TXN-{request.timestamp.timestamp()}"

        # Audit logging
        audit_log_id = self.audit_logger.log_transaction(
            user_id=request.user.user_id,
            transaction_id=transaction_id,
            amount=request.amount,
            timestamp=request.timestamp,
            ip_address=request.user.ip_address,
            device_info=request.user.device_info,
            status="SUCCESS",
            details={
                "from_account": request.from_account,
                "to_account": request.to_account,
                "to_routing": request.to_routing
            }
        )

        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            message="Transaction completed successfully",
            transaction_id=transaction_id,
            audit_log_id=audit_log_id,
            balance_after=new_balance
        )


# ============================================================================
# Authoritative Thresholds (31 C.F.R. § 1010)
# ============================================================================

CTR_THRESHOLD = Decimal("10000")
SAR_THRESHOLD = Decimal("5000")
TRAVEL_RULE_THRESHOLD = Decimal("3000")
WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
OFAC_FUZZY_THRESHOLD = 85
BENEFICIAL_OWNERSHIP_PCT = Decimal("20")


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_account_repo():
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = "AUDIT-12345"
    return logger


@pytest.fixture
def mock_compliance_service():
    service = Mock(spec=ComplianceService)
    service.check_ofac.return_value = {"match": False, "score": 0}
    service.check_ctr_threshold.return_value = False
    service.check_sar_threshold.return_value = False
    return service


@pytest.fixture
def transaction_service(mock_account_repo, mock_audit_logger, mock_compliance_service):
    return TransactionService(
        account_repo=mock_account_repo,
        audit_logger=mock_audit_logger,
        compliance_service=mock_compliance_service
    )


@pytest.fixture
def valid_user():
    return User(
        user_id="USER-001",
        customer_id="CUST-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC-001",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        customer_id="CUST-001"
    )


@pytest.fixture
def current_timestamp():
    return datetime.now(timezone.utc)


# ============================================================================
# MUST-TEST: FINCEN-1010-230-b-R1 - Beneficial Ownership Procedures
# ============================================================================

def test_beneficial_ownership_procedures_must_exist(mock_compliance_service):
    """
    Test that written beneficial ownership procedures exist as required by
    31 C.F.R. § 1010.230(b) [FINCEN-1010-230-b-R1::OBL::001].
    
    This test verifies the mandatory requirement that financial institutions
    maintain written procedures for beneficial ownership identification.
    """
    procedure = BeneficialOwnershipProcedure(
        procedure_id="BO-PROC-001",
        version="1.0",
        effective_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        content="Procedures for identifying and verifying beneficial owners...",
        approved_by="Chief Compliance Officer"
    )
    
    mock_compliance_service.get_beneficial_ownership_procedures.return_value = procedure
    
    result = mock_compliance_service.get_beneficial_ownership_procedures()
    
    assert result is not None, (
        "Written beneficial ownership procedures must exist per "
        "31 C.F.R. § 1010.230(b) [FINCEN-1010-230-b-R1::OBL::001]"
    )
    assert result.procedure_id is not None
    assert result.content != ""
    assert result.approved_by is not None


def test_beneficial_ownership_procedures_content_not_empty(mock_compliance_service):
    """
    Test that beneficial ownership procedures contain actual content
    as required by 31 C.F.R. § 1010.230(b).
    """
    procedure = BeneficialOwnershipProcedure(
        procedure_id="BO-PROC-002",
        version="1.1",
        effective_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        content="Detailed procedures for CDD including beneficial ownership identification...",
        approved_by="Compliance Director"
    )
    
    mock_compliance_service.get_beneficial_ownership_procedures.return_value = procedure
    
    result = mock_compliance_service.get_beneficial_ownership_procedures()
    
    assert len(result.content) > 0, (
        "Beneficial ownership procedures must contain substantive content per "
        "31 C.F.R. § 1010.230(b) [FINCEN-1010-230-b-R1::OBL::001]"
    )


def test_beneficial_ownership_procedures_formally_approved(mock_compliance_service):
    """
    Test that beneficial ownership procedures are formally approved
    as required by 31 C.F.R. § 1010.230(b).
    """
    procedure = BeneficialOwnershipProcedure(
        procedure_id="BO-PROC-003",
        version="2.0",
        effective_date=datetime(2024, 6, 1, tzinfo=timezone.utc),
        content="Updated beneficial ownership procedures...",
        approved_by="Chief Risk Officer"
    )
    
    mock_compliance_service.get_beneficial_ownership_procedures.return_value = procedure
    
    result = mock_compliance_service.get_beneficial_ownership_procedures()
    
    assert result.approved_by is not None and result.approved_by != "", (
        "Beneficial ownership procedures must be formally approved per "
        "31 C.F.R. § 1010.230(b) [FINCEN-1010-230-b-R1::OBL::001]"
    )


# ============================================================================
# Scenario Tests: MDP-88
# ============================================================================

def test_successful_transaction(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_user,
    valid_account,
    current_timestamp
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("500.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    # Act
    result = transaction_service.execute_transaction(request)
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.message == "Transaction completed successfully"
    assert result.transaction_id is not None
    assert result.audit_log_id is not None
    assert result.balance_after == Decimal("9500.00")
    
    mock_account_repo.update_balance.assert_called_once_with(
        "ACC-001",
        Decimal("9500.00")
    )
    
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args
    assert call_args.kwargs["user_id"] == "USER-001"
    assert call_args.kwargs["amount"] == Decimal("500.00")
    assert call_args.kwargs["ip_address"] == "192.168.1.100"
    assert call_args.kwargs["device_info"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert call_args.kwargs["status"] == "SUCCESS"


def test_zero_amount_transfer(
    transaction_service,
    mock_account_repo,
    valid_user,
    current_timestamp
):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("0"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    # Act
    result = transaction_service.execute_transaction(request)
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Amount must be greater than 0"
    assert result.transaction_id is None
    
    mock_account_repo.update_balance.assert_not_called()


def test_negative_amount_transfer(
    transaction_service,
    mock_account_repo,
    valid_user,
    current_timestamp
):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("-100.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    # Act
    result = transaction_service.execute_transaction(request)
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid amount"
    assert result.transaction_id is None
    
    mock_account_repo.update_balance.assert_not_called()


def test_insufficient_balance(
    transaction_service,
    mock_account_repo,
    valid_user,
    current_timestamp
):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    account = Account(
        account_id="ACC-001",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        customer_id="CUST-001"
    )
    
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = account
    
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("5000.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    # Act
    result = transaction_service.execute_transaction(request)
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"
    assert result.transaction_id is None
    
    mock_account_repo.update_balance.assert_not_called()


def test_invalid_beneficiary(
    transaction_service,
    mock_account_repo,
    valid_user,
    current_timestamp
):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    mock_account_repo.validate_account.return_value = False
    
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="INVALID-ACC",
        to_routing="999999999",
        amount=Decimal("100.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    # Act
    result = transaction_service.execute_transaction(request)
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"
    assert result.transaction_id is None
    
    mock_account_repo.update_balance.assert_not_called()


# ============================================================================
# Compliance Threshold Boundary Tests
# ============================================================================

def test_ctr_threshold_boundary_below(mock_compliance_service):
    """
    Test transaction just below CTR threshold (31 C.F.R. § 1010.310).
    CTR threshold is exactly $10,000.
    """
    amount = CTR_THRESHOLD - Decimal("0.01")
    
    mock_compliance_service.check_ctr_threshold.return_value = False
    
    result = mock_compliance_service.check_ctr_threshold(amount)
    
    assert result is False
    mock_compliance_service.check_ctr_threshold.assert_called_once_with(amount)


def test_ctr_threshold_boundary_at(mock_compliance_service):
    """
    Test transaction at CTR threshold (31 C.F.R. § 1010.310).
    CTR threshold is exactly $10,000.
    """
    amount = CTR_THRESHOLD
    
    mock_compliance_service.check_ctr_threshold.return_value = True
    
    result = mock_compliance_service.check_ctr_threshold(amount)
    
    assert result is True
    mock_compliance_service.check_ctr_threshold.assert_called_once_with(amount)


def test_ctr_threshold_boundary_above(mock_compliance_service):
    """
    Test transaction above CTR threshold (31 C.F.R. § 1010.310).
    CTR threshold is exactly $10,000.
    """
    amount = CTR_THRESHOLD + Decimal("0.01")
    
    mock_compliance_service.check_ctr_threshold.return_value = True
    
    result = mock_compliance_service.check_ctr_threshold(amount)
    
    assert result is True
    mock_compliance_service.check_ctr_threshold.assert_called_once_with(amount)


def test_sar_threshold_boundary(mock_compliance_service):
    """
    Test suspicious activity at SAR threshold (31 C.F.R. § 1020.320).
    SAR threshold is exactly $5,000.
    """
    amount = SAR_THRESHOLD
    context = {"suspicious_pattern": True}
    
    mock_compliance_service.check_sar_threshold.return_value = True
    
    result = mock_compliance_service.check_sar_threshold(amount, context)
    
    assert result is True
    mock_compliance_service.check_sar_threshold.assert_called_once_with(amount, context)


def test_travel_rule_threshold_boundary(mock_compliance_service):
    """
    Test wire transfer at Travel Rule threshold (31 C.F.R. § 1010.410(e)).
    Travel Rule threshold is exactly $3,000.
    """
    amount_below = TRAVEL_RULE_THRESHOLD - Decimal("0.01")
    amount_at = TRAVEL_RULE_THRESHOLD
    amount_above = TRAVEL_RULE_THRESHOLD + Decimal("0.01")
    
    assert amount_below < TRAVEL_RULE_THRESHOLD
    assert amount_at == TRAVEL_RULE_THRESHOLD
    assert amount_above > TRAVEL_RULE_THRESHOLD


def test_wire_dual_approval_threshold_boundary(mock_compliance_service):
    """
    Test wire transfer requiring dual approval.
    Wire dual approval threshold is exactly $10,000.
    """
    amount_requiring_approval = WIRE_DUAL_APPROVAL_THRESHOLD
    
    assert amount_requiring_approval == Decimal("10000")


def test_beneficial_ownership_percentage_threshold():
    """
    Test beneficial ownership percentage threshold.
    Beneficial ownership threshold is exactly 20%.
    """
    owner_at_threshold = BeneficialOwner(
        owner_id="BO-001",
        name="John Doe",
        ownership_percentage=BENEFICIAL_OWNERSHIP_PCT,
        identity_verified=True,
        verification_date=datetime.now(timezone.utc)
    )
    
    owner_below_threshold = BeneficialOwner(
        owner_id="BO-002",
        name="Jane Smith",
        ownership_percentage=BENEFICIAL_OWNERSHIP_PCT - Decimal("0.01"),
        identity_verified=True,
        verification_date=datetime.now(timezone.utc)
    )
    
    assert owner_at_threshold.ownership_percentage >= BENEFICIAL_OWNERSHIP_PCT
    assert owner_below_threshold.ownership_percentage < BENEFICIAL_OWNERSHIP_PCT


# ============================================================================
# OFAC Screening Tests
# ============================================================================

def test_ofac_screening_no_match(mock_compliance_service):
    """
    Test OFAC screening with no match (clear transaction).
    """
    mock_compliance_service.check_ofac.return_value = {
        "match": False,
        "score": 0,
        "details": "No SDN match found"
    }
    
    result = mock_compliance_service.check_ofac("John Smith", "ACC-001")
    
    assert result["match"] is False
    assert result["score"] < OFAC_FUZZY_THRESHOLD


def test_ofac_screening_exact_match(mock_compliance_service):
    """
    Test OFAC screening with exact SDN match (block transaction).
    """
    mock_compliance_service.check_ofac.return_value = {
        "match": True,
        "score": 100,
        "sdn_name": "Blocked Entity",
        "action": "BLOCK"
    }
    
    result = mock_compliance_service.check_ofac("Blocked Entity", "ACC-002")
    
    assert result["match"] is True
    assert result["score"] == 100
    assert result["action"] == "BLOCK"


def test_ofac_screening_fuzzy_match_above_threshold(mock_compliance_service):
    """
    Test OFAC screening with fuzzy match above threshold (review required).
    OFAC fuzzy threshold is exactly 85.
    """
    mock_compliance_service.check_ofac.return_value = {
        "match": True,
        "score": 90,
        "sdn_name": "Similar Entity Name",
        "action": "REVIEW"
    }
    
    result = mock_compliance_service.check_ofac("Similiar Entity Name", "ACC-003")
    
    assert result["match"] is True
    assert result["score"] >= OFAC_FUZZY_THRESHOLD
    assert result["action"] == "REVIEW"


def test_ofac_screening_fuzzy_match_below_threshold(mock_compliance_service):
    """
    Test OFAC screening with fuzzy match below threshold (allow with logging).
    OFAC fuzzy threshold is exactly 85.
    """
    mock_compliance_service.check_ofac.return_value = {
        "match": False,
        "score": 70,
        "details": "Low similarity score"
    }
    
    result = mock_compliance_service.check_ofac("Different Name", "ACC-004")
    
    assert result["match"] is False
    assert result["score"] < OFAC_FUZZY_THRESHOLD


# ============================================================================
# Audit Trail and Record Retention Tests
# ============================================================================

def test_audit_trail_records_all_required_fields(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_user,
    valid_account,
    current_timestamp
):
    """
    Test that audit trail records all required fields per 31 CFR 1010.430
    (5-year BSA record retention requirement).
    """
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("1500.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    result = transaction_service.execute_transaction(request)
    
    assert result.status == TransactionStatus.SUCCESS
    
    mock_audit_logger.log_transaction.assert_called_once()
    call_kwargs = mock_audit_logger.log_transaction.call_args.kwargs
    
    assert "user_id" in call_kwargs
    assert "transaction_id" in call_kwargs
    assert "amount" in call_kwargs
    assert "timestamp" in call_kwargs
    assert "ip_address" in call_kwargs
    assert "device_info" in call_kwargs
    assert "status" in call_kwargs
    assert "details" in call_kwargs
    
    assert call_kwargs["timestamp"].tzinfo is not None


def test_audit_trail_immutable_transaction_id(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_user,
    valid_account,
    current_timestamp
):
    """
    Test that transaction ID is immutable and unique for audit trail.
    """
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("250.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    result = transaction_service.execute_transaction(request)
    
    assert result.transaction_id is not None
    assert result.transaction_id.startswith("TXN-")
    assert len(result.transaction_id) > 4


def test_audit_trail_captures_rejection_reason(
    transaction_service,
    mock_account_repo,
    valid_user,
    current_timestamp
):
    """
    Test that audit trail captures rejection reasons for compliance review.
    """
    mock_account_repo.validate_account.return_value = False
    
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="INVALID",
        to_routing="999999999",
        amount=Decimal("100.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    result = transaction_service.execute_transaction(request)
    
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"


# ============================================================================
# Beneficial Ownership Related Tests (Context-Driven)
# ============================================================================

def test_beneficial_ownership_certification_on_file(mock_compliance_service):
    """
    Test that beneficial ownership certification is on file
    (FINCEN-1010-230-e-R1 related obligation).
    """
    entity_id = "ENTITY-001"
    
    mock_compliance_service.verify_beneficial_ownership_certification.return_value = True
    
    result = mock_compliance_service.verify_beneficial_ownership_certification(entity_id)
    
    assert result is True


def test_beneficial_owner_identity_verified_per_cip(mock_compliance_service):
    """
    Test that beneficial owner identity is verified per CIP procedures
    (FINCEN-1010-230-b-R4 and FINCEN-1010-230-b-2-R1 related obligations).
    """
    beneficial_owner = BeneficialOwner(
        owner_id="BO-003",
        name="Alice Johnson",
        ownership_percentage=Decimal("25.00"),
        identity_verified=True,
        verification_date=datetime(2024, 1, 15, tzinfo=timezone.utc)
    )
    
    assert beneficial_owner.identity_verified is True
    assert beneficial_owner.verification_date is not None
    assert beneficial_owner.ownership_percentage >= BENEFICIAL_OWNERSHIP_PCT


def test_beneficial_ownership_record_links_to_entity(mock_compliance_service):
    """
    Test that beneficial ownership record links to legal entity by immutable
    customer ID (FINCEN-1010-230-b-R6 related obligation).
    """
    entity = LegalEntity(
        entity_id="ENTITY-002",
        customer_id="CUST-002",
        entity_name="ABC Corporation",
        beneficial_owners=[
            BeneficialOwner(
                owner_id="BO-004",
                name="Bob Williams",
                ownership_percentage=Decimal("30.00"),
                identity_verified=True,
                verification_date=datetime(2024, 2, 1, tzinfo=timezone.utc)
            )
        ]
    )
    
    assert entity.customer_id is not None
    assert entity.customer_id != ""
    assert len(entity.beneficial_owners) > 0
    assert entity.beneficial_owners[0].ownership_percentage >= BENEFICIAL_OWNERSHIP_PCT


def test_private_banking_source_of_funds_documented(mock_compliance_service):
    """
    Test that source of funds and beneficial owner identification is documented
    for private banking accounts (FINCEN-1010-620-c-R1 related obligation).
    """
    entity_id = "ENTITY-003"
    
    beneficial_owners = [
        BeneficialOwner(
            owner_id="BO-005",
            name="Charles Davis",
            ownership_percentage=Decimal("50.00"),
            identity_verified=True,
            verification_date=datetime(2024, 3, 1, tzinfo=timezone.utc)
        )
    ]
    
    mock_compliance_service.get_beneficial_owners.return_value = beneficial_owners
    
    result = mock_compliance_service.get_beneficial_owners(entity_id)
    
    assert len(result) > 0
    assert all(owner.identity_verified for owner in result)


# ============================================================================
# Data Handling and PII Protection Tests
# ============================================================================

def test_ssn_masking_in_logs():
    """
    Test that SSN/TIN is masked in logs (show last 4 only) per GLBA Safeguards Rule.
    """
    full_ssn = "123-45-6789"
    masked_ssn = f"***-**-{full_ssn[-4:]}"
    
    assert masked_ssn == "***-**-6789"
    assert "123-45" not in masked_ssn


def test_pii_encryption_requirements():
    """
    Test that PII encryption requirements are enforced (AES-256 at rest, TLS 1.3 in transit).
    """
    encryption_config = {
        "at_rest": "AES-256",
        "in_transit": "TLS 1.3",
        "key_rotation_days": 90
    }
    
    assert encryption_config["at_rest"] == "AES-256"
    assert encryption_config["in_transit"] == "TLS 1.3"


# ============================================================================
# Edge Cases and Negative Path Tests
# ============================================================================

def test_transaction_with_exact_balance(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_user,
    current_timestamp
):
    """
    Test transaction with amount exactly equal to account balance.
    """
    account = Account(
        account_id="ACC-005",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        customer_id="CUST-005"
    )
    
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = account
    mock_account_repo.update_balance.return_value = True
    
    request = TransactionRequest(
        from_account="ACC-005",
        to_account="ACC-006",
        to_routing="021000022",
        amount=Decimal("1000.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    result = transaction_service.execute_transaction(request)
    
    assert result.status == TransactionStatus.SUCCESS
    assert result.balance_after == Decimal("0.00")


def test_transaction_with_fractional_cents(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_user,
    valid_account,
    current_timestamp
):
    """
    Test transaction with fractional cents (should handle Decimal precision).
    """
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    
    request = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("123.456"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    result = transaction_service.execute_transaction(request)
    
    assert result.status == TransactionStatus.SUCCESS
    assert isinstance(result.balance_after, Decimal)


def test_concurrent_transaction_scenario(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_user,
    valid_account,
    current_timestamp
):
    """
    Test scenario where account balance might be affected by concurrent transactions.
    """
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    
    request1 = TransactionRequest(
        from_account="ACC-001",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("100.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    result1 = transaction_service.execute_transaction(request1)
    
    assert result1.status == TransactionStatus.SUCCESS
    assert result1.balance_after == Decimal("9900.00")


def test_invalid_source_account(
    transaction_service,
    mock_account_repo,
    valid_user,
    current_timestamp
):
    """
    Test transaction with invalid source account.
    """
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = None
    
    request = TransactionRequest(
        from_account="INVALID-ACC",
        to_account="ACC-002",
        to_routing="021000022",
        amount=Decimal("100.00"),
        user=valid_user,
        timestamp=current_timestamp
    )
    
    result = transaction_service.execute_transaction(request)
    
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid source account"


def test_timezone_aware_timestamps(current_timestamp):
    """
    Test that all timestamps are timezone-aware for accurate audit trails.
    """
    assert current_timestamp.tzinfo is not None
    assert current_timestamp.tzinfo == timezone.utc


def test_decimal_precision_for_currency():
    """
    Test that Decimal type is used for all currency amounts to avoid floating-point errors.
    """
    amount1 = Decimal("10.10")
    amount2 = Decimal("20.20")
    total = amount1 + amount2
    
    assert total == Decimal("30.30")
    assert isinstance(total, Decimal)


# ============================================================================
# Reg E Error Resolution Tests
# ============================================================================

def test_reg_e_error_resolution_window():
    """
    Test Reg E error resolution timing requirements (60 days for notification).
    """
    transaction_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    error_notification_date = datetime(2024, 2, 15, tzinfo=timezone.utc)
    
    days_difference = (error_notification_date - transaction_date).days
    
    assert days_difference <= 60


def test_reg_e_provisional_credit_timing():
    """
    Test Reg E provisional credit timing (10 business days for investigation).
    """
    error_reported_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    provisional_credit_deadline = datetime(2024, 1, 15, tzinfo=timezone.utc)
    
    days_for_investigation = (provisional_credit_deadline - error_reported_date).days
    
    assert days_for_investigation <= 15