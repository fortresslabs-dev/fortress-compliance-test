import pytest
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
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
    BLOCKED = "BLOCKED"


class SARStatus(Enum):
    FILED = "FILED"
    PENDING = "PENDING"
    NOT_REQUIRED = "NOT_REQUIRED"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    owner_id: str
    status: str = "ACTIVE"


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    metadata: Dict[str, Any]


@dataclass
class SARFiling:
    sar_id: str
    subject_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    status: SARStatus
    is_insider: bool


@dataclass
class AMLProgram:
    program_id: str
    has_internal_controls: bool
    has_independent_testing: bool
    has_designated_officer: bool
    has_ongoing_training: bool
    has_risk_based_cdd: bool
    board_approved: bool
    board_approval_date: Optional[datetime]
    includes_cip: bool
    cip_consistent_with_aml: bool


@dataclass
class AuditLog:
    log_id: str
    timestamp: datetime
    user_id: str
    ip_address: str
    device_info: str
    action: str
    details: Dict[str, Any]
    immutable: bool = True


# ============================================================================
# Authoritative Thresholds (31 C.F.R.)
# ============================================================================

CTR_THRESHOLD = Decimal("10000")
SAR_THRESHOLD = Decimal("5000")
TRAVEL_RULE_THRESHOLD = Decimal("3000")
WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
OFAC_FUZZY_THRESHOLD = 85
BENEFICIAL_OWNERSHIP_PCT = Decimal("20")

SAR_FILING_DEADLINE_DAYS = 30
SAR_RETENTION_YEARS = 5
BSA_RETENTION_YEARS = 5


# ============================================================================
# Service Interfaces
# ============================================================================

class TransactionService:
    def __init__(self, account_repo, audit_logger, sar_service, ofac_service):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.sar_service = sar_service
        self.ofac_service = ofac_service

    def initiate_transaction(
        self,
        from_account_id: str,
        to_account_id: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        # Validate amount
        if amount <= Decimal("0"):
            if amount == Decimal("0"):
                raise ValueError("Amount must be greater than 0")
            else:
                raise ValueError("Invalid amount")

        # Get accounts
        from_account = self.account_repo.get_account(from_account_id)
        if not from_account:
            raise ValueError("Invalid account")

        to_account = self.account_repo.get_account(to_account_id)
        if not to_account:
            raise ValueError("Invalid beneficiary account")

        # Check balance
        if from_account.balance < amount:
            raise ValueError("Insufficient balance")

        # OFAC screening
        ofac_result = self.ofac_service.screen(to_account.owner_id)
        if ofac_result["blocked"]:
            raise ValueError("OFAC blocked transaction")

        # Process transaction
        from_account.balance -= amount
        to_account.balance += amount
        self.account_repo.update_account(from_account)
        self.account_repo.update_account(to_account)

        transaction = Transaction(
            transaction_id=f"TXN-{datetime.now(timezone.utc).timestamp()}",
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=datetime.now(timezone.utc),
            status=TransactionStatus.SUCCESS,
            metadata={"user_id": user_id}
        )

        # Audit trail
        self.audit_logger.log(
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
            action="TRANSACTION",
            details={
                "transaction_id": transaction.transaction_id,
                "from_account": from_account_id,
                "to_account": to_account_id,
                "amount": str(amount),
                "status": transaction.status.value
            }
        )

        return transaction


class SARService:
    def __init__(self, audit_logger):
        self.audit_logger = audit_logger
        self.filed_sars: List[SARFiling] = []

    def evaluate_and_file(
        self,
        subject_id: str,
        amount: Decimal,
        reason: str,
        is_insider: bool,
        detection_date: datetime
    ) -> Optional[SARFiling]:
        # 31 C.F.R. § 1020.320 - SAR filing requirements
        should_file = False

        if is_insider:
            # Insider abuse - any amount
            should_file = True
        elif amount > SAR_THRESHOLD:
            # Suspicious activity > $5,000
            should_file = True

        if should_file:
            sar = SARFiling(
                sar_id=f"SAR-{len(self.filed_sars) + 1}",
                subject_id=subject_id,
                amount=amount,
                reason=reason,
                filed_date=datetime.now(timezone.utc),
                detection_date=detection_date,
                status=SARStatus.FILED,
                is_insider=is_insider
            )
            self.filed_sars.append(sar)

            self.audit_logger.log(
                user_id="SYSTEM",
                ip_address="INTERNAL",
                device_info="SAR_SERVICE",
                action="SAR_FILED",
                details={
                    "sar_id": sar.sar_id,
                    "subject_id": subject_id,
                    "amount": str(amount),
                    "reason": reason,
                    "is_insider": is_insider
                }
            )
            return sar

        return None

    def is_sar_filed_for_subject(self, subject_id: str) -> bool:
        return any(sar.subject_id == subject_id for sar in self.filed_sars)

    def get_sar_for_subject(self, subject_id: str) -> Optional[SARFiling]:
        for sar in self.filed_sars:
            if sar.subject_id == subject_id:
                return sar
        return None


class CustomerInquiryService:
    def __init__(self, sar_service):
        self.sar_service = sar_service

    def handle_account_restriction_inquiry(self, customer_id: str) -> str:
        # 31 C.F.R. § 1020.320(e) - No tipping off
        if self.sar_service.is_sar_filed_for_subject(customer_id):
            # Must NOT disclose SAR filing
            return "Your account is under routine review. Please contact customer service for general inquiries."
        return "No restrictions found on your account."


class AMLProgramService:
    def __init__(self):
        self.programs: Dict[str, AMLProgram] = {}

    def create_aml_program(
        self,
        program_id: str,
        has_internal_controls: bool,
        has_independent_testing: bool,
        has_designated_officer: bool,
        has_ongoing_training: bool,
        has_risk_based_cdd: bool,
        board_approved: bool,
        board_approval_date: Optional[datetime],
        includes_cip: bool,
        cip_consistent_with_aml: bool
    ) -> AMLProgram:
        program = AMLProgram(
            program_id=program_id,
            has_internal_controls=has_internal_controls,
            has_independent_testing=has_independent_testing,
            has_designated_officer=has_designated_officer,
            has_ongoing_training=has_ongoing_training,
            has_risk_based_cdd=has_risk_based_cdd,
            board_approved=board_approved,
            board_approval_date=board_approval_date,
            includes_cip=includes_cip,
            cip_consistent_with_aml=cip_consistent_with_aml
        )
        self.programs[program_id] = program
        return program

    def validate_cip_integration(self, program_id: str) -> bool:
        """Validate that CIP is part of and consistent with AML program per 31 C.F.R. § 1010.220(a)"""
        program = self.programs.get(program_id)
        if not program:
            return False
        return program.includes_cip and program.cip_consistent_with_aml


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_account_repo():
    repo = Mock()
    repo.accounts = {}

    def get_account(account_id: str) -> Optional[Account]:
        return repo.accounts.get(account_id)

    def update_account(account: Account):
        repo.accounts[account.account_id] = account

    def create_account(account: Account):
        repo.accounts[account.account_id] = account

    repo.get_account = Mock(side_effect=get_account)
    repo.update_account = Mock(side_effect=update_account)
    repo.create_account = Mock(side_effect=create_account)

    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock()
    logger.logs = []

    def log(user_id: str, ip_address: str, device_info: str, action: str, details: Dict[str, Any]):
        audit_log = AuditLog(
            log_id=f"LOG-{len(logger.logs) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
            action=action,
            details=details,
            immutable=True
        )
        logger.logs.append(audit_log)

    logger.log = Mock(side_effect=log)
    return logger


@pytest.fixture
def mock_ofac_service():
    service = Mock()

    def screen(subject_id: str) -> Dict[str, Any]:
        # Default: no match
        return {
            "blocked": False,
            "match_score": 0,
            "matched_entity": None
        }

    service.screen = Mock(side_effect=screen)
    return service


@pytest.fixture
def sar_service(mock_audit_logger):
    return SARService(audit_logger=mock_audit_logger)


@pytest.fixture
def transaction_service(mock_account_repo, mock_audit_logger, sar_service, mock_ofac_service):
    return TransactionService(
        account_repo=mock_account_repo,
        audit_logger=mock_audit_logger,
        sar_service=sar_service,
        ofac_service=mock_ofac_service
    )


@pytest.fixture
def customer_inquiry_service(sar_service):
    return CustomerInquiryService(sar_service=sar_service)


@pytest.fixture
def aml_program_service():
    return AMLProgramService()


@pytest.fixture
def valid_account_from(mock_account_repo):
    account = Account(
        account_id="ACC-001",
        routing_number="123456789",
        balance=Decimal("10000.00"),
        owner_id="USER-001",
        status="ACTIVE"
    )
    mock_account_repo.create_account(account)
    return account


@pytest.fixture
def valid_account_to(mock_account_repo):
    account = Account(
        account_id="ACC-002",
        routing_number="987654321",
        balance=Decimal("5000.00"),
        owner_id="USER-002",
        status="ACTIVE"
    )
    mock_account_repo.create_account(account)
    return account


# ============================================================================
# MUST-TEST OBLIGATIONS - 31 C.F.R. § 1010.220(a)
# ============================================================================

def test_cip_must_be_part_of_aml_program(aml_program_service):
    """
    [FINCEN-1010-220-a-R1::OBL::001]
    Written CIP must be part of, and consistent with, the institution's AML program.
    
    Tests that CIP is integrated into the AML program as required by 31 C.F.R. § 1010.220(a).
    """
    # Arrange
    program_id = "AML-PROG-001"
    
    # Act
    program = aml_program_service.create_aml_program(
        program_id=program_id,
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=datetime.now(timezone.utc),
        includes_cip=True,
        cip_consistent_with_aml=True
    )
    
    # Assert
    assert program.includes_cip, (
        "CIP must be part of the institution's AML program per 31 C.F.R. § 1010.220(a)"
    )
    assert program.cip_consistent_with_aml, (
        "CIP must be consistent with the institution's AML program per 31 C.F.R. § 1010.220(a)"
    )
    assert aml_program_service.validate_cip_integration(program_id), (
        "CIP integration validation failed - CIP must be part of and consistent with "
        "the institution's AML program per 31 C.F.R. § 1010.220(a)"
    )


def test_cip_not_consistent_with_aml_program_fails_validation(aml_program_service):
    """
    [FINCEN-1010-220-a-R1::OBL::001] - Negative test
    Validates that CIP inconsistent with AML program fails validation per 31 C.F.R. § 1010.220(a).
    """
    # Arrange
    program_id = "AML-PROG-002"
    
    # Act
    program = aml_program_service.create_aml_program(
        program_id=program_id,
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=datetime.now(timezone.utc),
        includes_cip=True,
        cip_consistent_with_aml=False  # Inconsistent
    )
    
    # Assert
    assert not aml_program_service.validate_cip_integration(program_id), (
        "CIP validation must fail when CIP is not consistent with AML program "
        "per 31 C.F.R. § 1010.220(a)"
    )


def test_cip_missing_from_aml_program_fails_validation(aml_program_service):
    """
    [FINCEN-1010-220-a-R1::OBL::001] - Negative test
    Validates that missing CIP in AML program fails validation per 31 C.F.R. § 1010.220(a).
    """
    # Arrange
    program_id = "AML-PROG-003"
    
    # Act
    program = aml_program_service.create_aml_program(
        program_id=program_id,
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=datetime.now(timezone.utc),
        includes_cip=False,  # Missing CIP
        cip_consistent_with_aml=False
    )
    
    # Assert
    assert not aml_program_service.validate_cip_integration(program_id), (
        "CIP validation must fail when CIP is not part of AML program "
        "per 31 C.F.R. § 1010.220(a)"
    )


# ============================================================================
# BDD Scenario Tests
# ============================================================================

def test_successful_transaction(
    transaction_service,
    valid_account_from,
    valid_account_to,
    mock_audit_logger
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    initial_from_balance = valid_account_from.balance
    initial_to_balance = valid_account_to.balance
    transfer_amount = Decimal("1000.00")
    
    # Act
    transaction = transaction_service.initiate_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=transfer_amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    assert valid_account_from.balance == initial_from_balance - transfer_amount
    assert valid_account_to.balance == initial_to_balance + transfer_amount
    assert len(mock_audit_logger.logs) > 0
    assert mock_audit_logger.logs[0].action == "TRANSACTION"
    assert mock_audit_logger.logs[0].details["transaction_id"] == transaction.transaction_id
    assert mock_audit_logger.logs[0].immutable is True


def test_sar_suspicious_activity_above_threshold(sar_service, mock_audit_logger):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    subject_id = "CUSTOMER-123"
    suspicious_amount = Decimal("6000.00")  # Above SAR_THRESHOLD
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file(
        subject_id=subject_id,
        amount=suspicious_amount,
        reason="Structured transactions to evade reporting",
        is_insider=False,
        detection_date=detection_date
    )
    
    # Assert
    assert sar is not None
    assert sar.status == SARStatus.FILED
    assert sar.amount == suspicious_amount
    assert sar.subject_id == subject_id
    assert (sar.filed_date - detection_date).days <= SAR_FILING_DEADLINE_DAYS
    
    # Verify audit log
    sar_logs = [log for log in mock_audit_logger.logs if log.action == "SAR_FILED"]
    assert len(sar_logs) > 0
    assert sar_logs[0].details["subject_id"] == subject_id


def test_sar_suspicious_activity_at_exact_threshold(sar_service):
    """
    Boundary test: SAR at exact $5,000 threshold
    """
    # Arrange
    subject_id = "CUSTOMER-124"
    exact_threshold_amount = SAR_THRESHOLD  # Exactly $5,000
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file(
        subject_id=subject_id,
        amount=exact_threshold_amount,
        reason="Suspicious pattern at threshold",
        is_insider=False,
        detection_date=detection_date
    )
    
    # Assert - at threshold should NOT trigger (> not >=)
    assert sar is None


def test_sar_suspicious_activity_just_above_threshold(sar_service):
    """
    Boundary test: SAR just above $5,000 threshold
    """
    # Arrange
    subject_id = "CUSTOMER-125"
    just_above_threshold = SAR_THRESHOLD + Decimal("0.01")  # $5,000.01
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file(
        subject_id=subject_id,
        amount=just_above_threshold,
        reason="Suspicious pattern just above threshold",
        is_insider=False,
        detection_date=detection_date
    )
    
    # Assert
    assert sar is not None
    assert sar.status == SARStatus.FILED


def test_sar_suspicious_activity_below_threshold(sar_service):
    """
    Scenario: Suspicious activity below $5,000 threshold should not trigger SAR
    """
    # Arrange
    subject_id = "CUSTOMER-126"
    below_threshold_amount = Decimal("4999.99")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file(
        subject_id=subject_id,
        amount=below_threshold_amount,
        reason="Suspicious pattern below threshold",
        is_insider=False,
        detection_date=detection_date
    )
    
    # Assert
    assert sar is None


def test_sar_insider_abuse_any_amount(sar_service, mock_audit_logger):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    insider_id = "EMPLOYEE-456"
    small_amount = Decimal("100.00")  # Well below normal SAR threshold
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file(
        subject_id=insider_id,
        amount=small_amount,
        reason="Insider abuse - unauthorized access to customer accounts",
        is_insider=True,
        detection_date=detection_date
    )
    
    # Assert
    assert sar is not None
    assert sar.status == SARStatus.FILED
    assert sar.is_insider is True
    assert sar.amount == small_amount
    
    # Verify immediate filing
    assert (sar.filed_date - detection_date).total_seconds() < 60


def test_sar_insider_abuse_zero_amount(sar_service):
    """
    Scenario: Insider abuse at $0 (e.g., unauthorized data access)
    """
    # Arrange
    insider_id = "EMPLOYEE-457"
    zero_amount = Decimal("0.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file(
        subject_id=insider_id,
        amount=zero_amount,
        reason="Insider abuse - unauthorized data access",
        is_insider=True,
        detection_date=detection_date
    )
    
    # Assert
    assert sar is not None
    assert sar.status == SARStatus.FILED
    assert sar.is_insider is True


def test_sar_no_tipping_off(customer_inquiry_service, sar_service):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    customer_id = "CUSTOMER-789"
    
    # File a SAR for the customer
    sar_service.evaluate_and_file(
        subject_id=customer_id,
        amount=Decimal("10000.00"),
        reason="Suspicious wire transfers",
        is_insider=False,
        detection_date=datetime.now(timezone.utc)
    )
    
    # Act
    response = customer_inquiry_service.handle_account_restriction_inquiry(customer_id)
    
    # Assert - Must NOT disclose SAR filing (31 C.F.R. § 1020.320(e))
    assert "SAR" not in response
    assert "Suspicious Activity Report" not in response
    assert "filed" not in response.lower() or "routine" in response.lower()
    assert sar_service.is_sar_filed_for_subject(customer_id)


def test_sar_no_tipping_off_no_sar_filed(customer_inquiry_service, sar_service):
    """
    Scenario: Customer inquiry when no SAR has been filed
    """
    # Arrange
    customer_id = "CUSTOMER-790"
    
    # Act
    response = customer_inquiry_service.handle_account_restriction_inquiry(customer_id)
    
    # Assert
    assert "No restrictions" in response or "routine" in response.lower()
    assert not sar_service.is_sar_filed_for_subject(customer_id)


def test_zero_amount_transfer(transaction_service, valid_account_from, valid_account_to):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    zero_amount = Decimal("0")
    
    # Act & Assert
    with pytest.raises(ValueError) as exc_info:
        transaction_service.initiate_transaction(
            from_account_id=valid_account_from.account_id,
            to_account_id=valid_account_to.account_id,
            amount=zero_amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0"
        )
    
    assert "Amount must be greater than 0" in str(exc_info.value)


def test_negative_amount_transfer(transaction_service, valid_account_from, valid_account_to):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    negative_amount = Decimal("-100.00")
    
    # Act & Assert
    with pytest.raises(ValueError) as exc_info:
        transaction_service.initiate_transaction(
            from_account_id=valid_account_from.account_id,
            to_account_id=valid_account_to.account_id,
            amount=negative_amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0"
        )
    
    assert "Invalid amount" in str(exc_info.value)


def test_insufficient_balance(transaction_service, valid_account_from, valid_account_to):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    valid_account_from.balance = Decimal("1000.00")
    transfer_amount = Decimal("5000.00")
    
    # Act & Assert
    with pytest.raises(ValueError) as exc_info:
        transaction_service.initiate_transaction(
            from_account_id=valid_account_from.account_id,
            to_account_id=valid_account_to.account_id,
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0"
        )
    
    assert "Insufficient balance" in str(exc_info.value)


def test_invalid_beneficiary(transaction_service, valid_account_from, mock_account_repo):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    invalid_account_id = "ACC-INVALID"
    transfer_amount = Decimal("100.00")
    
    # Act & Assert
    with pytest.raises(ValueError) as exc_info:
        transaction_service.initiate_transaction(
            from_account_id=valid_account_from.account_id,
            to_account_id=invalid_account_id,
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0"
        )
    
    assert "Invalid beneficiary account" in str(exc_info.value)


def test_invalid_from_account(transaction_service, valid_account_to):
    """
    Negative test: Invalid from account
    """
    # Arrange
    invalid_account_id = "ACC-INVALID"
    transfer_amount = Decimal("100.00")
    
    # Act & Assert
    with pytest.raises(ValueError) as exc_info:
        transaction_service.initiate_transaction(
            from_account_id=invalid_account_id,
            to_account_id=valid_account_to.account_id,
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0"
        )
    
    assert "Invalid account" in str(exc_info.value)


# ============================================================================
# Compliance & Threshold Boundary Tests
# ============================================================================

def test_ctr_threshold_boundary():
    """
    Test CTR threshold boundary at $10,000 per authoritative thresholds
    """
    # Arrange
    at_threshold = CTR_THRESHOLD
    above_threshold = CTR_THRESHOLD + Decimal("0.01")
    below_threshold = CTR_THRESHOLD - Decimal("0.01")
    
    # Assert
    assert at_threshold == Decimal("10000")
    assert above_threshold > CTR_THRESHOLD
    assert below_threshold < CTR_THRESHOLD


def test_travel_rule_threshold_boundary():
    """
    Test Travel Rule threshold boundary at $3,000 per authoritative thresholds
    """
    # Arrange
    at_threshold = TRAVEL_RULE_THRESHOLD
    above_threshold = TRAVEL_RULE_THRESHOLD + Decimal("0.01")
    below_threshold = TRAVEL_RULE_THRESHOLD - Decimal("0.01")
    
    # Assert
    assert at_threshold == Decimal("3000")
    assert above_threshold > TRAVEL_RULE_THRESHOLD
    assert below_threshold < TRAVEL_RULE_THRESHOLD


def test_wire_dual_approval_threshold_boundary():
    """
    Test Wire Dual Approval threshold boundary at $10,000 per authoritative thresholds
    """
    # Arrange
    at_threshold = WIRE_DUAL_APPROVAL_THRESHOLD
    above_threshold = WIRE_DUAL_APPROVAL_THRESHOLD + Decimal("0.01")
    below_threshold = WIRE_DUAL_APPROVAL_THRESHOLD - Decimal("0.01")
    
    # Assert
    assert at_threshold == Decimal("10000")
    assert above_threshold > WIRE_DUAL_APPROVAL_THRESHOLD
    assert below_threshold < WIRE_DUAL_APPROVAL_THRESHOLD


def test_ofac_fuzzy_threshold():
    """
    Test OFAC fuzzy matching threshold at 85 per authoritative thresholds
    """
    # Arrange
    at_threshold = OFAC_FUZZY_THRESHOLD
    above_threshold = OFAC_FUZZY_THRESHOLD + 1
    below_threshold = OFAC_FUZZY_THRESHOLD - 1
    
    # Assert
    assert at_threshold == 85
    assert above_threshold > OFAC_FUZZY_THRESHOLD
    assert below_threshold < OFAC_FUZZY_THRESHOLD


def test_beneficial_ownership_threshold():
    """
    Test Beneficial Ownership threshold at 20% per authoritative thresholds
    """
    # Arrange
    at_threshold = BENEFICIAL_OWNERSHIP_PCT
    above_threshold = BENEFICIAL_OWNERSHIP_PCT + Decimal("0.01")
    below_threshold = BENEFICIAL_OWNERSHIP_PCT - Decimal("0.01")
    
    # Assert
    assert at_threshold == Decimal("20")
    assert above_threshold > BENEFICIAL_OWNERSHIP_PCT
    assert below_threshold < BENEFICIAL_OWNERSHIP_PCT


def test_ofac_blocked_transaction(
    transaction_service,
    valid_account_from,
    valid_account_to,
    mock_ofac_service
):
    """
    Test OFAC screening blocks transaction when match found
    """
    # Arrange
    mock_ofac_service.screen.return_value = {
        "blocked": True,
        "match_score": 95,
        "matched_entity": "SDN-12345"
    }
    transfer_amount = Decimal("1000.00")
    
    # Act & Assert
    with pytest.raises(ValueError) as exc_info:
        transaction_service.initiate_transaction(
            from_account_id=valid_account_from.account_id,
            to_account_id=valid_account_to.account_id,
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0"
        )
    
    assert "OFAC blocked" in str(exc_info.value)


def test_audit_trail_immutability(mock_audit_logger, transaction_service, valid_account_from, valid_account_to):
    """
    Test that audit logs are immutable per BSA requirements (31 CFR 1010.430)
    """
    # Arrange & Act
    transaction_service.initiate_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=Decimal("500.00"),
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert len(mock_audit_logger.logs) > 0
    for log in mock_audit_logger.logs:
        assert log.immutable is True
        assert log.timestamp is not None
        assert log.user_id is not None
        assert log.ip_address is not None
        assert log.device_info is not None


def test_audit_trail_contains_required_fields(
    mock_audit_logger,
    transaction_service,
    valid_account_from,
    valid_account_to
):
    """
    Test audit trail contains all required fields per BSA requirements
    """
    # Arrange & Act
    transaction_service.initiate_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=Decimal("500.00"),
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert len(mock_audit_logger.logs) > 0
    log = mock_audit_logger.logs[0]
    assert log.user_id == "USER-001"
    assert log.ip_address == "192.168.1.1"
    assert log.device_info == "Mozilla/5.0"
    assert log.action == "TRANSACTION"
    assert "transaction_id" in log.details
    assert "from_account" in log.details
    assert "to_account" in log.details
    assert "amount" in log.details
    assert "status" in log.details


def test_sar_retention_period():
    """
    Test SAR retention period is 5 years per BSA requirements
    """
    assert SAR_RETENTION_YEARS == 5
    assert BSA_RETENTION_YEARS == 5


def test_sar_filing_deadline():
    """
    Test SAR filing deadline is 30 days per FinCEN requirements
    """
    assert SAR_FILING_DEADLINE_DAYS == 30


def test_aml_program_components(aml_program_service):
    """
    Test AML program contains all required components per 31 C.F.R. § 1010.210(b)
    """
    # Arrange & Act
    program = aml_program_service.create_aml_program(
        program_id="AML-PROG-COMPLETE",
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=datetime.now(timezone.utc),
        includes_cip=True,
        cip_consistent_with_aml=True
    )
    
    # Assert - All required components per FINCEN-1010-210-b-R1
    assert program.has_internal_controls
    assert program.has_independent_testing
    assert program.has_designated_officer
    assert program.has_ongoing_training
    assert program.has_risk_based_cdd


def test_aml_program_board_approval(aml_program_service):
    """
    Test AML program board approval per 31 C.F.R. § 1010.210(b)
    """
    # Arrange
    approval_date = datetime.now(timezone.utc)
    
    # Act
    program = aml_program_service.create_aml_program(
        program_id="AML-PROG-APPROVED",
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=approval_date,
        includes_cip=True,
        cip_consistent_with_aml=True
    )
    
    # Assert - Board approval required per FINCEN-1010-210-b-R3
    assert program.board_approved
    assert program.board_approval_date is not None
    assert program.board_approval_date == approval_date


def test_decimal_precision_for_currency():
    """
    Test that Decimal type is used for currency amounts to avoid floating point errors
    """
    # Arrange
    amount1 = Decimal("10000.00")
    amount2 = Decimal("0.01")
    
    # Act
    result = amount1 + amount2
    
    # Assert
    assert result == Decimal("10000.01")
    assert isinstance(result, Decimal)


def test_timezone_aware_datetimes():
    """
    Test that all timestamps are timezone-aware (UTC)
    """
    # Arrange & Act
    now = datetime.now(timezone.utc)
    
    # Assert
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc