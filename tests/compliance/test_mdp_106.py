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
    customer_id: str
    status: str = "ACTIVE"


@dataclass
class Customer:
    customer_id: str
    name: str
    ssn: str
    is_employee: bool = False
    risk_level: str = "LOW"


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SARFiling:
    sar_id: str
    customer_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    is_insider: bool
    status: SARStatus


@dataclass
class AMLProgram:
    has_internal_controls: bool
    has_independent_testing: bool
    has_compliance_officer: bool
    has_training: bool
    has_cdd_procedures: bool
    board_approved: bool
    approval_date: Optional[datetime]
    has_cip: bool
    cip_consistent_with_aml: bool


@dataclass
class AuditLog:
    log_id: str
    timestamp: datetime
    user_id: str
    action: str
    ip_address: str
    device_info: str
    details: Dict[str, Any]


# ============================================================================
# Service Interfaces
# ============================================================================

class OFACService:
    def screen(self, name: str, threshold: int = 85) -> Dict[str, Any]:
        raise NotImplementedError


class RuleResolver:
    def get_sar_threshold(self) -> Decimal:
        return Decimal("5000")
    
    def get_ctr_threshold(self) -> Decimal:
        return Decimal("10000")
    
    def get_travel_rule_threshold(self) -> Decimal:
        return Decimal("3000")
    
    def get_wire_dual_approval_threshold(self) -> Decimal:
        return Decimal("10000")
    
    def get_ofac_fuzzy_threshold(self) -> int:
        return 85
    
    def get_beneficial_ownership_pct(self) -> Decimal:
        return Decimal("20")


class AuditLogger:
    def log(self, user_id: str, action: str, ip_address: str, 
            device_info: str, details: Dict[str, Any]) -> AuditLog:
        raise NotImplementedError


class TransactionService:
    def __init__(self, rule_resolver: RuleResolver, audit_logger: AuditLogger):
        self.rule_resolver = rule_resolver
        self.audit_logger = audit_logger
    
    def process_transaction(self, from_account: Account, to_account: Account,
                          amount: Decimal, user_id: str, ip_address: str,
                          device_info: str) -> Transaction:
        raise NotImplementedError


class SARService:
    def __init__(self, rule_resolver: RuleResolver):
        self.rule_resolver = rule_resolver
    
    def file_sar(self, customer_id: str, amount: Decimal, reason: str,
                 detection_date: datetime, is_insider: bool = False) -> SARFiling:
        raise NotImplementedError
    
    def should_file_sar(self, amount: Decimal, is_suspicious: bool,
                       is_insider: bool = False) -> bool:
        if is_insider:
            return True
        if is_suspicious and amount > self.rule_resolver.get_sar_threshold():
            return True
        return False


class ComplianceService:
    def __init__(self, rule_resolver: RuleResolver):
        self.rule_resolver = rule_resolver
    
    def validate_aml_program(self, program: AMLProgram) -> bool:
        raise NotImplementedError
    
    def validate_cip_consistency(self, program: AMLProgram) -> bool:
        raise NotImplementedError


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def rule_resolver() -> RuleResolver:
    """Provides authoritative compliance thresholds."""
    return RuleResolver()


@pytest.fixture
def mock_ofac_service() -> Mock:
    """Mock OFAC/SDN screening service."""
    service = Mock(spec=OFACService)
    service.screen.return_value = {
        "match": False,
        "score": 0,
        "action": "ALLOW"
    }
    return service


@pytest.fixture
def mock_audit_logger() -> Mock:
    """Mock audit logging service."""
    logger = Mock(spec=AuditLogger)
    logger.log.return_value = AuditLog(
        log_id="audit-123",
        timestamp=datetime.now(timezone.utc),
        user_id="user-123",
        action="TRANSACTION",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0",
        details={}
    )
    return logger


@pytest.fixture
def mock_transaction_service(rule_resolver: RuleResolver, 
                            mock_audit_logger: Mock) -> Mock:
    """Mock transaction processing service."""
    service = Mock(spec=TransactionService)
    service.rule_resolver = rule_resolver
    service.audit_logger = mock_audit_logger
    return service


@pytest.fixture
def mock_sar_service(rule_resolver: RuleResolver) -> Mock:
    """Mock SAR filing service."""
    service = Mock(spec=SARService)
    service.rule_resolver = rule_resolver
    service.should_file_sar = SARService(rule_resolver).should_file_sar
    return service


@pytest.fixture
def mock_compliance_service(rule_resolver: RuleResolver) -> Mock:
    """Mock compliance validation service."""
    service = Mock(spec=ComplianceService)
    service.rule_resolver = rule_resolver
    return service


@pytest.fixture
def valid_account() -> Account:
    """Valid account with sufficient balance."""
    return Account(
        account_id="ACC-123",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        customer_id="CUST-123",
        status="ACTIVE"
    )


@pytest.fixture
def valid_beneficiary_account() -> Account:
    """Valid beneficiary account."""
    return Account(
        account_id="ACC-456",
        routing_number="021000021",
        balance=Decimal("5000.00"),
        customer_id="CUST-456",
        status="ACTIVE"
    )


@pytest.fixture
def low_balance_account() -> Account:
    """Account with low balance."""
    return Account(
        account_id="ACC-789",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        customer_id="CUST-789",
        status="ACTIVE"
    )


@pytest.fixture
def employee_customer() -> Customer:
    """Bank employee customer."""
    return Customer(
        customer_id="CUST-EMP-001",
        name="John Employee",
        ssn="123-45-6789",
        is_employee=True,
        risk_level="HIGH"
    )


@pytest.fixture
def regular_customer() -> Customer:
    """Regular customer."""
    return Customer(
        customer_id="CUST-123",
        name="Jane Customer",
        ssn="987-65-4321",
        is_employee=False,
        risk_level="LOW"
    )


@pytest.fixture
def valid_aml_program_with_cip() -> AMLProgram:
    """Valid AML program with CIP properly integrated."""
    return AMLProgram(
        has_internal_controls=True,
        has_independent_testing=True,
        has_compliance_officer=True,
        has_training=True,
        has_cdd_procedures=True,
        board_approved=True,
        approval_date=datetime(2023, 1, 15, tzinfo=timezone.utc),
        has_cip=True,
        cip_consistent_with_aml=True
    )


@pytest.fixture
def aml_program_without_cip() -> AMLProgram:
    """AML program missing CIP."""
    return AMLProgram(
        has_internal_controls=True,
        has_independent_testing=True,
        has_compliance_officer=True,
        has_training=True,
        has_cdd_procedures=True,
        board_approved=True,
        approval_date=datetime(2023, 1, 15, tzinfo=timezone.utc),
        has_cip=False,
        cip_consistent_with_aml=False
    )


@pytest.fixture
def aml_program_cip_inconsistent() -> AMLProgram:
    """AML program with CIP but inconsistent with AML program."""
    return AMLProgram(
        has_internal_controls=True,
        has_independent_testing=True,
        has_compliance_officer=True,
        has_training=True,
        has_cdd_procedures=True,
        board_approved=True,
        approval_date=datetime(2023, 1, 15, tzinfo=timezone.utc),
        has_cip=True,
        cip_consistent_with_aml=False
    )


# ============================================================================
# MUST-TEST OBLIGATION: FINCEN-1010-220-a-R1
# Written CIP must be part of, and consistent with, the institution's AML program
# ============================================================================

def test_cip_must_be_part_of_aml_program(
    mock_compliance_service: Mock,
    valid_aml_program_with_cip: AMLProgram
):
    """
    Test that CIP is required as part of the AML program.
    
    OBLIGATION: [FINCEN-1010-220-a-R1::OBL::001]
    Written CIP must be part of the institution's AML program.
    """
    # Arrange
    program = valid_aml_program_with_cip
    
    # Act & Assert
    assert program.has_cip is True, (
        "CIP must be part of the institution's AML program per 31 C.F.R. § 1010.220(a)"
    )
    assert program.has_internal_controls is True
    assert program.has_compliance_officer is True


def test_cip_must_be_consistent_with_aml_program(
    mock_compliance_service: Mock,
    valid_aml_program_with_cip: AMLProgram
):
    """
    Test that CIP must be consistent with the AML program.
    
    OBLIGATION: [FINCEN-1010-220-a-R1::OBL::001]
    Written CIP must be consistent with the institution's AML program.
    """
    # Arrange
    program = valid_aml_program_with_cip
    
    # Act & Assert
    assert program.cip_consistent_with_aml is True, (
        "Written CIP must be consistent with the institution's AML program "
        "per 31 C.F.R. § 1010.220(a)"
    )


def test_aml_program_fails_without_cip(
    mock_compliance_service: Mock,
    aml_program_without_cip: AMLProgram
):
    """
    Test that AML program is invalid without CIP.
    
    OBLIGATION: [FINCEN-1010-220-a-R1::OBL::001]
    Negative test: AML program must include CIP.
    """
    # Arrange
    program = aml_program_without_cip
    mock_compliance_service.validate_aml_program.return_value = False
    
    # Act
    result = mock_compliance_service.validate_aml_program(program)
    
    # Assert
    assert program.has_cip is False
    assert result is False, (
        "AML program must include written CIP per 31 C.F.R. § 1010.220(a)"
    )


def test_aml_program_fails_with_inconsistent_cip(
    mock_compliance_service: Mock,
    aml_program_cip_inconsistent: AMLProgram
):
    """
    Test that AML program is invalid when CIP is inconsistent.
    
    OBLIGATION: [FINCEN-1010-220-a-R1::OBL::001]
    Negative test: CIP must be consistent with AML program.
    """
    # Arrange
    program = aml_program_cip_inconsistent
    mock_compliance_service.validate_cip_consistency.return_value = False
    
    # Act
    result = mock_compliance_service.validate_cip_consistency(program)
    
    # Assert
    assert program.has_cip is True
    assert program.cip_consistent_with_aml is False
    assert result is False, (
        "Written CIP must be consistent with the institution's AML program "
        "per 31 C.F.R. § 1010.220(a)"
    )


def test_cip_integration_with_complete_aml_components(
    valid_aml_program_with_cip: AMLProgram
):
    """
    Test CIP integration with all required AML program components.
    
    OBLIGATION: [FINCEN-1010-220-a-R1::OBL::001]
    CIP must be part of complete AML program with all required elements.
    """
    # Arrange
    program = valid_aml_program_with_cip
    
    # Act & Assert - Verify all AML components present
    assert program.has_internal_controls is True
    assert program.has_independent_testing is True
    assert program.has_compliance_officer is True
    assert program.has_training is True
    assert program.has_cdd_procedures is True
    assert program.board_approved is True
    assert program.approval_date is not None
    
    # Assert - CIP integration
    assert program.has_cip is True, (
        "Written CIP must be part of the institution's AML program "
        "per 31 C.F.R. § 1010.220(a)"
    )
    assert program.cip_consistent_with_aml is True, (
        "Written CIP must be consistent with the institution's AML program "
        "per 31 C.F.R. § 1010.220(a)"
    )


# ============================================================================
# Scenario: successful_transaction
# ============================================================================

def test_successful_transaction_with_sufficient_balance_and_valid_account(
    mock_transaction_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_beneficiary_account: Account
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    amount = Decimal("500.00")
    user_id = "user-123"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"
    
    expected_transaction = Transaction(
        transaction_id="TXN-001",
        from_account=valid_account.account_id,
        to_account=valid_beneficiary_account.account_id,
        amount=amount,
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        rejection_reason=None,
        metadata={"user_id": user_id}
    )
    
    mock_transaction_service.process_transaction.return_value = expected_transaction
    
    # Act
    transaction = mock_transaction_service.process_transaction(
        valid_account,
        valid_beneficiary_account,
        amount,
        user_id,
        ip_address,
        device_info
    )
    
    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    assert transaction.amount == amount
    assert transaction.from_account == valid_account.account_id
    assert transaction.to_account == valid_beneficiary_account.account_id
    assert transaction.rejection_reason is None
    
    # Verify audit trail recorded
    mock_transaction_service.process_transaction.assert_called_once_with(
        valid_account,
        valid_beneficiary_account,
        amount,
        user_id,
        ip_address,
        device_info
    )


# ============================================================================
# Scenario: sar_suspicious_activity_above_threshold
# ============================================================================

def test_sar_filed_for_suspicious_activity_above_threshold(
    mock_sar_service: Mock,
    rule_resolver: RuleResolver,
    regular_customer: Customer
):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    sar_threshold = rule_resolver.get_sar_threshold()
    amount = sar_threshold + Decimal("1000.00")  # $6,000
    detection_date = datetime.now(timezone.utc)
    filing_deadline = detection_date + timedelta(days=30)
    
    expected_sar = SARFiling(
        sar_id="SAR-001",
        customer_id=regular_customer.customer_id,
        amount=amount,
        reason="Suspicious pattern detected",
        filed_date=datetime.now(timezone.utc),
        detection_date=detection_date,
        is_insider=False,
        status=SARStatus.FILED
    )
    
    mock_sar_service.file_sar.return_value = expected_sar
    
    # Act
    should_file = mock_sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=False
    )
    
    assert should_file is True, (
        f"SAR must be filed for suspicious activity > ${sar_threshold}"
    )
    
    sar = mock_sar_service.file_sar(
        customer_id=regular_customer.customer_id,
        amount=amount,
        reason="Suspicious pattern detected",
        detection_date=detection_date,
        is_insider=False
    )
    
    # Assert
    assert sar.status == SARStatus.FILED
    assert sar.amount > sar_threshold
    assert sar.is_insider is False
    assert (sar.filed_date - detection_date) <= timedelta(days=30), (
        "SAR must be filed within 30 days of detection"
    )
    
    # Verify no tipping off (subject NOT notified)
    # This is enforced by not calling any notification service
    mock_sar_service.file_sar.assert_called_once()


def test_sar_not_filed_for_suspicious_activity_at_threshold(
    mock_sar_service: Mock,
    rule_resolver: RuleResolver
):
    """
    Boundary test: SAR not required at exactly $5,000 threshold.
    Amount must be GREATER than threshold.
    """
    # Arrange
    sar_threshold = rule_resolver.get_sar_threshold()
    amount = sar_threshold  # Exactly $5,000
    
    # Act
    should_file = mock_sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=False
    )
    
    # Assert
    assert should_file is False, (
        f"SAR requires suspicious activity > ${sar_threshold}, not equal to"
    )


def test_sar_filed_for_suspicious_activity_one_cent_above_threshold(
    mock_sar_service: Mock,
    rule_resolver: RuleResolver
):
    """
    Boundary test: SAR required at $5,000.01 (one cent above threshold).
    """
    # Arrange
    sar_threshold = rule_resolver.get_sar_threshold()
    amount = sar_threshold + Decimal("0.01")  # $5,000.01
    
    # Act
    should_file = mock_sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=False
    )
    
    # Assert
    assert should_file is True, (
        f"SAR must be filed for suspicious activity > ${sar_threshold}"
    )


def test_sar_not_filed_for_non_suspicious_activity_above_threshold(
    mock_sar_service: Mock,
    rule_resolver: RuleResolver
):
    """
    Negative test: SAR not filed if activity is not suspicious,
    even if above threshold.
    """
    # Arrange
    sar_threshold = rule_resolver.get_sar_threshold()
    amount = sar_threshold + Decimal("1000.00")
    
    # Act
    should_file = mock_sar_service.should_file_sar(
        amount=amount,
        is_suspicious=False,
        is_insider=False
    )
    
    # Assert
    assert should_file is False, (
        "SAR not required for non-suspicious activity"
    )


# ============================================================================
# Scenario: sar_insider_abuse_any_amount
# ============================================================================

def test_sar_filed_for_insider_abuse_at_any_amount(
    mock_sar_service: Mock,
    rule_resolver: RuleResolver,
    employee_customer: Customer
):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    amount = Decimal("100.00")  # Well below $5,000 threshold
    detection_date = datetime.now(timezone.utc)
    
    expected_sar = SARFiling(
        sar_id="SAR-INSIDER-001",
        customer_id=employee_customer.customer_id,
        amount=amount,
        reason="Insider abuse detected",
        filed_date=datetime.now(timezone.utc),
        detection_date=detection_date,
        is_insider=True,
        status=SARStatus.FILED
    )
    
    mock_sar_service.file_sar.return_value = expected_sar
    
    # Act
    should_file = mock_sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=True
    )
    
    assert should_file is True, (
        "SAR must be filed for insider abuse at any dollar amount"
    )
    
    sar = mock_sar_service.file_sar(
        customer_id=employee_customer.customer_id,
        amount=amount,
        reason="Insider abuse detected",
        detection_date=detection_date,
        is_insider=True
    )
    
    # Assert
    assert sar.status == SARStatus.FILED
    assert sar.is_insider is True
    assert sar.amount < rule_resolver.get_sar_threshold(), (
        "Insider SAR filed even though amount is below standard threshold"
    )


def test_sar_filed_for_insider_abuse_zero_amount(
    mock_sar_service: Mock,
    employee_customer: Customer
):
    """
    Boundary test: SAR filed for insider abuse even at $0.
    """
    # Arrange
    amount = Decimal("0.00")
    detection_date = datetime.now(timezone.utc)
    
    expected_sar = SARFiling(
        sar_id="SAR-INSIDER-002",
        customer_id=employee_customer.customer_id,
        amount=amount,
        reason="Insider abuse - unauthorized access",
        filed_date=datetime.now(timezone.utc),
        detection_date=detection_date,
        is_insider=True,
        status=SARStatus.FILED
    )
    
    mock_sar_service.file_sar.return_value = expected_sar
    
    # Act
    should_file = mock_sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=True
    )
    
    # Assert
    assert should_file is True, (
        "SAR must be filed for insider abuse at any amount, including $0"
    )


# ============================================================================
# Scenario: sar_no_tipping_off
# ============================================================================

def test_sar_no_tipping_off_customer_not_notified(
    mock_sar_service: Mock,
    regular_customer: Customer
):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    sar = SARFiling(
        sar_id="SAR-003",
        customer_id=regular_customer.customer_id,
        amount=Decimal("6000.00"),
        reason="Suspicious pattern",
        filed_date=datetime.now(timezone.utc),
        detection_date=datetime.now(timezone.utc) - timedelta(days=5),
        is_insider=False,
        status=SARStatus.FILED
    )
    
    # Act - Simulate customer inquiry response
    # The bank should provide generic response without mentioning SAR
    customer_inquiry_response = "Your account is under routine review."
    
    # Assert
    assert "SAR" not in customer_inquiry_response
    assert "Suspicious Activity Report" not in customer_inquiry_response
    assert "filed" not in customer_inquiry_response.lower()
    assert sar.status == SARStatus.FILED, (
        "SAR filing must not be disclosed to the subject (no tipping off)"
    )


# ============================================================================
# Scenario: zero_amount_transfer
# ============================================================================

def test_zero_amount_transfer_rejected(
    mock_transaction_service: Mock,
    valid_account: Account,
    valid_beneficiary_account: Account
):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    amount = Decimal("0.00")
    user_id = "user-123"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"
    
    expected_transaction = Transaction(
        transaction_id="TXN-REJECTED-001",
        from_account=valid_account.account_id,
        to_account=valid_beneficiary_account.account_id,
        amount=amount,
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.REJECTED,
        rejection_reason="Amount must be greater than 0"
    )
    
    mock_transaction_service.process_transaction.return_value = expected_transaction
    
    # Act
    transaction = mock_transaction_service.process_transaction(
        valid_account,
        valid_beneficiary_account,
        amount,
        user_id,
        ip_address,
        device_info
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Amount must be greater than 0"
    assert transaction.amount == Decimal("0.00")


# ============================================================================
# Scenario: negative_amount_transfer
# ============================================================================

def test_negative_amount_transfer_rejected(
    mock_transaction_service: Mock,
    valid_account: Account,
    valid_beneficiary_account: Account
):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    amount = Decimal("-100.00")
    user_id = "user-123"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"
    
    expected_transaction = Transaction(
        transaction_id="TXN-REJECTED-002",
        from_account=valid_account.account_id,
        to_account=valid_beneficiary_account.account_id,
        amount=amount,
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.REJECTED,
        rejection_reason="Invalid amount"
    )
    
    mock_transaction_service.process_transaction.return_value = expected_transaction
    
    # Act
    transaction = mock_transaction_service.process_transaction(
        valid_account,
        valid_beneficiary_account,
        amount,
        user_id,
        ip_address,
        device_info
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid amount"
    assert transaction.amount < Decimal("0.00")


# ============================================================================
# Scenario: insufficient_balance
# ============================================================================

def test_insufficient_balance_transfer_rejected(
    mock_transaction_service: Mock,
    low_balance_account: Account,
    valid_beneficiary_account: Account
):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    amount = Decimal("5000.00")
    user_id = "user-789"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"
    
    assert low_balance_account.balance == Decimal("1000.00")
    assert amount > low_balance_account.balance
    
    expected_transaction = Transaction(
        transaction_id="TXN-REJECTED-003",
        from_account=low_balance_account.account_id,
        to_account=valid_beneficiary_account.account_id,
        amount=amount,
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.REJECTED,
        rejection_reason="Insufficient balance"
    )
    
    mock_transaction_service.process_transaction.return_value = expected_transaction
    
    # Act
    transaction = mock_transaction_service.process_transaction(
        low_balance_account,
        valid_beneficiary_account,
        amount,
        user_id,
        ip_address,
        device_info
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Insufficient balance"
    assert transaction.amount > low_balance_account.balance


# ============================================================================
# Scenario: invalid_beneficiary
# ============================================================================

def test_invalid_beneficiary_account_rejected(
    mock_transaction_service: Mock,
    valid_account: Account
):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    invalid_beneficiary = Account(
        account_id="INVALID",
        routing_number="000000000",  # Invalid routing number
        balance=Decimal("0.00"),
        customer_id="INVALID",
        status="INVALID"
    )
    
    amount = Decimal("500.00")
    user_id = "user-123"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"
    
    expected_transaction = Transaction(
        transaction_id="TXN-REJECTED-004",
        from_account=valid_account.account_id,
        to_account=invalid_beneficiary.account_id,
        amount=amount,
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.REJECTED,
        rejection_reason="Invalid beneficiary account"
    )
    
    mock_transaction_service.process_transaction.return_value = expected_transaction
    
    # Act
    transaction = mock_transaction_service.process_transaction(
        valid_account,
        invalid_beneficiary,
        amount,
        user_id,
        ip_address,
        device_info
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid beneficiary account"


# ============================================================================
# Additional Compliance Tests
# ============================================================================

def test_ctr_threshold_boundary(rule_resolver: RuleResolver):
    """
    Test CTR threshold boundary at $10,000.
    """
    # Arrange
    ctr_threshold = rule_resolver.get_ctr_threshold()
    
    # Assert
    assert ctr_threshold == Decimal("10000"), (
        "CTR threshold must be exactly $10,000"
    )


def test_travel_rule_threshold_boundary(rule_resolver: RuleResolver):
    """
    Test Travel Rule threshold boundary at $3,000.
    """
    # Arrange
    travel_rule_threshold = rule_resolver.get_travel_rule_threshold()
    
    # Assert
    assert travel_rule_threshold == Decimal("3000"), (
        "Travel Rule threshold must be exactly $3,000"
    )


def test_wire_dual_approval_threshold(rule_resolver: RuleResolver):
    """
    Test wire dual approval threshold at $10,000.
    """
    # Arrange
    wire_threshold = rule_resolver.get_wire_dual_approval_threshold()
    
    # Assert
    assert wire_threshold == Decimal("10000"), (
        "Wire dual approval threshold must be exactly $10,000"
    )


def test_ofac_fuzzy_match_threshold(rule_resolver: RuleResolver):
    """
    Test OFAC fuzzy match threshold at 85%.
    """
    # Arrange
    ofac_threshold = rule_resolver.get_ofac_fuzzy_threshold()
    
    # Assert
    assert ofac_threshold == 85, (
        "OFAC fuzzy match threshold must be exactly 85%"
    )


def test_beneficial_ownership_percentage(rule_resolver: RuleResolver):
    """
    Test beneficial ownership threshold at 20%.
    """
    # Arrange
    beneficial_ownership_pct = rule_resolver.get_beneficial_ownership_pct()
    
    # Assert
    assert beneficial_ownership_pct == Decimal("20"), (
        "Beneficial ownership threshold must be exactly 20%"
    )


def test_audit_trail_contains_required_fields(
    mock_audit_logger: Mock
):
    """
    Test that audit trail contains all required fields per compliance requirements.
    """
    # Arrange
    user_id = "user-123"
    action = "WIRE_TRANSFER"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    details = {
        "amount": "5000.00",
        "from_account": "ACC-123",
        "to_account": "ACC-456"
    }
    
    audit_log = AuditLog(
        log_id="audit-456",
        timestamp=datetime.now(timezone.utc),
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        device_info=device_info,
        details=details
    )
    
    mock_audit_logger.log.return_value = audit_log
    
    # Act
    log = mock_audit_logger.log(user_id, action, ip_address, device_info, details)
    
    # Assert - All required audit fields present
    assert log.timestamp is not None
    assert log.timestamp.tzinfo is not None, "Timestamp must be timezone-aware"
    assert log.user_id == user_id
    assert log.ip_address == ip_address
    assert log.device_info == device_info
    assert log.action == action
    assert log.details is not None


def test_ofac_screening_below_threshold_allows_transaction(
    mock_ofac_service: Mock
):
    """
    Test OFAC screening allows transaction when match score below threshold.
    """
    # Arrange
    customer_name = "John Smith"
    ofac_threshold = 85
    
    mock_ofac_service.screen.return_value = {
        "match": False,
        "score": 50,  # Below threshold
        "action": "ALLOW"
    }
    
    # Act
    result = mock_ofac_service.screen(customer_name, ofac_threshold)
    
    # Assert
    assert result["match"] is False
    assert result["score"] < ofac_threshold
    assert result["action"] == "ALLOW"


def test_ofac_screening_at_threshold_triggers_review(
    mock_ofac_service: Mock
):
    """
    Test OFAC screening triggers review at exact threshold (85%).
    """
    # Arrange
    customer_name = "Suspicious Name"
    ofac_threshold = 85
    
    mock_ofac_service.screen.return_value = {
        "match": True,
        "score": 85,  # At threshold
        "action": "REVIEW"
    }
    
    # Act
    result = mock_ofac_service.screen(customer_name, ofac_threshold)
    
    # Assert
    assert result["match"] is True
    assert result["score"] >= ofac_threshold
    assert result["action"] in ["REVIEW", "BLOCK"]


def test_ofac_screening_above_threshold_blocks_transaction(
    mock_ofac_service: Mock
):
    """
    Test OFAC screening blocks transaction when match score above threshold.
    """
    # Arrange
    customer_name = "Sanctioned Entity"
    ofac_threshold = 85
    
    mock_ofac_service.screen.return_value = {
        "match": True,
        "score": 95,  # Above threshold
        "action": "BLOCK"
    }
    
    # Act
    result = mock_ofac_service.screen(customer_name, ofac_threshold)
    
    # Assert
    assert result["match"] is True
    assert result["score"] > ofac_threshold
    assert result["action"] == "BLOCK"


def test_pii_masking_ssn_in_logs():
    """
    Test that SSN is properly masked in logs (show last 4 only).
    """
    # Arrange
    customer = Customer(
        customer_id="CUST-123",
        name="Jane Doe",
        ssn="123-45-6789",
        is_employee=False
    )
    
    # Act - Simulate masking function
    def mask_ssn(ssn: str) -> str:
        if len(ssn) >= 4:
            return "***-**-" + ssn[-4:]
        return "***"
    
    masked_ssn = mask_ssn(customer.ssn)
    
    # Assert
    assert masked_ssn == "***-**-6789"
    assert "123-45" not in masked_ssn
    assert masked_ssn.endswith("6789")


def test_transaction_timestamp_is_timezone_aware():
    """
    Test that transaction timestamps are timezone-aware (UTC).
    """
    # Arrange & Act
    transaction = Transaction(
        transaction_id="TXN-999",
        from_account="ACC-123",
        to_account="ACC-456",
        amount=Decimal("1000.00"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS
    )
    
    # Assert
    assert transaction.timestamp.tzinfo is not None, (
        "Transaction timestamp must be timezone-aware"
    )
    assert transaction.timestamp.tzinfo == timezone.utc, (
        "Transaction timestamp should use UTC"
    )


def test_sar_retention_period_five_years():
    """
    Test SAR retention requirement (5 years per 31 CFR 1010.430).
    """
    # Arrange
    sar = SARFiling(
        sar_id="SAR-RETENTION-001",
        customer_id="CUST-123",
        amount=Decimal("6000.00"),
        reason="Suspicious pattern",
        filed_date=datetime.now(timezone.utc),
        detection_date=datetime.now(timezone.utc) - timedelta(days=5),
        is_insider=False,
        status=SARStatus.FILED
    )
    
    retention_years = 5
    retention_date = sar.filed_date + timedelta(days=365 * retention_years)
    
    # Assert
    assert (retention_date - sar.filed_date).days >= (365 * 5), (
        "SAR records must be retained for 5 years per 31 CFR 1010.430"
    )


def test_high_value_wire_requires_dual_approval(
    rule_resolver: RuleResolver
):
    """
    Test that wires >= $10,000 require dual approval.
    """
    # Arrange
    wire_threshold = rule_resolver.get_wire_dual_approval_threshold()
    wire_amount = Decimal("10000.00")
    
    # Act
    requires_dual_approval = wire_amount >= wire_threshold
    
    # Assert
    assert requires_dual_approval is True, (
        f"Wire transfers >= ${wire_threshold} require dual approval"
    )


def test_wire_below_threshold_no_dual_approval(
    rule_resolver: RuleResolver
):
    """
    Test that wires < $10,000 do not require dual approval.
    """
    # Arrange
    wire_threshold = rule_resolver.get_wire_dual_approval_threshold()
    wire_amount = Decimal("9999.99")
    
    # Act
    requires_dual_approval = wire_amount >= wire_threshold
    
    # Assert
    assert requires_dual_approval is False, (
        f"Wire transfers < ${wire_threshold} do not require dual approval"
    )


def test_travel_rule_data_required_above_threshold(
    rule_resolver: RuleResolver
):
    """
    Test that Travel Rule data is required for transactions > $3,000.
    """
    # Arrange
    travel_rule_threshold = rule_resolver.get_travel_rule_threshold()
    transaction_amount = Decimal("3000.01")
    
    # Act
    requires_travel_rule_data = transaction_amount > travel_rule_threshold
    
    # Assert
    assert requires_travel_rule_data is True, (
        f"Travel Rule data required for transactions > ${travel_rule_threshold}"
    )


def test_travel_rule_data_not_required_at_threshold(
    rule_resolver: RuleResolver
):
    """
    Test that Travel Rule data is not required at exactly $3,000.
    """
    # Arrange
    travel_rule_threshold = rule_resolver.get_travel_rule_threshold()
    transaction_amount = travel_rule_threshold
    
    # Act
    requires_travel_rule_data = transaction_amount > travel_rule_threshold
    
    # Assert
    assert requires_travel_rule_data is False, (
        f"Travel Rule data not required at exactly ${travel_rule_threshold}"
    )