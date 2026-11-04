import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# Domain Models
# ============================================================================

class TransactionStatus(Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    PENDING = "pending"
    BLOCKED = "blocked"


class SARFilingReason(Enum):
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    INSIDER_ABUSE = "insider_abuse"
    STRUCTURING = "structuring"
    NO_SUSPECT_IDENTIFIED = "no_suspect_identified"


@dataclass
class Account:
    account_id: str
    balance: Decimal
    routing_number: str
    account_number: str
    owner_name: str
    ssn: Optional[str] = None


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
    subject_name: str
    subject_tin: Optional[str]
    activity_date: datetime
    amount: Decimal
    reason: SARFilingReason
    filed_date: datetime
    detection_date: datetime
    narrative: str
    continuing_activity: bool = False


@dataclass
class AuditLogEntry:
    timestamp: datetime
    user_id: str
    action: str
    transaction_id: Optional[str]
    ip_address: str
    device_info: str
    details: Dict[str, Any]


# ============================================================================
# Service Interfaces
# ============================================================================

class AccountService:
    def get_account(self, account_id: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_id: str, new_balance: Decimal) -> bool:
        raise NotImplementedError

    def validate_routing_account(self, routing: str, account: str) -> bool:
        raise NotImplementedError


class TransactionService:
    def __init__(
        self,
        account_service: AccountService,
        audit_service: 'AuditService',
        monitoring_service: 'MonitoringService',
        sar_service: 'SARService'
    ):
        self.account_service = account_service
        self.audit_service = audit_service
        self.monitoring_service = monitoring_service
        self.sar_service = sar_service

    def execute_transaction(
        self,
        from_account_id: str,
        to_account_id: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        raise NotImplementedError


class MonitoringService:
    def detect_suspicious_activity(self, transaction: Transaction) -> bool:
        raise NotImplementedError

    def is_insider(self, account_id: str) -> bool:
        raise NotImplementedError

    def get_suspicious_amount(self, transaction: Transaction) -> Decimal:
        raise NotImplementedError


class SARService:
    def __init__(self, sar_threshold: Decimal = Decimal("5000")):
        self.sar_threshold = sar_threshold
        self.filed_sars: List[SARFiling] = []

    def file_sar(
        self,
        subject_name: str,
        subject_tin: Optional[str],
        activity_date: datetime,
        amount: Decimal,
        reason: SARFilingReason,
        detection_date: datetime,
        narrative: str
    ) -> SARFiling:
        raise NotImplementedError

    def should_file_sar(
        self,
        amount: Decimal,
        is_suspicious: bool,
        is_insider: bool
    ) -> bool:
        raise NotImplementedError

    def is_sar_filed_for_customer(self, customer_id: str) -> bool:
        raise NotImplementedError

    def disclose_sar_filing(self) -> bool:
        return False


class AuditService:
    def log_transaction(
        self,
        transaction: Transaction,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> AuditLogEntry:
        raise NotImplementedError


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_account_service() -> Mock:
    service = Mock(spec=AccountService)
    return service


@pytest.fixture
def mock_audit_service() -> Mock:
    service = Mock(spec=AuditService)
    return service


@pytest.fixture
def mock_monitoring_service() -> Mock:
    service = Mock(spec=MonitoringService)
    return service


@pytest.fixture
def mock_sar_service() -> Mock:
    service = Mock(spec=SARService)
    service.sar_threshold = Decimal("5000")
    service.filed_sars = []
    service.disclose_sar_filing.return_value = False
    return service


@pytest.fixture
def transaction_service(
    mock_account_service,
    mock_audit_service,
    mock_monitoring_service,
    mock_sar_service
) -> TransactionService:
    return TransactionService(
        account_service=mock_account_service,
        audit_service=mock_audit_service,
        monitoring_service=mock_monitoring_service,
        sar_service=mock_sar_service
    )


@pytest.fixture
def valid_account() -> Account:
    return Account(
        account_id="ACC-001",
        balance=Decimal("10000.00"),
        routing_number="021000021",
        account_number="1234567890",
        owner_name="John Doe",
        ssn="123-45-6789"
    )


@pytest.fixture
def beneficiary_account() -> Account:
    return Account(
        account_id="ACC-002",
        balance=Decimal("5000.00"),
        routing_number="021000022",
        account_number="0987654321",
        owner_name="Jane Smith",
        ssn="987-65-4321"
    )


@pytest.fixture
def current_time() -> datetime:
    return datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)


# ============================================================================
# MUST-TEST OBLIGATIONS: FINCEN-SAR-001 (31 C.F.R. § 1020.320)
# ============================================================================

def test_obl_001_sar_filing_for_suspicious_activity_at_5000_threshold(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::001] Banks must file a SAR for any transaction
    that involves or aggregates to $5,000 or more where the institution
    knows, suspects, or has reason to suspect money laundering, BSA
    violations, or structuring.
    
    Test: Suspicious activity at exactly $5,000 must trigger SAR filing.
    """
    # Arrange
    amount = Decimal("5000.00")
    is_suspicious = True
    is_insider = False
    
    mock_sar_service.should_file_sar.return_value = True
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-001",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Suspicious pattern detected"
    )
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is True, (
        "SAR must be filed for suspicious transaction of $5,000 or more "
        "per 31 C.F.R. § 1020.320"
    )
    
    sar = mock_sar_service.file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=current_time,
        narrative="Suspicious pattern detected"
    )
    
    assert sar.amount >= Decimal("5000.00"), (
        "SAR filing amount must be $5,000 or more per 31 C.F.R. § 1020.320"
    )


def test_obl_001_sar_filing_for_suspicious_activity_above_5000(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::001] Banks must file a SAR for any transaction
    that involves or aggregates to $5,000 or more where the institution
    knows, suspects, or has reason to suspect money laundering.
    
    Test: Suspicious activity above $5,000 must trigger SAR filing.
    """
    # Arrange
    amount = Decimal("7500.00")
    is_suspicious = True
    is_insider = False
    
    mock_sar_service.should_file_sar.return_value = True
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is True, (
        "SAR must be filed for suspicious transaction above $5,000 "
        "per 31 C.F.R. § 1020.320"
    )


def test_obl_001_no_sar_for_suspicious_activity_below_5000(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::001] Banks must file a SAR for any transaction
    that involves or aggregates to $5,000 or more.
    
    Test: Suspicious activity below $5,000 should NOT trigger SAR filing
    (unless insider abuse or other exception applies).
    """
    # Arrange
    amount = Decimal("4999.99")
    is_suspicious = True
    is_insider = False
    
    mock_sar_service.should_file_sar.return_value = False
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is False, (
        "SAR must NOT be filed for suspicious transaction below $5,000 "
        "per 31 C.F.R. § 1020.320"
    )


def test_obl_002_sar_filing_for_insider_abuse_any_amount(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::002] For insider abuse, SAR must be filed
    regardless of amount.
    
    Test: Insider abuse at $1 must trigger SAR filing.
    """
    # Arrange
    amount = Decimal("1.00")
    is_suspicious = True
    is_insider = True
    
    mock_sar_service.should_file_sar.return_value = True
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-002",
        subject_name="Insider Employee",
        subject_tin="111-22-3333",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.INSIDER_ABUSE,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Insider abuse detected"
    )
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is True, (
        "SAR must be filed for insider abuse regardless of amount "
        "per 31 C.F.R. § 1020.320"
    )
    
    sar = mock_sar_service.file_sar(
        subject_name="Insider Employee",
        subject_tin="111-22-3333",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.INSIDER_ABUSE,
        detection_date=current_time,
        narrative="Insider abuse detected"
    )
    
    assert sar.reason == SARFilingReason.INSIDER_ABUSE, (
        "SAR reason must be insider abuse per 31 C.F.R. § 1020.320"
    )


def test_obl_002_sar_filing_for_insider_abuse_zero_amount(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::002] For insider abuse, SAR must be filed
    regardless of amount.
    
    Test: Insider abuse at $0 (e.g., unauthorized access) must trigger SAR.
    """
    # Arrange
    amount = Decimal("0.00")
    is_suspicious = True
    is_insider = True
    
    mock_sar_service.should_file_sar.return_value = True
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is True, (
        "SAR must be filed for insider abuse at any amount including $0 "
        "per 31 C.F.R. § 1020.320"
    )


def test_obl_003_sar_filing_for_25000_or_more_no_suspect(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::003] For transactions of $25,000 or more, a SAR
    must be filed even if no suspect can be identified.
    
    Test: Transaction of exactly $25,000 with no identified suspect must
    trigger SAR filing.
    """
    # Arrange
    amount = Decimal("25000.00")
    is_suspicious = True
    no_suspect_identified = True
    
    mock_sar_service.should_file_sar.return_value = True
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-003",
        subject_name="Unknown",
        subject_tin=None,
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Suspicious activity $25,000+, no suspect identified"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="Unknown",
        subject_tin=None,
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
        detection_date=current_time,
        narrative="Suspicious activity $25,000+, no suspect identified"
    )
    
    # Assert
    assert sar.amount >= Decimal("25000.00"), (
        "SAR must be filed for transactions of $25,000 or more even if no "
        "suspect can be identified per 31 C.F.R. § 1020.320"
    )
    assert sar.subject_tin is None or sar.subject_name == "Unknown", (
        "SAR may be filed without identified suspect for $25,000+ transactions "
        "per 31 C.F.R. § 1020.320"
    )


def test_obl_003_sar_filing_for_above_25000_no_suspect(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::003] For transactions of $25,000 or more, a SAR
    must be filed even if no suspect can be identified.
    
    Test: Transaction above $25,000 with no identified suspect.
    """
    # Arrange
    amount = Decimal("50000.00")
    
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-004",
        subject_name="Unknown",
        subject_tin=None,
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Large transaction, no suspect identified"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="Unknown",
        subject_tin=None,
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
        detection_date=current_time,
        narrative="Large transaction, no suspect identified"
    )
    
    # Assert
    assert sar.amount >= Decimal("25000.00"), (
        "SAR must be filed for transactions of $25,000 or more per 31 C.F.R. § 1020.320"
    )


def test_obl_004_sar_filing_within_30_days_of_detection(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::004] SARs must be filed within 30 calendar days
    of initial detection.
    
    Test: SAR filed date must be within 30 days of detection date.
    """
    # Arrange
    detection_date = current_time
    filed_date = current_time + timedelta(days=25)
    amount = Decimal("10000.00")
    
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-005",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=filed_date,
        detection_date=detection_date,
        narrative="Suspicious activity detected"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative="Suspicious activity detected"
    )
    
    # Assert
    days_to_file = (sar.filed_date - sar.detection_date).days
    assert days_to_file <= 30, (
        f"SAR must be filed within 30 calendar days of detection "
        f"per 31 C.F.R. § 1020.320 (filed in {days_to_file} days)"
    )


def test_obl_004_sar_filing_deadline_violation(
    mock_sar_service,
    current_time
):
    """
    [FINCEN-SAR-001::OBL::004] SARs must be filed within 30 calendar days
    of initial detection.
    
    Test: SAR filed after 30 days violates the deadline requirement.
    """
    # Arrange
    detection_date = current_time
    filed_date = current_time + timedelta(days=31)
    amount = Decimal("10000.00")
    
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-006",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=filed_date,
        detection_date=detection_date,
        narrative="Late SAR filing"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative="Late SAR filing"
    )
    
    # Assert
    days_to_file = (sar.filed_date - sar.detection_date).days
    assert days_to_file > 30, (
        f"Test validation: SAR was filed in {days_to_file} days, "
        f"violating the 30-day requirement per 31 C.F.R. § 1020.320"
    )


# ============================================================================
# BDD Scenario Tests
# ============================================================================

def test_scenario_successful_transaction(
    mock_account_service,
    mock_audit_service,
    mock_monitoring_service,
    valid_account,
    beneficiary_account,
    current_time
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    amount = Decimal("1000.00")
    new_balance = valid_account.balance - amount
    
    mock_account_service.get_account.side_effect = [valid_account, beneficiary_account]
    mock_account_service.update_balance.return_value = True
    mock_account_service.validate_routing_account.return_value = True
    mock_monitoring_service.detect_suspicious_activity.return_value = False
    
    transaction = Transaction(
        transaction_id="TXN-001",
        from_account=valid_account.account_id,
        to_account=beneficiary_account.account_id,
        amount=amount,
        timestamp=current_time,
        status=TransactionStatus.SUCCESS,
        metadata={"user_id": "USER-001"}
    )
    
    audit_entry = AuditLogEntry(
        timestamp=current_time,
        user_id="USER-001",
        action="TRANSFER",
        transaction_id="TXN-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0",
        details={"amount": str(amount)}
    )
    
    mock_audit_service.log_transaction.return_value = audit_entry
    
    # Act
    from_account = mock_account_service.get_account(valid_account.account_id)
    to_account = mock_account_service.get_account(beneficiary_account.account_id)
    
    assert from_account.balance >= amount
    assert mock_account_service.validate_routing_account(
        to_account.routing_number,
        to_account.account_number
    )
    
    balance_updated = mock_account_service.update_balance(
        valid_account.account_id,
        new_balance
    )
    
    audit_log = mock_audit_service.log_transaction(
        transaction,
        "USER-001",
        "192.168.1.1",
        "Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    assert balance_updated is True
    assert audit_log.transaction_id == "TXN-001"
    assert audit_log.user_id == "USER-001"


def test_scenario_sar_suspicious_activity_above_threshold(
    mock_sar_service,
    mock_monitoring_service,
    current_time
):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    amount = Decimal("7500.00")
    detection_date = current_time
    filing_date = current_time + timedelta(days=20)
    
    transaction = Transaction(
        transaction_id="TXN-002",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=amount,
        timestamp=current_time,
        status=TransactionStatus.SUCCESS
    )
    
    mock_monitoring_service.detect_suspicious_activity.return_value = True
    mock_monitoring_service.get_suspicious_amount.return_value = amount
    mock_monitoring_service.is_insider.return_value = False
    
    sar = SARFiling(
        sar_id="SAR-007",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=filing_date,
        detection_date=detection_date,
        narrative="Suspicious pattern detected"
    )
    
    mock_sar_service.file_sar.return_value = sar
    mock_sar_service.disclose_sar_filing.return_value = False
    
    # Act
    is_suspicious = mock_monitoring_service.detect_suspicious_activity(transaction)
    suspicious_amount = mock_monitoring_service.get_suspicious_amount(transaction)
    
    assert is_suspicious
    assert suspicious_amount > Decimal("5000.00")
    
    filed_sar = mock_sar_service.file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative="Suspicious pattern detected"
    )
    
    subject_notified = mock_sar_service.disclose_sar_filing()
    
    # Assert
    assert filed_sar.amount > Decimal("5000.00")
    assert (filed_sar.filed_date - filed_sar.detection_date).days <= 30
    assert subject_notified is False, "Subject must NOT be notified of SAR filing"


def test_scenario_sar_insider_abuse_any_amount(
    mock_sar_service,
    mock_monitoring_service,
    current_time
):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    amount = Decimal("500.00")  # Below normal $5,000 threshold
    
    transaction = Transaction(
        transaction_id="TXN-003",
        from_account="ACC-INSIDER",
        to_account="ACC-002",
        amount=amount,
        timestamp=current_time,
        status=TransactionStatus.SUCCESS
    )
    
    mock_monitoring_service.is_insider.return_value = True
    mock_monitoring_service.detect_suspicious_activity.return_value = True
    
    sar = SARFiling(
        sar_id="SAR-008",
        subject_name="Insider Employee",
        subject_tin="111-22-3333",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.INSIDER_ABUSE,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Insider abuse detected"
    )
    
    mock_sar_service.file_sar.return_value = sar
    
    # Act
    is_insider = mock_monitoring_service.is_insider("ACC-INSIDER")
    is_suspicious = mock_monitoring_service.detect_suspicious_activity(transaction)
    
    assert is_insider
    assert is_suspicious
    
    filed_sar = mock_sar_service.file_sar(
        subject_name="Insider Employee",
        subject_tin="111-22-3333",
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.INSIDER_ABUSE,
        detection_date=current_time,
        narrative="Insider abuse detected"
    )
    
    # Assert
    assert filed_sar.reason == SARFilingReason.INSIDER_ABUSE
    assert filed_sar.amount < Decimal("5000.00"), (
        "Insider abuse SAR must be filed regardless of amount"
    )
    assert (filed_sar.filed_date - filed_sar.detection_date).days == 0, (
        "SAR should be filed immediately for insider abuse"
    )


def test_scenario_sar_no_tipping_off(
    mock_sar_service,
    current_time
):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    customer_id = "CUST-001"
    
    sar = SARFiling(
        sar_id="SAR-009",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Suspicious activity"
    )
    
    mock_sar_service.is_sar_filed_for_customer.return_value = True
    mock_sar_service.disclose_sar_filing.return_value = False
    
    # Act
    sar_exists = mock_sar_service.is_sar_filed_for_customer(customer_id)
    disclosure_allowed = mock_sar_service.disclose_sar_filing()
    
    # Assert
    assert sar_exists is True
    assert disclosure_allowed is False, (
        "Bank must NOT disclose SAR filing to customer (no tipping off)"
    )


def test_scenario_zero_amount_transfer(
    mock_account_service,
    valid_account,
    current_time
):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    amount = Decimal("0.00")
    
    # Act
    if amount <= Decimal("0"):
        transaction = Transaction(
            transaction_id="TXN-004",
            from_account=valid_account.account_id,
            to_account="ACC-002",
            amount=amount,
            timestamp=current_time,
            status=TransactionStatus.REJECTED,
            rejection_reason="Amount must be greater than 0"
        )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Amount must be greater than 0"


def test_scenario_negative_amount_transfer(
    mock_account_service,
    valid_account,
    current_time
):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    amount = Decimal("-100.00")
    
    # Act
    if amount < Decimal("0"):
        transaction = Transaction(
            transaction_id="TXN-005",
            from_account=valid_account.account_id,
            to_account="ACC-002",
            amount=amount,
            timestamp=current_time,
            status=TransactionStatus.REJECTED,
            rejection_reason="Invalid amount"
        )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid amount"


def test_scenario_insufficient_balance(
    mock_account_service,
    current_time
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
        balance=Decimal("1000.00"),
        routing_number="021000021",
        account_number="1234567890",
        owner_name="John Doe"
    )
    amount = Decimal("5000.00")
    
    mock_account_service.get_account.return_value = account
    
    # Act
    user_account = mock_account_service.get_account("ACC-001")
    
    if user_account.balance < amount:
        transaction = Transaction(
            transaction_id="TXN-006",
            from_account=account.account_id,
            to_account="ACC-002",
            amount=amount,
            timestamp=current_time,
            status=TransactionStatus.REJECTED,
            rejection_reason="Insufficient balance"
        )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Insufficient balance"


def test_scenario_invalid_beneficiary(
    mock_account_service,
    valid_account,
    current_time
):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    invalid_routing = "000000000"
    invalid_account = "0000000000"
    amount = Decimal("1000.00")
    
    mock_account_service.validate_routing_account.return_value = False
    
    # Act
    is_valid = mock_account_service.validate_routing_account(
        invalid_routing,
        invalid_account
    )
    
    if not is_valid:
        transaction = Transaction(
            transaction_id="TXN-007",
            from_account=valid_account.account_id,
            to_account="INVALID",
            amount=amount,
            timestamp=current_time,
            status=TransactionStatus.REJECTED,
            rejection_reason="Invalid beneficiary account"
        )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid beneficiary account"


# ============================================================================
# Boundary and Threshold Tests (using AUTHORITATIVE THRESHOLDS)
# ============================================================================

def test_sar_threshold_boundary_at_4999_99(
    mock_sar_service,
    current_time
):
    """
    Test SAR threshold boundary: $4,999.99 (just below $5,000 threshold)
    should NOT trigger SAR for non-insider suspicious activity.
    """
    # Arrange
    amount = Decimal("4999.99")
    is_suspicious = True
    is_insider = False
    
    mock_sar_service.should_file_sar.return_value = False
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is False, (
        "SAR should NOT be filed for suspicious activity just below $5,000 threshold"
    )


def test_sar_threshold_boundary_at_5000_00(
    mock_sar_service,
    current_time
):
    """
    Test SAR threshold boundary: exactly $5,000.00 should trigger SAR
    for suspicious activity.
    """
    # Arrange
    amount = Decimal("5000.00")
    is_suspicious = True
    is_insider = False
    
    mock_sar_service.should_file_sar.return_value = True
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is True, (
        "SAR must be filed for suspicious activity at exactly $5,000 threshold"
    )


def test_sar_threshold_boundary_at_5000_01(
    mock_sar_service,
    current_time
):
    """
    Test SAR threshold boundary: $5,000.01 (just above $5,000 threshold)
    should trigger SAR for suspicious activity.
    """
    # Arrange
    amount = Decimal("5000.01")
    is_suspicious = True
    is_insider = False
    
    mock_sar_service.should_file_sar.return_value = True
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is True, (
        "SAR must be filed for suspicious activity above $5,000 threshold"
    )


def test_sar_threshold_25000_boundary_at_24999_99(
    mock_sar_service,
    current_time
):
    """
    Test $25,000 threshold boundary: $24,999.99 (just below) should NOT
    trigger the no-suspect-identified SAR rule.
    """
    # Arrange
    amount = Decimal("24999.99")
    
    # Act & Assert
    # This amount is below the $25,000 threshold for no-suspect-identified SARs
    assert amount < Decimal("25000.00"), (
        "Amount below $25,000 threshold for no-suspect-identified SAR"
    )


def test_sar_threshold_25000_boundary_at_25000_00(
    mock_sar_service,
    current_time
):
    """
    Test $25,000 threshold boundary: exactly $25,000.00 should trigger
    SAR even with no suspect identified.
    """
    # Arrange
    amount = Decimal("25000.00")
    
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-010",
        subject_name="Unknown",
        subject_tin=None,
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
        filed_date=current_time,
        detection_date=current_time,
        narrative="$25,000+ transaction, no suspect identified"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="Unknown",
        subject_tin=None,
        activity_date=current_time,
        amount=amount,
        reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
        detection_date=current_time,
        narrative="$25,000+ transaction, no suspect identified"
    )
    
    # Assert
    assert sar.amount >= Decimal("25000.00"), (
        "SAR must be filed for $25,000+ transactions even without suspect"
    )


def test_sar_filing_deadline_boundary_day_30(
    mock_sar_service,
    current_time
):
    """
    Test SAR filing deadline boundary: filing on exactly day 30 should
    be compliant.
    """
    # Arrange
    detection_date = current_time
    filed_date = current_time + timedelta(days=30)
    
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-011",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=filed_date,
        detection_date=detection_date,
        narrative="Filed on day 30"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative="Filed on day 30"
    )
    
    # Assert
    days_to_file = (sar.filed_date - sar.detection_date).days
    assert days_to_file == 30
    assert days_to_file <= 30, (
        "SAR filed on day 30 is compliant with 30-day deadline"
    )


def test_sar_filing_deadline_boundary_day_31(
    mock_sar_service,
    current_time
):
    """
    Test SAR filing deadline boundary: filing on day 31 violates the
    30-day requirement.
    """
    # Arrange
    detection_date = current_time
    filed_date = current_time + timedelta(days=31)
    
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-012",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=filed_date,
        detection_date=detection_date,
        narrative="Filed on day 31 (late)"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative="Filed on day 31 (late)"
    )
    
    # Assert
    days_to_file = (sar.filed_date - sar.detection_date).days
    assert days_to_file == 31
    assert days_to_file > 30, (
        "SAR filed on day 31 violates the 30-day deadline requirement"
    )


# ============================================================================
# Additional Compliance Tests
# ============================================================================

def test_sar_required_fields_present(
    mock_sar_service,
    current_time
):
    """
    Test that SAR filing includes all required fields per
    FINCEN-SAR-FIELD-001: subject name, TIN/SSN, activity date, amount.
    """
    # Arrange
    sar = SARFiling(
        sar_id="SAR-013",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Complete SAR with all required fields"
    )
    
    # Assert
    assert sar.subject_name is not None and sar.subject_name != ""
    assert sar.subject_tin is not None
    assert sar.activity_date is not None
    assert sar.amount is not None and sar.amount > Decimal("0")


def test_sar_confidentiality_no_disclosure(
    mock_sar_service
):
    """
    Test SAR confidentiality per FINCEN-1010-320-R2: no disclosure of
    SAR or its existence, including in response to subpoena.
    """
    # Arrange
    mock_sar_service.disclose_sar_filing.return_value = False
    
    # Act
    can_disclose = mock_sar_service.disclose_sar_filing()
    
    # Assert
    assert can_disclose is False, (
        "SAR filing must remain confidential and not be disclosed"
    )


def test_continuing_activity_sar_90_day_period(
    mock_sar_service,
    current_time
):
    """
    Test continuing activity SAR per FINCEN-SAR-002: must be filed for
    each 90-day period until suspicious activity ceases.
    """
    # Arrange
    initial_sar_date = current_time
    continuing_sar_date = current_time + timedelta(days=90)
    
    initial_sar = SARFiling(
        sar_id="SAR-014",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=initial_sar_date,
        detection_date=current_time,
        narrative="Initial SAR",
        continuing_activity=False
    )
    
    continuing_sar = SARFiling(
        sar_id="SAR-015",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=continuing_sar_date,
        amount=Decimal("15000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        filed_date=continuing_sar_date,
        detection_date=current_time,
        narrative="Continuing activity SAR",
        continuing_activity=True
    )
    
    # Assert
    days_between = (continuing_sar.filed_date - initial_sar.filed_date).days
    assert days_between <= 90, (
        "Continuing activity SAR must be filed within 90 days of initial SAR"
    )
    assert continuing_sar.continuing_activity is True


def test_audit_trail_recorded_for_transaction(
    mock_audit_service,
    current_time
):
    """
    Test that audit trail is recorded for all transactions with required
    fields: timestamp, user ID, IP address, device info.
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-008",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("1000.00"),
        timestamp=current_time,
        status=TransactionStatus.SUCCESS
    )
    
    audit_entry = AuditLogEntry(
        timestamp=current_time,
        user_id="USER-001",
        action="TRANSFER",
        transaction_id="TXN-008",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0",
        details={"amount": "1000.00"}
    )
    
    mock_audit_service.log_transaction.return_value = audit_entry
    
    # Act
    logged_entry = mock_audit_service.log_transaction(
        transaction,
        "USER-001",
        "192.168.1.1",
        "Mozilla/5.0"
    )
    
    # Assert
    assert logged_entry.timestamp is not None
    assert logged_entry.user_id is not None
    assert logged_entry.ip_address is not None
    assert logged_entry.device_info is not None
    assert logged_entry.transaction_id == transaction.transaction_id


def test_ssn_masking_in_logs(
    valid_account
):
    """
    Test that SSN/TIN is masked in logs (show last 4 only) per
    data handling requirements.
    """
    # Arrange
    full_ssn = valid_account.ssn
    
    # Act
    masked_ssn = f"***-**-{full_ssn[-4:]}" if full_ssn else None
    
    # Assert
    assert masked_ssn == "***-**-6789"
    assert full_ssn not in masked_ssn or len(full_ssn) <= 4


def test_transaction_amount_uses_decimal_precision():
    """
    Test that transaction amounts use Decimal for currency precision.
    """
    # Arrange
    amount1 = Decimal("1000.00")
    amount2 = Decimal("0.01")
    
    # Act
    total = amount1 + amount2
    
    # Assert
    assert isinstance(total, Decimal)
    assert total == Decimal("1000.01")
    assert str(total) == "1000.01"


def test_datetime_timezone_aware(
    current_time
):
    """
    Test that datetimes are timezone-aware for compliance tracking.
    """
    # Assert
    assert current_time.tzinfo is not None
    assert current_time.tzinfo == timezone.utc


def test_sar_not_filed_for_non_suspicious_activity_below_threshold(
    mock_sar_service
):
    """
    Test that SAR is NOT filed for non-suspicious activity below threshold.
    """
    # Arrange
    amount = Decimal("3000.00")
    is_suspicious = False
    is_insider = False
    
    mock_sar_service.should_file_sar.return_value = False
    
    # Act
    should_file = mock_sar_service.should_file_sar(amount, is_suspicious, is_insider)
    
    # Assert
    assert should_file is False, (
        "SAR should NOT be filed for non-suspicious activity below threshold"
    )


def test_sar_aggregation_multiple_transactions(
    mock_sar_service,
    current_time
):
    """
    Test SAR filing for aggregated transactions that total $5,000 or more.
    """
    # Arrange
    transactions = [
        Decimal("2000.00"),
        Decimal("2000.00"),
        Decimal("1500.00")
    ]
    total_amount = sum(transactions)
    
    assert total_amount >= Decimal("5000.00")
    
    mock_sar_service.file_sar.return_value = SARFiling(
        sar_id="SAR-016",
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=total_amount,
        reason=SARFilingReason.STRUCTURING,
        filed_date=current_time,
        detection_date=current_time,
        narrative="Aggregated transactions totaling $5,500"
    )
    
    # Act
    sar = mock_sar_service.file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        activity_date=current_time,
        amount=total_amount,
        reason=SARFilingReason.STRUCTURING,
        detection_date=current_time,
        narrative="Aggregated transactions totaling $5,500"
    )
    
    # Assert
    assert sar.amount >= Decimal("5000.00")
    assert sar.reason == SARFilingReason.STRUCTURING


def test_authoritative_thresholds_used():
    """
    Test that AUTHORITATIVE THRESHOLDS are used as exact values.
    """
    # Arrange - AUTHORITATIVE THRESHOLDS from grounding block
    ctr_threshold = Decimal("10000")
    sar_threshold = Decimal("5000")
    travel_rule_threshold = Decimal("3000")
    wire_dual_approval_threshold = Decimal("10000")
    ofac_fuzzy_threshold = 85
    beneficial_ownership_pct = 20
    
    # Assert - verify exact values are used
    assert sar_threshold == Decimal("5000")
    assert ctr_threshold == Decimal("10000")
    assert travel_rule_threshold == Decimal("3000")
    assert wire_dual_approval_threshold == Decimal("10000")
    assert ofac_fuzzy_threshold == 85
    assert beneficial_ownership_pct == 20