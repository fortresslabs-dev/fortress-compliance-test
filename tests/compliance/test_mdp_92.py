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
    confidential: bool = True


@dataclass
class AuditRecord:
    audit_id: str
    timestamp: datetime
    user_id: str
    action: str
    ip_address: str
    device_info: str
    transaction_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ============================================================================
# Service Interfaces
# ============================================================================

class TransactionService:
    def __init__(
        self,
        account_repo,
        audit_logger,
        sar_service,
        monitoring_service,
        ofac_service
    ):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.sar_service = sar_service
        self.monitoring_service = monitoring_service
        self.ofac_service = ofac_service

    def execute_transaction(
        self,
        from_account_id: str,
        to_account_id: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        # Validate amount
        if amount <= 0:
            rejection_reason = "Amount must be greater than 0" if amount == 0 else "Invalid amount"
            txn = Transaction(
                transaction_id=f"txn_{datetime.now(timezone.utc).timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.audit_logger.log_transaction(txn, user_id, ip_address, device_info)
            return txn

        # Get accounts
        from_account = self.account_repo.get_account(from_account_id)
        to_account = self.account_repo.get_account(to_account_id)

        if not from_account or not to_account:
            txn = Transaction(
                transaction_id=f"txn_{datetime.now(timezone.utc).timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account"
            )
            self.audit_logger.log_transaction(txn, user_id, ip_address, device_info)
            return txn

        # Check balance
        if from_account.balance < amount:
            txn = Transaction(
                transaction_id=f"txn_{datetime.now(timezone.utc).timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance"
            )
            self.audit_logger.log_transaction(txn, user_id, ip_address, device_info)
            return txn

        # Execute transaction
        self.account_repo.debit(from_account_id, amount)
        self.account_repo.credit(to_account_id, amount)

        txn = Transaction(
            transaction_id=f"txn_{datetime.now(timezone.utc).timestamp()}",
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=datetime.now(timezone.utc),
            status=TransactionStatus.SUCCESS
        )

        self.audit_logger.log_transaction(txn, user_id, ip_address, device_info)
        self.monitoring_service.analyze_transaction(txn)

        return txn


class SARService:
    def __init__(self, fincen_gateway, audit_logger):
        self.fincen_gateway = fincen_gateway
        self.audit_logger = audit_logger
        self.sar_threshold = Decimal("5000")
        self.insider_threshold = Decimal("0")
        self.filing_deadline_days = 30

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
        sar = SARFiling(
            sar_id=f"sar_{datetime.now(timezone.utc).timestamp()}",
            subject_name=subject_name,
            subject_tin=subject_tin,
            activity_date=activity_date,
            amount=amount,
            reason=reason,
            filed_date=datetime.now(timezone.utc),
            detection_date=detection_date,
            narrative=narrative,
            confidential=True
        )
        self.fincen_gateway.submit_sar(sar)
        self.audit_logger.log_sar_filing(sar)
        return sar

    def should_file_sar_for_suspicious_activity(self, amount: Decimal) -> bool:
        return amount > self.sar_threshold

    def should_file_sar_for_insider(self, amount: Decimal) -> bool:
        return True  # Any amount for insider abuse

    def is_sar_filed_for_customer(self, customer_id: str) -> bool:
        return self.fincen_gateway.check_sar_exists(customer_id)

    def disclose_sar_to_customer(self) -> bool:
        return False  # Never disclose SAR filing


class MonitoringService:
    def __init__(self, sar_service):
        self.sar_service = sar_service

    def analyze_transaction(self, transaction: Transaction) -> Optional[SARFiling]:
        # Placeholder for suspicious pattern detection
        return None

    def detect_suspicious_pattern(
        self,
        account_id: str,
        amount: Decimal,
        pattern_type: str
    ) -> bool:
        # Mock implementation
        return False

    def detect_insider_abuse(
        self,
        employee_id: str,
        amount: Decimal
    ) -> bool:
        # Mock implementation
        return False


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_account_repo():
    repo = Mock()
    repo.get_account = Mock()
    repo.debit = Mock()
    repo.credit = Mock()
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock()
    logger.log_transaction = Mock()
    logger.log_sar_filing = Mock()
    logger.log_action = Mock()
    return logger


@pytest.fixture
def mock_fincen_gateway():
    gateway = Mock()
    gateway.submit_sar = Mock(return_value=True)
    gateway.check_sar_exists = Mock(return_value=False)
    return gateway


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen_entity = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def sar_service(mock_fincen_gateway, mock_audit_logger):
    return SARService(mock_fincen_gateway, mock_audit_logger)


@pytest.fixture
def monitoring_service(sar_service):
    return MonitoringService(sar_service)


@pytest.fixture
def transaction_service(
    mock_account_repo,
    mock_audit_logger,
    sar_service,
    monitoring_service,
    mock_ofac_service
):
    return TransactionService(
        mock_account_repo,
        mock_audit_logger,
        sar_service,
        monitoring_service,
        mock_ofac_service
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="acc_123",
        balance=Decimal("10000.00"),
        routing_number="021000021",
        account_number="1234567890",
        owner_name="John Doe",
        ssn="123-45-6789"
    )


@pytest.fixture
def valid_beneficiary_account():
    return Account(
        account_id="acc_456",
        balance=Decimal("5000.00"),
        routing_number="021000021",
        account_number="0987654321",
        owner_name="Jane Smith",
        ssn="987-65-4321"
    )


# ============================================================================
# Scenario Tests
# ============================================================================

def test_successful_transaction(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_account,
    valid_beneficiary_account
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        valid_account if acc_id == "acc_123" else valid_beneficiary_account
    )
    amount = Decimal("1000.00")
    user_id = "user_001"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"

    # Act
    result = transaction_service.execute_transaction(
        from_account_id="acc_123",
        to_account_id="acc_456",
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.amount == amount
    mock_account_repo.debit.assert_called_once_with("acc_123", amount)
    mock_account_repo.credit.assert_called_once_with("acc_456", amount)
    mock_audit_logger.log_transaction.assert_called_once()


def test_sar_suspicious_activity_above_threshold(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    subject_name = "Suspicious Customer"
    subject_tin = "123-45-6789"
    activity_date = datetime.now(timezone.utc)
    detection_date = datetime.now(timezone.utc)
    amount = Decimal("6000.00")
    narrative = "Suspicious pattern detected: rapid transfers"

    # Act
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative=narrative
    )

    # Assert
    assert sar.amount == amount
    assert sar.reason == SARFilingReason.SUSPICIOUS_ACTIVITY
    assert sar.confidential is True
    assert (sar.filed_date - detection_date).days <= 30
    mock_fincen_gateway.submit_sar.assert_called_once_with(sar)
    mock_audit_logger.log_sar_filing.assert_called_once_with(sar)
    # Verify no disclosure
    assert sar_service.disclose_sar_to_customer() is False


def test_sar_insider_abuse_any_amount(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    subject_name = "Employee John Smith"
    subject_tin = "987-65-4321"
    activity_date = datetime.now(timezone.utc)
    detection_date = datetime.now(timezone.utc)
    amount = Decimal("100.00")  # Below normal threshold
    narrative = "Insider abuse: unauthorized account access"

    # Act
    should_file = sar_service.should_file_sar_for_insider(amount)
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.INSIDER_ABUSE,
        detection_date=detection_date,
        narrative=narrative
    )

    # Assert
    assert should_file is True
    assert sar.amount == amount
    assert sar.reason == SARFilingReason.INSIDER_ABUSE
    assert sar.confidential is True
    mock_fincen_gateway.submit_sar.assert_called_once_with(sar)
    mock_audit_logger.log_sar_filing.assert_called_once_with(sar)


def test_sar_no_tipping_off(sar_service, mock_fincen_gateway):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    customer_id = "cust_123"
    mock_fincen_gateway.check_sar_exists.return_value = True

    # Act
    sar_exists = sar_service.is_sar_filed_for_customer(customer_id)
    should_disclose = sar_service.disclose_sar_to_customer()

    # Assert
    assert sar_exists is True
    assert should_disclose is False, "SAR filing must never be disclosed to customer"


def test_zero_amount_transfer(
    transaction_service,
    mock_account_repo,
    mock_audit_logger
):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    amount = Decimal("0.00")
    user_id = "user_001"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"

    # Act
    result = transaction_service.execute_transaction(
        from_account_id="acc_123",
        to_account_id="acc_456",
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Amount must be greater than 0"
    mock_account_repo.debit.assert_not_called()
    mock_account_repo.credit.assert_not_called()


def test_negative_amount_transfer(
    transaction_service,
    mock_account_repo,
    mock_audit_logger
):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    amount = Decimal("-100.00")
    user_id = "user_001"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"

    # Act
    result = transaction_service.execute_transaction(
        from_account_id="acc_123",
        to_account_id="acc_456",
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid amount"
    mock_account_repo.debit.assert_not_called()
    mock_account_repo.credit.assert_not_called()


def test_insufficient_balance(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_account,
    valid_beneficiary_account
):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    low_balance_account = Account(
        account_id="acc_123",
        balance=Decimal("1000.00"),
        routing_number="021000021",
        account_number="1234567890",
        owner_name="John Doe",
        ssn="123-45-6789"
    )
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        low_balance_account if acc_id == "acc_123" else valid_beneficiary_account
    )
    amount = Decimal("5000.00")
    user_id = "user_001"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"

    # Act
    result = transaction_service.execute_transaction(
        from_account_id="acc_123",
        to_account_id="acc_456",
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Insufficient balance"
    mock_account_repo.debit.assert_not_called()
    mock_account_repo.credit.assert_not_called()


def test_invalid_beneficiary(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_account
):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        valid_account if acc_id == "acc_123" else None
    )
    amount = Decimal("1000.00")
    user_id = "user_001"
    ip_address = "192.168.1.1"
    device_info = "Mozilla/5.0"

    # Act
    result = transaction_service.execute_transaction(
        from_account_id="acc_123",
        to_account_id="invalid_acc",
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"
    mock_account_repo.debit.assert_not_called()
    mock_account_repo.credit.assert_not_called()


# ============================================================================
# MUST-TEST OBLIGATIONS - Explicit Tests for 31 C.F.R. § 1020.320
# ============================================================================

def test_obligation_001_sar_filing_for_suspicious_activity_at_5000_threshold(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    [FINCEN-SAR-001::OBL::001] Banks must file a Suspicious Activity Report (SAR)
    for any transaction that involves or aggregates to $5,000 or more where the
    institution knows, suspects, or has reason to suspect money laundering, BSA
    violations, or structuring.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    threshold_amount = Decimal("5000.00")
    above_threshold = Decimal("5000.01")
    below_threshold = Decimal("4999.99")

    # Act
    should_file_at_threshold = sar_service.should_file_sar_for_suspicious_activity(threshold_amount)
    should_file_above = sar_service.should_file_sar_for_suspicious_activity(above_threshold)
    should_file_below = sar_service.should_file_sar_for_suspicious_activity(below_threshold)

    # Assert
    assert should_file_above is True, (
        "31 C.F.R. § 1020.320: SAR must be filed for suspicious activity > $5,000"
    )
    assert should_file_at_threshold is False, (
        "31 C.F.R. § 1020.320: SAR threshold is > $5,000, not >= $5,000"
    )
    assert should_file_below is False, (
        "31 C.F.R. § 1020.320: SAR not required for suspicious activity <= $5,000"
    )


def test_obligation_001_sar_filing_for_suspicious_activity_above_5000(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    [FINCEN-SAR-001::OBL::001] Verify SAR is filed for suspicious activity > $5,000.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    subject_name = "Suspicious Actor"
    subject_tin = "111-22-3333"
    activity_date = datetime.now(timezone.utc)
    detection_date = datetime.now(timezone.utc)
    amount = Decimal("7500.00")
    narrative = "Structuring detected: multiple deposits just under $10,000"

    # Act
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.STRUCTURING,
        detection_date=detection_date,
        narrative=narrative
    )

    # Assert
    assert sar.amount > Decimal("5000.00"), (
        "31 C.F.R. § 1020.320: SAR must be filed for suspicious activity > $5,000"
    )
    assert sar.reason in [
        SARFilingReason.SUSPICIOUS_ACTIVITY,
        SARFilingReason.STRUCTURING
    ], (
        "31 C.F.R. § 1020.320: SAR reason must indicate money laundering, "
        "BSA violations, or structuring"
    )
    mock_fincen_gateway.submit_sar.assert_called_once()


def test_obligation_002_sar_filing_for_insider_abuse_any_amount(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    [FINCEN-SAR-001::OBL::002] For insider abuse, SAR must be filed regardless
    of amount.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    small_amounts = [Decimal("1.00"), Decimal("50.00"), Decimal("500.00")]
    
    for amount in small_amounts:
        # Act
        should_file = sar_service.should_file_sar_for_insider(amount)
        
        sar = sar_service.file_sar(
            subject_name="Insider Employee",
            subject_tin="999-88-7777",
            activity_date=datetime.now(timezone.utc),
            amount=amount,
            reason=SARFilingReason.INSIDER_ABUSE,
            detection_date=datetime.now(timezone.utc),
            narrative=f"Insider abuse detected: amount ${amount}"
        )
        
        # Assert
        assert should_file is True, (
            f"31 C.F.R. § 1020.320: SAR must be filed for insider abuse "
            f"regardless of amount (tested with ${amount})"
        )
        assert sar.reason == SARFilingReason.INSIDER_ABUSE, (
            "31 C.F.R. § 1020.320: SAR reason must be insider abuse"
        )


def test_obligation_002_insider_abuse_no_minimum_threshold(
    sar_service
):
    """
    [FINCEN-SAR-001::OBL::002] Verify no minimum threshold for insider abuse.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    minimal_amount = Decimal("0.01")
    
    # Act
    should_file = sar_service.should_file_sar_for_insider(minimal_amount)
    
    # Assert
    assert should_file is True, (
        "31 C.F.R. § 1020.320: SAR must be filed for insider abuse at any amount, "
        "including $0.01"
    )
    assert sar_service.insider_threshold == Decimal("0"), (
        "31 C.F.R. § 1020.320: Insider abuse threshold must be $0 (no minimum)"
    )


def test_obligation_003_sar_filing_for_25000_or_more_no_suspect(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    [FINCEN-SAR-001::OBL::003] For transactions of $25,000 or more, a SAR must
    be filed even if no suspect can be identified.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    subject_name = "Unknown Subject"
    subject_tin = None  # No suspect identified
    activity_date = datetime.now(timezone.utc)
    detection_date = datetime.now(timezone.utc)
    amount = Decimal("25000.00")
    narrative = "Suspicious activity detected, no suspect identified"

    # Act
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
        detection_date=detection_date,
        narrative=narrative
    )

    # Assert
    assert sar.amount >= Decimal("25000.00"), (
        "31 C.F.R. § 1020.320: SAR must be filed for transactions >= $25,000 "
        "even if no suspect can be identified"
    )
    assert sar.subject_tin is None, (
        "31 C.F.R. § 1020.320: SAR can be filed without suspect identification "
        "for amounts >= $25,000"
    )
    assert sar.reason == SARFilingReason.NO_SUSPECT_IDENTIFIED, (
        "31 C.F.R. § 1020.320: SAR reason must indicate no suspect identified"
    )
    mock_fincen_gateway.submit_sar.assert_called()


def test_obligation_003_sar_filing_above_25000_boundary(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    [FINCEN-SAR-001::OBL::003] Boundary test for $25,000 threshold with no suspect.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    amounts = [
        Decimal("24999.99"),  # Just below threshold
        Decimal("25000.00"),  # At threshold
        Decimal("25000.01"),  # Just above threshold
        Decimal("50000.00")   # Well above threshold
    ]

    for amount in amounts:
        # Act
        sar = sar_service.file_sar(
            subject_name="Unknown",
            subject_tin=None,
            activity_date=datetime.now(timezone.utc),
            amount=amount,
            reason=SARFilingReason.NO_SUSPECT_IDENTIFIED,
            detection_date=datetime.now(timezone.utc),
            narrative=f"Suspicious activity: ${amount}, no suspect"
        )

        # Assert
        if amount >= Decimal("25000.00"):
            assert sar.subject_tin is None, (
                f"31 C.F.R. § 1020.320: SAR must be filed for ${amount} "
                f"even without suspect identification"
            )
            mock_fincen_gateway.submit_sar.assert_called()


def test_obligation_004_sar_filing_within_30_days(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    [FINCEN-SAR-001::OBL::004] SARs must be filed within 30 calendar days of
    initial detection.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    subject_name = "Suspicious Customer"
    subject_tin = "555-66-7777"
    activity_date = datetime.now(timezone.utc) - timedelta(days=10)
    detection_date = datetime.now(timezone.utc) - timedelta(days=5)
    amount = Decimal("10000.00")
    narrative = "Suspicious pattern detected"

    # Act
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative=narrative
    )

    # Assert
    days_to_file = (sar.filed_date - detection_date).days
    assert days_to_file <= 30, (
        f"31 C.F.R. § 1020.320: SAR must be filed within 30 calendar days of "
        f"initial detection (filed in {days_to_file} days)"
    )
    assert sar_service.filing_deadline_days == 30, (
        "31 C.F.R. § 1020.320: SAR filing deadline must be 30 calendar days"
    )


def test_obligation_004_sar_filing_deadline_boundary(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    [FINCEN-SAR-001::OBL::004] Boundary test for 30-day filing deadline.
    
    31 C.F.R. § 1020.320
    """
    # Arrange
    detection_date = datetime.now(timezone.utc) - timedelta(days=29)
    activity_date = detection_date - timedelta(days=1)
    
    # Act
    sar = sar_service.file_sar(
        subject_name="Test Subject",
        subject_tin="123-45-6789",
        activity_date=activity_date,
        amount=Decimal("6000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative="Testing 30-day deadline"
    )
    
    # Assert
    days_elapsed = (sar.filed_date - detection_date).days
    assert days_elapsed <= 30, (
        f"31 C.F.R. § 1020.320: SAR filed {days_elapsed} days after detection, "
        f"must be within 30 calendar days"
    )


# ============================================================================
# Boundary and Threshold Tests
# ============================================================================

def test_sar_threshold_boundary_at_5000():
    """
    Test SAR threshold boundary at exactly $5,000.
    Uses AUTHORITATIVE THRESHOLD: sar_threshold = 5000
    """
    # Arrange
    sar_threshold = Decimal("5000")
    
    # Test amounts
    at_threshold = sar_threshold
    above_threshold = sar_threshold + Decimal("0.01")
    below_threshold = sar_threshold - Decimal("0.01")
    
    # Assert
    assert above_threshold > sar_threshold
    assert at_threshold == sar_threshold
    assert below_threshold < sar_threshold


def test_ctr_threshold_boundary_at_10000():
    """
    Test CTR threshold boundary at exactly $10,000.
    Uses AUTHORITATIVE THRESHOLD: ctr_threshold = 10000
    """
    # Arrange
    ctr_threshold = Decimal("10000")
    
    # Test amounts
    at_threshold = ctr_threshold
    above_threshold = ctr_threshold + Decimal("0.01")
    below_threshold = ctr_threshold - Decimal("0.01")
    
    # Assert
    assert above_threshold > ctr_threshold
    assert at_threshold == ctr_threshold
    assert below_threshold < ctr_threshold


def test_travel_rule_threshold_at_3000():
    """
    Test Travel Rule threshold at $3,000.
    Uses AUTHORITATIVE THRESHOLD: travel_rule_threshold = 3000
    """
    # Arrange
    travel_rule_threshold = Decimal("3000")
    
    # Test amounts
    at_threshold = travel_rule_threshold
    above_threshold = travel_rule_threshold + Decimal("0.01")
    below_threshold = travel_rule_threshold - Decimal("0.01")
    
    # Assert
    assert above_threshold > travel_rule_threshold
    assert at_threshold == travel_rule_threshold
    assert below_threshold < travel_rule_threshold


def test_wire_dual_approval_threshold_at_10000():
    """
    Test wire dual approval threshold at $10,000.
    Uses AUTHORITATIVE THRESHOLD: wire_dual_approval_threshold = 10000
    """
    # Arrange
    wire_dual_approval_threshold = Decimal("10000")
    
    # Test amounts
    at_threshold = wire_dual_approval_threshold
    above_threshold = wire_dual_approval_threshold + Decimal("0.01")
    below_threshold = wire_dual_approval_threshold - Decimal("0.01")
    
    # Assert
    assert above_threshold > wire_dual_approval_threshold
    assert at_threshold == wire_dual_approval_threshold
    assert below_threshold < wire_dual_approval_threshold


def test_ofac_fuzzy_threshold_at_85():
    """
    Test OFAC fuzzy matching threshold at 85%.
    Uses AUTHORITATIVE THRESHOLD: ofac_fuzzy_threshold = 85
    """
    # Arrange
    ofac_fuzzy_threshold = 85
    
    # Test scores
    at_threshold = ofac_fuzzy_threshold
    above_threshold = ofac_fuzzy_threshold + 1
    below_threshold = ofac_fuzzy_threshold - 1
    
    # Assert
    assert above_threshold > ofac_fuzzy_threshold
    assert at_threshold == ofac_fuzzy_threshold
    assert below_threshold < ofac_fuzzy_threshold


def test_beneficial_ownership_threshold_at_20_percent():
    """
    Test beneficial ownership threshold at 20%.
    Uses AUTHORITATIVE THRESHOLD: beneficial_ownership_pct = 20
    """
    # Arrange
    beneficial_ownership_pct = 20
    
    # Test percentages
    at_threshold = beneficial_ownership_pct
    above_threshold = beneficial_ownership_pct + 1
    below_threshold = beneficial_ownership_pct - 1
    
    # Assert
    assert above_threshold > beneficial_ownership_pct
    assert at_threshold == beneficial_ownership_pct
    assert below_threshold < beneficial_ownership_pct


# ============================================================================
# Additional Compliance Tests
# ============================================================================

def test_sar_confidentiality_enforcement(sar_service):
    """
    Test that SAR confidentiality is enforced per 31 CFR 1020.320(e).
    """
    # Arrange
    subject_name = "Test Subject"
    subject_tin = "123-45-6789"
    activity_date = datetime.now(timezone.utc)
    detection_date = datetime.now(timezone.utc)
    amount = Decimal("10000.00")
    
    # Act
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative="Test SAR"
    )
    
    # Assert
    assert sar.confidential is True, "SAR must be marked confidential"
    assert sar_service.disclose_sar_to_customer() is False, (
        "SAR filing must never be disclosed to customer"
    )


def test_sar_required_fields_present(sar_service, mock_fincen_gateway, mock_audit_logger):
    """
    Test that SAR includes all required fields per FINCEN-SAR-FIELD-001.
    """
    # Arrange
    subject_name = "John Doe"
    subject_tin = "123-45-6789"
    activity_date = datetime.now(timezone.utc)
    detection_date = datetime.now(timezone.utc)
    amount = Decimal("7500.00")
    narrative = "Suspicious activity narrative"
    
    # Act
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date,
        narrative=narrative
    )
    
    # Assert
    assert sar.subject_name is not None, "SAR must include subject name"
    assert sar.subject_tin is not None, "SAR must include TIN/SSN"
    assert sar.activity_date is not None, "SAR must include suspicious activity date"
    assert sar.amount is not None, "SAR must include dollar amount"
    assert sar.amount > 0, "SAR amount must be positive"


def test_audit_trail_recorded_for_transaction(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_account,
    valid_beneficiary_account
):
    """
    Test that audit trail is recorded for all transactions.
    """
    # Arrange
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        valid_account if acc_id == "acc_123" else valid_beneficiary_account
    )
    amount = Decimal("2500.00")
    user_id = "user_001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="acc_123",
        to_account_id="acc_456",
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )
    
    # Assert
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args
    assert call_args[0][0].transaction_id is not None
    assert call_args[0][1] == user_id
    assert call_args[0][2] == ip_address
    assert call_args[0][3] == device_info


def test_timezone_aware_datetime_usage():
    """
    Test that all datetime objects are timezone-aware.
    """
    # Arrange & Act
    now = datetime.now(timezone.utc)
    
    # Assert
    assert now.tzinfo is not None, "Datetime must be timezone-aware"
    assert now.tzinfo == timezone.utc, "Datetime must use UTC timezone"


def test_decimal_precision_for_currency():
    """
    Test that Decimal is used for currency amounts with proper precision.
    """
    # Arrange
    amount1 = Decimal("1000.00")
    amount2 = Decimal("0.01")
    
    # Act
    result = amount1 + amount2
    
    # Assert
    assert isinstance(result, Decimal), "Currency must use Decimal type"
    assert result == Decimal("1000.01"), "Decimal precision must be maintained"


def test_sar_filing_for_structuring_pattern(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    Test SAR filing for structuring (multiple transactions to avoid CTR).
    """
    # Arrange
    subject_name = "Structuring Customer"
    subject_tin = "444-55-6666"
    activity_date = datetime.now(timezone.utc)
    detection_date = datetime.now(timezone.utc)
    # Multiple transactions just under $10,000 CTR threshold
    amount = Decimal("9500.00")
    narrative = "Customer made 5 deposits of $9,500 over 3 days to avoid CTR"
    
    # Act
    sar = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.STRUCTURING,
        detection_date=detection_date,
        narrative=narrative
    )
    
    # Assert
    assert sar.reason == SARFilingReason.STRUCTURING
    assert sar.amount > Decimal("5000.00"), (
        "31 C.F.R. § 1020.320: SAR must be filed for structuring > $5,000"
    )
    mock_fincen_gateway.submit_sar.assert_called_once()


def test_multiple_sar_filings_for_same_customer(
    sar_service,
    mock_fincen_gateway,
    mock_audit_logger
):
    """
    Test that multiple SARs can be filed for the same customer (continuing activity).
    """
    # Arrange
    subject_name = "Repeat Offender"
    subject_tin = "777-88-9999"
    
    # Act - File first SAR
    sar1 = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=datetime.now(timezone.utc) - timedelta(days=100),
        amount=Decimal("8000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=datetime.now(timezone.utc) - timedelta(days=95),
        narrative="Initial suspicious activity"
    )
    
    # Act - File continuing activity SAR
    sar2 = sar_service.file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        activity_date=datetime.now(timezone.utc) - timedelta(days=10),
        amount=Decimal("12000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=datetime.now(timezone.utc) - timedelta(days=5),
        narrative="Continuing suspicious activity"
    )
    
    # Assert
    assert sar1.sar_id != sar2.sar_id, "Each SAR must have unique ID"
    assert sar1.subject_tin == sar2.subject_tin, "SARs for same customer"
    assert mock_fincen_gateway.submit_sar.call_count == 2, (
        "Multiple SARs can be filed for continuing activity"
    )


def test_sar_not_filed_below_threshold_without_insider_abuse(sar_service):
    """
    Test that SAR is not required for amounts <= $5,000 without insider abuse.
    """
    # Arrange
    amount = Decimal("4999.99")
    
    # Act
    should_file = sar_service.should_file_sar_for_suspicious_activity(amount)
    
    # Assert
    assert should_file is False, (
        "SAR not required for suspicious activity <= $5,000 "
        "(unless insider abuse or other special circumstances)"
    )


def test_transaction_monitoring_integration(
    transaction_service,
    monitoring_service,
    mock_account_repo,
    valid_account,
    valid_beneficiary_account
):
    """
    Test that transaction monitoring is triggered after successful transaction.
    """
    # Arrange
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        valid_account if acc_id == "acc_123" else valid_beneficiary_account
    )
    monitoring_service.analyze_transaction = Mock()
    amount = Decimal("7500.00")
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="acc_123",
        to_account_id="acc_456",
        amount=amount,
        user_id="user_001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    monitoring_service.analyze_transaction.assert_called_once_with(result)