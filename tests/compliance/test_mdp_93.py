import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
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


class SARStatus(Enum):
    FILED = "FILED"
    PENDING = "PENDING"
    NOT_REQUIRED = "NOT_REQUIRED"


@dataclass
class Account:
    account_id: str
    balance: Decimal
    routing_number: str
    account_number: str
    owner_id: str


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None


@dataclass
class SARFiling:
    sar_id: str
    subject_name: str
    subject_tin: Optional[str]
    activity_date: datetime
    amount: Decimal
    detection_date: datetime
    filing_date: Optional[datetime]
    status: SARStatus
    is_insider_abuse: bool
    description: str


@dataclass
class AuditRecord:
    audit_id: str
    timestamp: datetime
    user_id: str
    action: str
    details: Dict[str, Any]
    ip_address: str
    device_info: str


# ============================================================================
# Authoritative Thresholds (source of truth)
# ============================================================================

CTR_THRESHOLD = Decimal("10000")
SAR_THRESHOLD = Decimal("5000")
TRAVEL_RULE_THRESHOLD = Decimal("3000")
WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
OFAC_FUZZY_THRESHOLD = 85
BENEFICIAL_OWNERSHIP_PCT = 20
SAR_FILING_DEADLINE_DAYS = 30
SAR_INSIDER_THRESHOLD = Decimal("0")


# ============================================================================
# Service Interfaces
# ============================================================================

class TransactionService:
    def __init__(self, account_repo, audit_logger, sar_service, ofac_service):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.sar_service = sar_service
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
        timestamp = datetime.now(timezone.utc)
        
        # Validate amount
        if amount <= 0:
            rejection_reason = "Amount must be greater than 0" if amount == 0 else "Invalid amount"
            txn = Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.audit_logger.log(user_id, "TRANSACTION_REJECTED", {
                "reason": rejection_reason,
                "amount": str(amount)
            }, ip_address, device_info)
            return txn

        # Validate accounts
        from_account = self.account_repo.get_account(from_account_id)
        to_account = self.account_repo.get_account(to_account_id)
        
        if not from_account or not to_account:
            txn = Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account"
            )
            self.audit_logger.log(user_id, "TRANSACTION_REJECTED", {
                "reason": "Invalid beneficiary account"
            }, ip_address, device_info)
            return txn

        # Check balance
        if from_account.balance < amount:
            txn = Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance"
            )
            self.audit_logger.log(user_id, "TRANSACTION_REJECTED", {
                "reason": "Insufficient balance",
                "balance": str(from_account.balance),
                "amount": str(amount)
            }, ip_address, device_info)
            return txn

        # Execute transaction
        self.account_repo.debit(from_account_id, amount)
        self.account_repo.credit(to_account_id, amount)
        
        txn = Transaction(
            transaction_id=f"TXN-{timestamp.timestamp()}",
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS
        )
        
        self.audit_logger.log(user_id, "TRANSACTION_SUCCESS", {
            "transaction_id": txn.transaction_id,
            "amount": str(amount),
            "from": from_account_id,
            "to": to_account_id
        }, ip_address, device_info)
        
        return txn


class SARService:
    def __init__(self, sar_repo, notification_service):
        self.sar_repo = sar_repo
        self.notification_service = notification_service

    def evaluate_and_file_sar(
        self,
        subject_name: str,
        subject_tin: Optional[str],
        amount: Decimal,
        activity_date: datetime,
        detection_date: datetime,
        is_suspicious: bool,
        is_insider_abuse: bool,
        description: str
    ) -> Optional[SARFiling]:
        # OBL::002 - Insider abuse: file regardless of amount
        if is_insider_abuse:
            return self._file_sar(
                subject_name, subject_tin, amount, activity_date,
                detection_date, is_insider_abuse, description
            )
        
        # OBL::001 - Suspicious activity >= $5,000
        if is_suspicious and amount >= SAR_THRESHOLD:
            return self._file_sar(
                subject_name, subject_tin, amount, activity_date,
                detection_date, is_insider_abuse, description
            )
        
        # OBL::003 - Transactions >= $25,000 even without identified suspect
        if amount >= Decimal("25000"):
            return self._file_sar(
                subject_name, subject_tin, amount, activity_date,
                detection_date, is_insider_abuse, description
            )
        
        return None

    def _file_sar(
        self,
        subject_name: str,
        subject_tin: Optional[str],
        amount: Decimal,
        activity_date: datetime,
        detection_date: datetime,
        is_insider_abuse: bool,
        description: str
    ) -> SARFiling:
        filing_date = detection_date + timedelta(days=SAR_FILING_DEADLINE_DAYS)
        
        sar = SARFiling(
            sar_id=f"SAR-{detection_date.timestamp()}",
            subject_name=subject_name,
            subject_tin=subject_tin,
            activity_date=activity_date,
            amount=amount,
            detection_date=detection_date,
            filing_date=filing_date,
            status=SARStatus.FILED,
            is_insider_abuse=is_insider_abuse,
            description=description
        )
        
        self.sar_repo.save(sar)
        self.notification_service.notify_fincen(sar)
        
        # OBL - No tipping off
        # Do NOT notify the subject
        
        return sar

    def check_sar_disclosure_allowed(self, customer_id: str) -> bool:
        # Per 31 C.F.R. § 1020.320 - SAR confidentiality
        # Never disclose SAR filing to customer
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
    logger.log = Mock()
    return logger


@pytest.fixture
def mock_sar_repo():
    repo = Mock()
    repo.save = Mock()
    repo.get_by_customer = Mock(return_value=[])
    return repo


@pytest.fixture
def mock_notification_service():
    service = Mock()
    service.notify_fincen = Mock()
    service.notify_customer = Mock()
    return service


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def transaction_service(mock_account_repo, mock_audit_logger, mock_ofac_service):
    sar_service = SARService(Mock(), Mock())
    return TransactionService(
        mock_account_repo,
        mock_audit_logger,
        sar_service,
        mock_ofac_service
    )


@pytest.fixture
def sar_service(mock_sar_repo, mock_notification_service):
    return SARService(mock_sar_repo, mock_notification_service)


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC-001",
        balance=Decimal("10000.00"),
        routing_number="021000021",
        account_number="1234567890",
        owner_id="USER-001"
    )


@pytest.fixture
def valid_beneficiary_account():
    return Account(
        account_id="ACC-002",
        balance=Decimal("5000.00"),
        routing_number="021000021",
        account_number="0987654321",
        owner_id="USER-002"
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
        valid_account if acc_id == "ACC-001" else valid_beneficiary_account
    )
    amount = Decimal("1000.00")
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.amount == amount
    mock_account_repo.debit.assert_called_once_with("ACC-001", amount)
    mock_account_repo.credit.assert_called_once_with("ACC-002", amount)
    mock_audit_logger.log.assert_called_once()
    audit_call = mock_audit_logger.log.call_args
    assert audit_call[0][1] == "TRANSACTION_SUCCESS"


def test_sar_suspicious_activity_above_threshold(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    
    Tests FINCEN-SAR-001::OBL::001 - SAR for suspicious activity >= $5,000
    """
    # Arrange
    amount = Decimal("6000.00")
    detection_date = datetime.now(timezone.utc)
    activity_date = detection_date - timedelta(days=1)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="John Doe",
        subject_tin="123-45-6789",
        amount=amount,
        activity_date=activity_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Structuring pattern detected"
    )
    
    # Assert - 31 C.F.R. § 1020.320 compliance
    assert sar is not None, (
        "SAR must be filed for suspicious activity >= $5,000 per 31 C.F.R. § 1020.320"
    )
    assert sar.amount == amount
    assert sar.status == SARStatus.FILED
    assert sar.filing_date <= detection_date + timedelta(days=30), (
        "SAR must be filed within 30 days per 31 C.F.R. § 1020.320"
    )
    mock_sar_repo.save.assert_called_once()
    mock_notification_service.notify_fincen.assert_called_once_with(sar)
    # Verify subject NOT notified (no tipping off)
    mock_notification_service.notify_customer.assert_not_called()


def test_sar_insider_abuse_any_amount(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    
    Tests FINCEN-SAR-001::OBL::002 - Insider abuse SAR regardless of amount
    """
    # Arrange
    amount = Decimal("100.00")  # Below normal SAR threshold
    detection_date = datetime.now(timezone.utc)
    activity_date = detection_date
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Jane Employee",
        subject_tin="987-65-4321",
        amount=amount,
        activity_date=activity_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=True,
        description="Employee unauthorized account access"
    )
    
    # Assert - 31 C.F.R. § 1020.320 compliance
    assert sar is not None, (
        "SAR must be filed for insider abuse regardless of amount per 31 C.F.R. § 1020.320"
    )
    assert sar.amount == amount
    assert sar.is_insider_abuse is True
    assert sar.status == SARStatus.FILED
    mock_sar_repo.save.assert_called_once()


def test_sar_no_tipping_off(sar_service):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    
    Tests SAR confidentiality per 31 C.F.R. § 1020.320
    """
    # Arrange
    customer_id = "CUST-001"
    
    # Act
    disclosure_allowed = sar_service.check_sar_disclosure_allowed(customer_id)
    
    # Assert - 31 C.F.R. § 1020.320 compliance
    assert disclosure_allowed is False, (
        "SAR filing must never be disclosed to customer per 31 C.F.R. § 1020.320"
    )


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
    amount = Decimal("0")
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
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
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
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
        account_id="ACC-001",
        balance=Decimal("1000.00"),
        routing_number="021000021",
        account_number="1234567890",
        owner_id="USER-001"
    )
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        low_balance_account if acc_id == "ACC-001" else valid_beneficiary_account
    )
    amount = Decimal("5000.00")
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
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
        valid_account if acc_id == "ACC-001" else None
    )
    amount = Decimal("1000.00")
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="INVALID-ACC",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"
    mock_account_repo.debit.assert_not_called()
    mock_account_repo.credit.assert_not_called()


# ============================================================================
# Explicit MUST-TEST Obligation Tests
# ============================================================================

def test_obl_001_sar_threshold_exact_5000(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Explicit test for FINCEN-SAR-001::OBL::001
    SAR must be filed for suspicious activity at exactly $5,000 threshold
    """
    # Arrange
    amount = SAR_THRESHOLD  # Exactly $5,000
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Test Subject",
        subject_tin="111-22-3333",
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Suspicious pattern at threshold"
    )
    
    # Assert
    assert sar is not None, (
        f"SAR must be filed for suspicious activity at ${amount} threshold "
        f"per 31 C.F.R. § 1020.320"
    )
    assert sar.amount == SAR_THRESHOLD


def test_obl_001_sar_below_threshold_not_filed(
    sar_service,
    mock_sar_repo
):
    """
    Explicit test for FINCEN-SAR-001::OBL::001
    SAR should NOT be filed for suspicious activity below $5,000 (non-insider)
    """
    # Arrange
    amount = SAR_THRESHOLD - Decimal("0.01")  # $4,999.99
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Test Subject",
        subject_tin="111-22-3333",
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Suspicious pattern below threshold"
    )
    
    # Assert
    assert sar is None, (
        f"SAR should not be filed for suspicious activity below ${SAR_THRESHOLD} "
        f"per 31 C.F.R. § 1020.320"
    )
    mock_sar_repo.save.assert_not_called()


def test_obl_002_insider_abuse_zero_amount(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Explicit test for FINCEN-SAR-001::OBL::002
    SAR must be filed for insider abuse even at $0 amount
    """
    # Arrange
    amount = SAR_INSIDER_THRESHOLD  # $0
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Insider Employee",
        subject_tin="444-55-6666",
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=True,
        description="Insider data breach, no monetary transaction"
    )
    
    # Assert
    assert sar is not None, (
        "SAR must be filed for insider abuse regardless of amount "
        "per 31 C.F.R. § 1020.320"
    )
    assert sar.is_insider_abuse is True
    assert sar.amount == Decimal("0")


def test_obl_003_sar_25000_no_suspect_identified(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Explicit test for FINCEN-SAR-001::OBL::003
    SAR must be filed for transactions >= $25,000 even without identified suspect
    """
    # Arrange
    amount = Decimal("25000.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Unknown",
        subject_tin=None,  # No suspect identified
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=False,  # Not flagged as suspicious
        is_insider_abuse=False,
        description="Large transaction, no suspect identified"
    )
    
    # Assert
    assert sar is not None, (
        "SAR must be filed for transactions >= $25,000 even without identified suspect "
        "per 31 C.F.R. § 1020.320"
    )
    assert sar.amount >= Decimal("25000")
    assert sar.subject_tin is None


def test_obl_003_sar_above_25000_no_suspect(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Explicit test for FINCEN-SAR-001::OBL::003
    SAR must be filed for transactions > $25,000 even without identified suspect
    """
    # Arrange
    amount = Decimal("50000.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Unknown",
        subject_tin=None,
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=False,
        is_insider_abuse=False,
        description="Large wire transfer"
    )
    
    # Assert
    assert sar is not None, (
        "SAR must be filed for transactions >= $25,000 per 31 C.F.R. § 1020.320"
    )


def test_obl_004_sar_filing_deadline_30_days(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Explicit test for FINCEN-SAR-001::OBL::004
    SAR must be filed within 30 calendar days of initial detection
    """
    # Arrange
    amount = Decimal("10000.00")
    detection_date = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    activity_date = detection_date - timedelta(days=2)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Test Subject",
        subject_tin="777-88-9999",
        amount=amount,
        activity_date=activity_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Suspicious activity"
    )
    
    # Assert
    assert sar is not None
    expected_deadline = detection_date + timedelta(days=SAR_FILING_DEADLINE_DAYS)
    assert sar.filing_date <= expected_deadline, (
        f"SAR must be filed within {SAR_FILING_DEADLINE_DAYS} calendar days "
        f"of detection per 31 C.F.R. § 1020.320"
    )
    days_to_file = (sar.filing_date - detection_date).days
    assert days_to_file <= 30, (
        f"SAR filing deadline exceeded: {days_to_file} days > 30 days "
        f"per 31 C.F.R. § 1020.320"
    )


# ============================================================================
# Boundary and Edge Case Tests
# ============================================================================

def test_sar_boundary_4999_99_not_filed(sar_service, mock_sar_repo):
    """
    Boundary test: $4,999.99 (just below SAR threshold) should not trigger SAR
    for non-insider suspicious activity
    """
    # Arrange
    amount = Decimal("4999.99")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Test",
        subject_tin="123-45-6789",
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Below threshold"
    )
    
    # Assert
    assert sar is None
    mock_sar_repo.save.assert_not_called()


def test_sar_boundary_5000_00_filed(sar_service, mock_sar_repo):
    """
    Boundary test: Exactly $5,000.00 should trigger SAR for suspicious activity
    """
    # Arrange
    amount = Decimal("5000.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Test",
        subject_tin="123-45-6789",
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="At threshold"
    )
    
    # Assert
    assert sar is not None, (
        "SAR must be filed at exactly $5,000 threshold per 31 C.F.R. § 1020.320"
    )
    mock_sar_repo.save.assert_called_once()


def test_sar_boundary_5000_01_filed(sar_service, mock_sar_repo):
    """
    Boundary test: $5,000.01 (just above SAR threshold) should trigger SAR
    """
    # Arrange
    amount = Decimal("5000.01")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Test",
        subject_tin="123-45-6789",
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Above threshold"
    )
    
    # Assert
    assert sar is not None
    mock_sar_repo.save.assert_called_once()


def test_sar_boundary_24999_99_not_filed_no_suspect(sar_service, mock_sar_repo):
    """
    Boundary test: $24,999.99 without suspect should not trigger SAR
    """
    # Arrange
    amount = Decimal("24999.99")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Unknown",
        subject_tin=None,
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=False,
        is_insider_abuse=False,
        description="Below $25k threshold"
    )
    
    # Assert
    assert sar is None
    mock_sar_repo.save.assert_not_called()


def test_sar_boundary_25000_00_filed_no_suspect(sar_service, mock_sar_repo):
    """
    Boundary test: Exactly $25,000 without suspect should trigger SAR
    per OBL::003
    """
    # Arrange
    amount = Decimal("25000.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Unknown",
        subject_tin=None,
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=False,
        is_insider_abuse=False,
        description="At $25k threshold"
    )
    
    # Assert
    assert sar is not None, (
        "SAR must be filed at $25,000 threshold even without suspect "
        "per 31 C.F.R. § 1020.320"
    )
    mock_sar_repo.save.assert_called_once()


def test_transaction_boundary_minimum_valid_amount(
    transaction_service,
    mock_account_repo,
    valid_account,
    valid_beneficiary_account
):
    """
    Boundary test: Minimum valid transaction amount ($0.01)
    """
    # Arrange
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        valid_account if acc_id == "ACC-001" else valid_beneficiary_account
    )
    amount = Decimal("0.01")
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.amount == Decimal("0.01")


def test_transaction_exact_balance_transfer(
    transaction_service,
    mock_account_repo,
    valid_beneficiary_account
):
    """
    Boundary test: Transfer exact account balance
    """
    # Arrange
    exact_balance_account = Account(
        account_id="ACC-001",
        balance=Decimal("1000.00"),
        routing_number="021000021",
        account_number="1234567890",
        owner_id="USER-001"
    )
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        exact_balance_account if acc_id == "ACC-001" else valid_beneficiary_account
    )
    amount = Decimal("1000.00")
    
    # Act
    result = transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.amount == amount


def test_sar_includes_required_fields(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Test that SAR includes all required fields per FINCEN-SAR-FIELD-001:
    subject name, TIN/SSN, activity date, and dollar amount
    """
    # Arrange
    amount = Decimal("10000.00")
    detection_date = datetime.now(timezone.utc)
    activity_date = detection_date - timedelta(days=1)
    subject_name = "John Doe"
    subject_tin = "123-45-6789"
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name=subject_name,
        subject_tin=subject_tin,
        amount=amount,
        activity_date=activity_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Test SAR"
    )
    
    # Assert
    assert sar is not None
    assert sar.subject_name == subject_name, "SAR must include subject name"
    assert sar.subject_tin == subject_tin, "SAR must include TIN/SSN"
    assert sar.activity_date == activity_date, "SAR must include activity date"
    assert sar.amount == amount, "SAR must include dollar amount"


def test_audit_trail_includes_required_data(
    transaction_service,
    mock_account_repo,
    mock_audit_logger,
    valid_account,
    valid_beneficiary_account
):
    """
    Test that audit trail includes required data:
    timestamp, user ID, IP address, device info
    """
    # Arrange
    mock_account_repo.get_account.side_effect = lambda acc_id: (
        valid_account if acc_id == "ACC-001" else valid_beneficiary_account
    )
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0 (Windows NT 10.0)"
    
    # Act
    transaction_service.execute_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        amount=Decimal("500.00"),
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )
    
    # Assert
    mock_audit_logger.log.assert_called_once()
    call_args = mock_audit_logger.log.call_args[0]
    assert call_args[0] == user_id, "Audit must include user ID"
    assert call_args[2] == ip_address, "Audit must include IP address"
    assert call_args[3] == device_info, "Audit must include device info"


def test_non_suspicious_activity_below_25k_no_sar(sar_service, mock_sar_repo):
    """
    Negative test: Non-suspicious activity below $25,000 should not trigger SAR
    """
    # Arrange
    amount = Decimal("10000.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Regular Customer",
        subject_tin="111-22-3333",
        amount=amount,
        activity_date=detection_date,
        detection_date=detection_date,
        is_suspicious=False,
        is_insider_abuse=False,
        description="Normal transaction"
    )
    
    # Assert
    assert sar is None
    mock_sar_repo.save.assert_not_called()


def test_sar_filing_preserves_detection_date(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Test that SAR preserves the original detection date for compliance tracking
    """
    # Arrange
    amount = Decimal("7500.00")
    detection_date = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    activity_date = datetime(2024, 1, 14, 15, 45, 0, tzinfo=timezone.utc)
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Test Subject",
        subject_tin="555-66-7777",
        amount=amount,
        activity_date=activity_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description="Suspicious pattern"
    )
    
    # Assert
    assert sar is not None
    assert sar.detection_date == detection_date
    assert sar.activity_date == activity_date


def test_multiple_sar_fields_validation(
    sar_service,
    mock_sar_repo,
    mock_notification_service
):
    """
    Test that SAR captures all required compliance fields correctly
    """
    # Arrange
    amount = Decimal("15000.00")
    detection_date = datetime.now(timezone.utc)
    activity_date = detection_date - timedelta(hours=12)
    description = "Multiple structuring transactions detected"
    
    # Act
    sar = sar_service.evaluate_and_file_sar(
        subject_name="Suspicious Actor",
        subject_tin="999-88-7777",
        amount=amount,
        activity_date=activity_date,
        detection_date=detection_date,
        is_suspicious=True,
        is_insider_abuse=False,
        description=description
    )
    
    # Assert
    assert sar is not None
    assert sar.subject_name == "Suspicious Actor"
    assert sar.subject_tin == "999-88-7777"
    assert sar.amount == amount
    assert sar.activity_date == activity_date
    assert sar.detection_date == detection_date
    assert sar.description == description
    assert sar.status == SARStatus.FILED
    assert sar.is_insider_abuse is False


def test_authoritative_threshold_values():
    """
    Test that authoritative threshold values match the compliance grounding
    """
    assert CTR_THRESHOLD == Decimal("10000"), "CTR threshold must be exactly $10,000"
    assert SAR_THRESHOLD == Decimal("5000"), "SAR threshold must be exactly $5,000"
    assert TRAVEL_RULE_THRESHOLD == Decimal("3000"), "Travel rule threshold must be exactly $3,000"
    assert WIRE_DUAL_APPROVAL_THRESHOLD == Decimal("10000"), "Wire dual approval threshold must be exactly $10,000"
    assert OFAC_FUZZY_THRESHOLD == 85, "OFAC fuzzy match threshold must be exactly 85"
    assert BENEFICIAL_OWNERSHIP_PCT == 20, "Beneficial ownership percentage must be exactly 20"
    assert SAR_FILING_DEADLINE_DAYS == 30, "SAR filing deadline must be exactly 30 days per 31 C.F.R. § 1020.320"
    assert SAR_INSIDER_THRESHOLD == Decimal("0"), "SAR insider threshold must be $0 per 31 C.F.R. § 1020.320"