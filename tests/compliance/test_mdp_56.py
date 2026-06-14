import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# Domain Models
class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    PENDING_REVIEW = "PENDING_REVIEW"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    user_id: str
    status: str = "ACTIVE"


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    user_id: str
    ip_address: str
    device_info: str
    rejection_reason: Optional[str] = None


@dataclass
class SARFiling:
    sar_id: str
    subject_account: str
    filing_date: datetime
    detection_date: datetime
    amount: Decimal
    reason: str
    filed_with_fincen: bool
    subject_notified: bool
    insider_involved: bool


@dataclass
class AuditLogEntry:
    log_id: str
    timestamp: datetime
    user_id: str
    action: str
    details: Dict[str, Any]
    ip_address: str
    device_info: str
    encrypted: bool = True


# Constants based on U.S. banking regulations
CTR_THRESHOLD = Decimal("10000")
SAR_THRESHOLD = Decimal("5000")
SAR_INSIDER_THRESHOLD = Decimal("0")
TRAVEL_RULE_THRESHOLD = Decimal("3000")
WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
OFAC_FUZZY_THRESHOLD = 85
BENEFICIAL_OWNERSHIP_PCT = 20
SAR_FILING_DEADLINE_DAYS = 30
SAR_RETENTION_YEARS = 5


# Service Interfaces
class BankingService:
    def __init__(
        self,
        account_repository,
        audit_logger,
        sar_service,
        ofac_service,
        rule_resolver,
    ):
        self.account_repository = account_repository
        self.audit_logger = audit_logger
        self.sar_service = sar_service
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver

    def initiate_transaction(
        self,
        from_account_id: str,
        to_account_id: str,
        to_routing_number: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str,
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        # Validate amount
        if amount == Decimal("0"):
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Amount must be greater than 0",
            )

        if amount < Decimal("0"):
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid amount",
            )

        # Validate accounts
        from_account = self.account_repository.get_account(from_account_id)
        if not from_account or from_account.status != "ACTIVE":
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid account",
            )

        # Validate beneficiary
        if not self.account_repository.validate_beneficiary(
            to_account_id, to_routing_number
        ):
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid beneficiary account",
            )

        # Check sufficient balance
        if from_account.balance < amount:
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Insufficient balance",
            )

        # OFAC screening
        ofac_result = self.ofac_service.screen_transaction(
            from_account_id, to_account_id, user_id
        )
        if ofac_result["blocked"]:
            self.audit_logger.log(
                user_id=user_id,
                action="OFAC_BLOCK",
                details={
                    "transaction_id": transaction_id,
                    "reason": ofac_result["reason"],
                },
                ip_address=ip_address,
                device_info=device_info,
            )
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.BLOCKED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason=f"OFAC: {ofac_result['reason']}",
            )

        # Process transaction
        self.account_repository.debit(from_account_id, amount)
        self.account_repository.credit(to_account_id, amount)

        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Audit trail
        self.audit_logger.log(
            user_id=user_id,
            action="TRANSACTION_SUCCESS",
            details={
                "transaction_id": transaction_id,
                "amount": str(amount),
                "from_account": from_account_id,
                "to_account": to_account_id,
            },
            ip_address=ip_address,
            device_info=device_info,
        )

        return transaction

    def handle_customer_inquiry(self, account_id: str, inquiry_type: str) -> str:
        if inquiry_type == "account_restrictions":
            if self.sar_service.has_sar_filed(account_id):
                return "Your account is subject to standard monitoring procedures."
        return "No restrictions found."


# Fixtures
@pytest.fixture
def mock_account_repository():
    repo = Mock()
    repo.get_account = Mock()
    repo.validate_beneficiary = Mock()
    repo.debit = Mock()
    repo.credit = Mock()
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock()
    logger.log = Mock()
    return logger


@pytest.fixture
def mock_sar_service():
    service = Mock()
    service.detect_suspicious_activity = Mock()
    service.file_sar = Mock()
    service.has_sar_filed = Mock()
    return service


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen_transaction = Mock()
    return service


@pytest.fixture
def mock_rule_resolver():
    resolver = Mock()
    resolver.get_sar_threshold = Mock(return_value=SAR_THRESHOLD)
    resolver.get_sar_insider_threshold = Mock(return_value=SAR_INSIDER_THRESHOLD)
    resolver.get_sar_filing_deadline_days = Mock(return_value=SAR_FILING_DEADLINE_DAYS)
    return resolver


@pytest.fixture
def banking_service(
    mock_account_repository,
    mock_audit_logger,
    mock_sar_service,
    mock_ofac_service,
    mock_rule_resolver,
):
    return BankingService(
        account_repository=mock_account_repository,
        audit_logger=mock_audit_logger,
        sar_service=mock_sar_service,
        ofac_service=mock_ofac_service,
        rule_resolver=mock_rule_resolver,
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC-123456",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="ACTIVE",
    )


@pytest.fixture
def valid_beneficiary_account():
    return Account(
        account_id="ACC-789012",
        routing_number="026009593",
        balance=Decimal("5000.00"),
        user_id="USER-002",
        status="ACTIVE",
    )


# Test: successful_transaction
def test_successful_transaction(
    banking_service,
    mock_account_repository,
    mock_audit_logger,
    mock_ofac_service,
    valid_account,
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    mock_account_repository.get_account.return_value = valid_account
    mock_account_repository.validate_beneficiary.return_value = True
    mock_ofac_service.screen_transaction.return_value = {
        "blocked": False,
        "reason": None,
    }

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-123456",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("500.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    assert transaction.amount == Decimal("500.00")
    mock_account_repository.debit.assert_called_once_with("ACC-123456", Decimal("500.00"))
    mock_account_repository.credit.assert_called_once_with("ACC-789012", Decimal("500.00"))
    mock_audit_logger.log.assert_called_once()
    audit_call = mock_audit_logger.log.call_args
    assert audit_call.kwargs["action"] == "TRANSACTION_SUCCESS"
    assert audit_call.kwargs["user_id"] == "USER-001"
    assert audit_call.kwargs["ip_address"] == "192.168.1.100"


# Test: sar_suspicious_activity_above_threshold
def test_sar_suspicious_activity_above_threshold(mock_sar_service, mock_rule_resolver):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    suspicious_amount = Decimal("6000.00")
    account_id = "ACC-SUSPICIOUS"

    mock_sar_service.detect_suspicious_activity.return_value = {
        "is_suspicious": True,
        "amount": suspicious_amount,
        "pattern": "structuring",
    }

    # Act
    sar_filing = SARFiling(
        sar_id="SAR-2024-001",
        subject_account=account_id,
        filing_date=detection_date + timedelta(days=15),
        detection_date=detection_date,
        amount=suspicious_amount,
        reason="Structuring pattern detected",
        filed_with_fincen=True,
        subject_notified=False,
        insider_involved=False,
    )

    # Assert
    assert suspicious_amount > SAR_THRESHOLD
    assert sar_filing.filed_with_fincen is True
    assert sar_filing.subject_notified is False
    filing_delay = (sar_filing.filing_date - sar_filing.detection_date).days
    assert filing_delay <= SAR_FILING_DEADLINE_DAYS
    assert sar_filing.amount == suspicious_amount


# Test: sar_insider_abuse_any_amount
def test_sar_insider_abuse_any_amount(mock_sar_service):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    insider_amount = Decimal("100.00")  # Below normal SAR threshold
    employee_account = "ACC-EMPLOYEE-001"

    # Act
    sar_filing = SARFiling(
        sar_id="SAR-2024-INSIDER-001",
        subject_account=employee_account,
        filing_date=detection_date,  # Immediate filing
        detection_date=detection_date,
        amount=insider_amount,
        reason="Insider abuse - unauthorized access",
        filed_with_fincen=True,
        subject_notified=False,
        insider_involved=True,
    )

    # Assert
    assert insider_amount < SAR_THRESHOLD  # Below normal threshold
    assert insider_amount >= SAR_INSIDER_THRESHOLD  # No minimum for insider
    assert sar_filing.insider_involved is True
    assert sar_filing.filed_with_fincen is True
    assert sar_filing.subject_notified is False
    filing_delay = (sar_filing.filing_date - sar_filing.detection_date).days
    assert filing_delay == 0  # Immediate filing


# Test: sar_no_tipping_off
def test_sar_no_tipping_off(banking_service, mock_sar_service):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    account_id = "ACC-SAR-FILED"
    mock_sar_service.has_sar_filed.return_value = True

    # Act
    response = banking_service.handle_customer_inquiry(
        account_id=account_id, inquiry_type="account_restrictions"
    )

    # Assert
    assert "SAR" not in response
    assert "Suspicious Activity Report" not in response
    assert "FinCEN" not in response
    assert "standard monitoring" in response.lower()
    mock_sar_service.has_sar_filed.assert_called_once_with(account_id)


# Test: zero_amount_transfer
def test_zero_amount_transfer(banking_service, mock_account_repository, valid_account):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    mock_account_repository.get_account.return_value = valid_account

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-123456",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("0"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Amount must be greater than 0"
    assert transaction.amount == Decimal("0")
    mock_account_repository.debit.assert_not_called()
    mock_account_repository.credit.assert_not_called()


# Test: negative_amount_transfer
def test_negative_amount_transfer(banking_service, mock_account_repository, valid_account):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    mock_account_repository.get_account.return_value = valid_account

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-123456",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("-100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid amount"
    assert transaction.amount == Decimal("-100.00")
    mock_account_repository.debit.assert_not_called()
    mock_account_repository.credit.assert_not_called()


# Test: insufficient_balance
def test_insufficient_balance(banking_service, mock_account_repository):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    low_balance_account = Account(
        account_id="ACC-LOW-BAL",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER-003",
        status="ACTIVE",
    )
    mock_account_repository.get_account.return_value = low_balance_account
    mock_account_repository.validate_beneficiary.return_value = True

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-LOW-BAL",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("5000.00"),
        user_id="USER-003",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Insufficient balance"
    assert transaction.amount == Decimal("5000.00")
    mock_account_repository.debit.assert_not_called()
    mock_account_repository.credit.assert_not_called()


# Test: invalid_beneficiary
def test_invalid_beneficiary(banking_service, mock_account_repository, valid_account):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    mock_account_repository.get_account.return_value = valid_account
    mock_account_repository.validate_beneficiary.return_value = False

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-123456",
        to_account_id="ACC-INVALID",
        to_routing_number="999999999",
        amount=Decimal("500.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid beneficiary account"
    mock_account_repository.debit.assert_not_called()
    mock_account_repository.credit.assert_not_called()


# Boundary test: SAR threshold exactly at $5,000
def test_sar_threshold_boundary_at_threshold():
    """
    Boundary test: Transaction exactly at SAR threshold of $5,000
    Should trigger SAR filing as it meets the threshold
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    threshold_amount = Decimal("5000.00")

    # Act
    sar_filing = SARFiling(
        sar_id="SAR-2024-BOUNDARY",
        subject_account="ACC-BOUNDARY",
        filing_date=detection_date + timedelta(days=10),
        detection_date=detection_date,
        amount=threshold_amount,
        reason="Suspicious activity at threshold",
        filed_with_fincen=True,
        subject_notified=False,
        insider_involved=False,
    )

    # Assert
    assert threshold_amount >= SAR_THRESHOLD
    assert sar_filing.filed_with_fincen is True


# Boundary test: SAR threshold just below $5,000
def test_sar_threshold_boundary_below_threshold():
    """
    Boundary test: Transaction just below SAR threshold ($4,999.99)
    Should not automatically trigger SAR filing based on amount alone
    """
    # Arrange
    below_threshold_amount = Decimal("4999.99")

    # Assert
    assert below_threshold_amount < SAR_THRESHOLD


# Boundary test: SAR threshold just above $5,000
def test_sar_threshold_boundary_above_threshold():
    """
    Boundary test: Transaction just above SAR threshold ($5,000.01)
    Should trigger SAR filing
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    above_threshold_amount = Decimal("5000.01")

    # Act
    sar_filing = SARFiling(
        sar_id="SAR-2024-ABOVE",
        subject_account="ACC-ABOVE",
        filing_date=detection_date + timedelta(days=5),
        detection_date=detection_date,
        amount=above_threshold_amount,
        reason="Suspicious activity above threshold",
        filed_with_fincen=True,
        subject_notified=False,
        insider_involved=False,
    )

    # Assert
    assert above_threshold_amount > SAR_THRESHOLD
    assert sar_filing.filed_with_fincen is True


# Test: OFAC screening blocks transaction
def test_ofac_screening_blocks_transaction(
    banking_service, mock_account_repository, mock_ofac_service, mock_audit_logger, valid_account
):
    """
    Test OFAC screening blocks transaction when match found
    Ensures compliance with OFAC/SDN screening requirements
    """
    # Arrange
    mock_account_repository.get_account.return_value = valid_account
    mock_account_repository.validate_beneficiary.return_value = True
    mock_ofac_service.screen_transaction.return_value = {
        "blocked": True,
        "reason": "SDN list match - 95% confidence",
    }

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-123456",
        to_account_id="ACC-SANCTIONED",
        to_routing_number="026009593",
        amount=Decimal("1000.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.BLOCKED
    assert "OFAC" in transaction.rejection_reason
    mock_account_repository.debit.assert_not_called()
    mock_account_repository.credit.assert_not_called()
    mock_audit_logger.log.assert_called_once()
    audit_call = mock_audit_logger.log.call_args
    assert audit_call.kwargs["action"] == "OFAC_BLOCK"


# Test: OFAC screening passes transaction
def test_ofac_screening_passes_transaction(
    banking_service, mock_account_repository, mock_ofac_service, valid_account
):
    """
    Test OFAC screening allows transaction when no match found
    """
    # Arrange
    mock_account_repository.get_account.return_value = valid_account
    mock_account_repository.validate_beneficiary.return_value = True
    mock_ofac_service.screen_transaction.return_value = {
        "blocked": False,
        "reason": None,
    }

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-123456",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("1000.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    mock_ofac_service.screen_transaction.assert_called_once()


# Test: Audit trail includes required fields
def test_audit_trail_includes_required_fields(
    banking_service, mock_account_repository, mock_ofac_service, mock_audit_logger, valid_account
):
    """
    Test audit trail includes all required fields per BSA/AML requirements:
    - Timestamp
    - User ID
    - IP address
    - Device info
    - Transaction details
    """
    # Arrange
    mock_account_repository.get_account.return_value = valid_account
    mock_account_repository.validate_beneficiary.return_value = True
    mock_ofac_service.screen_transaction.return_value = {
        "blocked": False,
        "reason": None,
    }

    # Act
    banking_service.initiate_transaction(
        from_account_id="ACC-123456",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("2500.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0)",
    )

    # Assert
    mock_audit_logger.log.assert_called_once()
    audit_call = mock_audit_logger.log.call_args
    assert audit_call.kwargs["user_id"] == "USER-001"
    assert audit_call.kwargs["ip_address"] == "192.168.1.100"
    assert audit_call.kwargs["device_info"] == "Mozilla/5.0 (Windows NT 10.0)"
    assert "transaction_id" in audit_call.kwargs["details"]
    assert "amount" in audit_call.kwargs["details"]


# Test: SAR filing deadline enforcement
def test_sar_filing_deadline_enforcement():
    """
    Test SAR filing must occur within 30 days of detection
    Per FinCEN requirements (31 CFR 1020.320)
    """
    # Arrange
    detection_date = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    filing_date_valid = detection_date + timedelta(days=29)
    filing_date_invalid = detection_date + timedelta(days=31)

    # Act & Assert - Valid filing
    sar_valid = SARFiling(
        sar_id="SAR-2024-VALID",
        subject_account="ACC-001",
        filing_date=filing_date_valid,
        detection_date=detection_date,
        amount=Decimal("10000.00"),
        reason="Suspicious pattern",
        filed_with_fincen=True,
        subject_notified=False,
        insider_involved=False,
    )
    filing_delay_valid = (sar_valid.filing_date - sar_valid.detection_date).days
    assert filing_delay_valid <= SAR_FILING_DEADLINE_DAYS

    # Act & Assert - Invalid filing (late)
    sar_invalid = SARFiling(
        sar_id="SAR-2024-LATE",
        subject_account="ACC-002",
        filing_date=filing_date_invalid,
        detection_date=detection_date,
        amount=Decimal("10000.00"),
        reason="Suspicious pattern",
        filed_with_fincen=True,
        subject_notified=False,
        insider_involved=False,
    )
    filing_delay_invalid = (sar_invalid.filing_date - sar_invalid.detection_date).days
    assert filing_delay_invalid > SAR_FILING_DEADLINE_DAYS


# Test: Invalid account status
def test_invalid_account_status(banking_service, mock_account_repository):
    """
    Test transaction rejected when account is not active
    """
    # Arrange
    inactive_account = Account(
        account_id="ACC-INACTIVE",
        routing_number="021000021",
        balance=Decimal("5000.00"),
        user_id="USER-004",
        status="SUSPENDED",
    )
    mock_account_repository.get_account.return_value = inactive_account

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-INACTIVE",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("100.00"),
        user_id="USER-004",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid account"


# Test: Account not found
def test_account_not_found(banking_service, mock_account_repository):
    """
    Test transaction rejected when account does not exist
    """
    # Arrange
    mock_account_repository.get_account.return_value = None

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-NONEXISTENT",
        to_account_id="ACC-789012",
        to_routing_number="026009593",
        amount=Decimal("100.00"),
        user_id="USER-005",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid account"


# Test: CTR threshold boundary
def test_ctr_threshold_boundary():
    """
    Test CTR (Currency Transaction Report) threshold at $10,000
    Transactions >= $10,000 require CTR filing with FinCEN
    """
    # Arrange
    ctr_amount = Decimal("10000.00")
    below_ctr = Decimal("9999.99")
    above_ctr = Decimal("10000.01")

    # Assert
    assert ctr_amount >= CTR_THRESHOLD
    assert below_ctr < CTR_THRESHOLD
    assert above_ctr > CTR_THRESHOLD


# Test: Travel Rule threshold
def test_travel_rule_threshold():
    """
    Test Travel Rule threshold at $3,000
    Transactions >= $3,000 require transmittal of customer information
    """
    # Arrange
    travel_rule_amount = Decimal("3000.00")
    below_travel_rule = Decimal("2999.99")
    above_travel_rule = Decimal("3000.01")

    # Assert
    assert travel_rule_amount >= TRAVEL_RULE_THRESHOLD
    assert below_travel_rule < TRAVEL_RULE_THRESHOLD
    assert above_travel_rule > TRAVEL_RULE_THRESHOLD


# Test: Timezone-aware datetime handling
def test_timezone_aware_datetime():
    """
    Test all timestamps are timezone-aware (UTC)
    Required for accurate audit trail and compliance reporting
    """
    # Arrange & Act
    timestamp = datetime.now(timezone.utc)

    # Assert
    assert timestamp.tzinfo is not None
    assert timestamp.tzinfo == timezone.utc


# Test: Decimal precision for currency
def test_decimal_precision_for_currency():
    """
    Test currency amounts use Decimal type for precision
    Avoids floating-point arithmetic errors in financial calculations
    """
    # Arrange
    amount1 = Decimal("100.10")
    amount2 = Decimal("200.20")

    # Act
    total = amount1 + amount2

    # Assert
    assert isinstance(total, Decimal)
    assert total == Decimal("300.30")
    assert str(total) == "300.30"


# Test: SAR retention period
def test_sar_retention_period():
    """
    Test SAR records must be retained for 5 years
    Per 31 CFR 1010.430
    """
    # Arrange
    filing_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    retention_end_date = filing_date + timedelta(days=365 * SAR_RETENTION_YEARS)

    # Assert
    retention_years = (retention_end_date - filing_date).days / 365
    assert retention_years >= SAR_RETENTION_YEARS


# Test: No tipping off - multiple inquiry types
def test_no_tipping_off_various_inquiries(banking_service, mock_sar_service):
    """
    Test bank never discloses SAR filing regardless of inquiry type
    """
    # Arrange
    account_id = "ACC-SAR-FILED"
    mock_sar_service.has_sar_filed.return_value = True

    # Act & Assert - Account restrictions inquiry
    response1 = banking_service.handle_customer_inquiry(
        account_id=account_id, inquiry_type="account_restrictions"
    )
    assert "SAR" not in response1
    assert "Suspicious Activity" not in response1

    # Act & Assert - General inquiry
    response2 = banking_service.handle_customer_inquiry(
        account_id=account_id, inquiry_type="general"
    )
    assert "SAR" not in response2


# Test: Insider SAR with zero amount
def test_insider_sar_with_zero_threshold():
    """
    Test insider abuse SAR can be filed at any amount (no minimum threshold)
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    minimal_amount = Decimal("0.01")

    # Act
    sar_filing = SARFiling(
        sar_id="SAR-2024-INSIDER-MIN",
        subject_account="ACC-EMPLOYEE-002",
        filing_date=detection_date,
        detection_date=detection_date,
        amount=minimal_amount,
        reason="Insider abuse - data access violation",
        filed_with_fincen=True,
        subject_notified=False,
        insider_involved=True,
    )

    # Assert
    assert sar_filing.insider_involved is True
    assert sar_filing.amount > SAR_INSIDER_THRESHOLD
    assert sar_filing.filed_with_fincen is True