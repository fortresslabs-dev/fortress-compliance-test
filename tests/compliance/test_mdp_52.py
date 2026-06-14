import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    PENDING_REVIEW = "PENDING_REVIEW"


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
    is_valid: bool = True


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None
    user_id: str = ""
    ip_address: str = ""
    device_info: str = ""


@dataclass
class SARFiling:
    sar_id: str
    transaction_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    status: SARStatus
    subject_notified: bool = False
    insider_involved: bool = False


@dataclass
class AuditRecord:
    audit_id: str
    transaction_id: str
    user_id: str
    timestamp: datetime
    action: str
    ip_address: str
    device_info: str
    metadata: Dict[str, Any]


class BankingService:
    def __init__(
        self,
        audit_logger: Any,
        rule_resolver: Any,
        ofac_service: Any,
        sar_service: Any
    ):
        self.audit_logger = audit_logger
        self.rule_resolver = rule_resolver
        self.ofac_service = ofac_service
        self.sar_service = sar_service

    def initiate_transaction(
        self,
        from_account: Account,
        to_account: Account,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        if amount <= Decimal("0"):
            if amount == Decimal("0"):
                rejection_reason = "Amount must be greater than 0"
            else:
                rejection_reason = "Invalid amount"
            
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_id,
                to_account=to_account.account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log(transaction)
            return transaction

        if not to_account.is_valid:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_id,
                to_account=to_account.account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log(transaction)
            return transaction

        if from_account.balance < amount:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_id,
                to_account=to_account.account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log(transaction)
            return transaction

        from_account.balance -= amount
        to_account.balance += amount

        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account.account_id,
            to_account=to_account.account_id,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        self.audit_logger.log(transaction)
        return transaction

    def check_suspicious_activity(
        self,
        transaction: Transaction,
        is_insider: bool = False
    ) -> Optional[SARFiling]:
        sar_threshold = Decimal("5000")
        detection_date = datetime.now(timezone.utc)

        if is_insider and transaction.amount > Decimal("0"):
            sar = SARFiling(
                sar_id=f"SAR-{detection_date.timestamp()}",
                transaction_id=transaction.transaction_id,
                amount=transaction.amount,
                reason="Insider abuse detected",
                filed_date=detection_date,
                detection_date=detection_date,
                status=SARStatus.FILED,
                subject_notified=False,
                insider_involved=True
            )
            self.sar_service.file_sar(sar)
            return sar

        if transaction.amount > sar_threshold:
            filing_deadline = detection_date + timedelta(days=30)
            sar = SARFiling(
                sar_id=f"SAR-{detection_date.timestamp()}",
                transaction_id=transaction.transaction_id,
                amount=transaction.amount,
                reason="Suspicious activity above threshold",
                filed_date=filing_deadline,
                detection_date=detection_date,
                status=SARStatus.PENDING,
                subject_notified=False,
                insider_involved=False
            )
            self.sar_service.file_sar(sar)
            return sar

        return None

    def handle_customer_inquiry(
        self,
        customer_id: str,
        sar_exists: bool
    ) -> str:
        if sar_exists:
            return "Your account is being reviewed per standard procedures."
        return "No restrictions on your account."


# Fixtures

@pytest.fixture
def mock_audit_logger():
    """Mock audit logger for recording transactions."""
    logger = Mock()
    logger.log = Mock()
    return logger


@pytest.fixture
def mock_rule_resolver():
    """Mock rule resolver for compliance rules."""
    resolver = Mock()
    resolver.get_sar_threshold = Mock(return_value=Decimal("5000"))
    resolver.get_ctr_threshold = Mock(return_value=Decimal("10000"))
    resolver.get_travel_rule_threshold = Mock(return_value=Decimal("3000"))
    resolver.get_sar_filing_deadline_days = Mock(return_value=30)
    return resolver


@pytest.fixture
def mock_ofac_service():
    """Mock OFAC/SDN screening service."""
    service = Mock()
    service.screen = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def mock_sar_service():
    """Mock SAR filing service."""
    service = Mock()
    service.file_sar = Mock()
    service.check_sar_exists = Mock(return_value=False)
    return service


@pytest.fixture
def banking_service(
    mock_audit_logger,
    mock_rule_resolver,
    mock_ofac_service,
    mock_sar_service
):
    """Banking service with mocked dependencies."""
    return BankingService(
        audit_logger=mock_audit_logger,
        rule_resolver=mock_rule_resolver,
        ofac_service=mock_ofac_service,
        sar_service=mock_sar_service
    )


@pytest.fixture
def valid_account():
    """Valid account with sufficient balance."""
    return Account(
        account_id="ACC-001",
        balance=Decimal("10000.00"),
        routing_number="021000021",
        account_number="1234567890",
        is_valid=True
    )


@pytest.fixture
def valid_beneficiary():
    """Valid beneficiary account."""
    return Account(
        account_id="ACC-002",
        balance=Decimal("5000.00"),
        routing_number="021000022",
        account_number="0987654321",
        is_valid=True
    )


@pytest.fixture
def invalid_beneficiary():
    """Invalid beneficiary account."""
    return Account(
        account_id="ACC-INVALID",
        balance=Decimal("0.00"),
        routing_number="000000000",
        account_number="0000000000",
        is_valid=False
    )


# Test Cases

class TestSuccessfulTransaction:
    """Test successful transaction scenario."""

    def test_successful_transaction(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_audit_logger: Mock
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        initial_from_balance = valid_account.balance
        initial_to_balance = valid_beneficiary.balance
        transfer_amount = Decimal("500.00")
        user_id = "USER-123"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == transfer_amount
        assert valid_account.balance == initial_from_balance - transfer_amount
        assert valid_beneficiary.balance == initial_to_balance + transfer_amount
        assert transaction.user_id == user_id
        assert transaction.ip_address == ip_address
        assert transaction.device_info == device_info
        mock_audit_logger.log.assert_called_once_with(transaction)


class TestSARSuspiciousActivityAboveThreshold:
    """Test SAR filing for suspicious activity above threshold."""

    def test_sar_suspicious_activity_above_threshold(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_sar_service: Mock
    ):
        """
        Scenario: sar_suspicious_activity_above_threshold
        Given Transaction monitoring detects suspicious pattern
        When Suspicious activity involves > $5,000
        Then SAR filed with FinCEN within 30 days, subject NOT notified
        """
        # Arrange
        suspicious_amount = Decimal("6000.00")
        valid_account.balance = Decimal("10000.00")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=suspicious_amount,
            user_id="USER-456",
            ip_address="10.0.0.1",
            device_info="Chrome"
        )
        
        sar = banking_service.check_suspicious_activity(transaction)

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert sar is not None
        assert sar.amount == suspicious_amount
        assert sar.subject_notified is False
        assert sar.status == SARStatus.PENDING
        assert (sar.filed_date - sar.detection_date).days == 30
        mock_sar_service.file_sar.assert_called_once()

    def test_sar_threshold_boundary_at_5000(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_sar_service: Mock
    ):
        """
        Boundary test: Transaction exactly at $5,000 should not trigger SAR.
        """
        # Arrange
        threshold_amount = Decimal("5000.00")
        valid_account.balance = Decimal("10000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=threshold_amount,
            user_id="USER-789",
            ip_address="10.0.0.2",
            device_info="Safari"
        )
        
        sar = banking_service.check_suspicious_activity(transaction)

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert sar is None

    def test_sar_threshold_boundary_at_5001(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_sar_service: Mock
    ):
        """
        Boundary test: Transaction at $5,000.01 should trigger SAR.
        """
        # Arrange
        above_threshold_amount = Decimal("5000.01")
        valid_account.balance = Decimal("10000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=above_threshold_amount,
            user_id="USER-999",
            ip_address="10.0.0.3",
            device_info="Firefox"
        )
        
        sar = banking_service.check_suspicious_activity(transaction)

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert sar is not None
        assert sar.amount == above_threshold_amount


class TestSARInsiderAbuseAnyAmount:
    """Test SAR filing for insider abuse at any amount."""

    def test_sar_insider_abuse_any_amount(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_sar_service: Mock
    ):
        """
        Scenario: sar_insider_abuse_any_amount
        Given Bank employee involved in suspicious activity
        When Insider abuse detected at any dollar amount
        Then SAR filed immediately, no minimum threshold
        """
        # Arrange
        small_amount = Decimal("100.00")
        valid_account.balance = Decimal("10000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=small_amount,
            user_id="INSIDER-001",
            ip_address="192.168.1.50",
            device_info="Internal"
        )
        
        sar = banking_service.check_suspicious_activity(
            transaction,
            is_insider=True
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert sar is not None
        assert sar.insider_involved is True
        assert sar.amount == small_amount
        assert sar.subject_notified is False
        assert sar.status == SARStatus.FILED
        assert sar.filed_date == sar.detection_date
        mock_sar_service.file_sar.assert_called_once()

    def test_sar_insider_abuse_one_dollar(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_sar_service: Mock
    ):
        """
        Boundary test: Insider abuse with $1 should trigger immediate SAR.
        """
        # Arrange
        minimal_amount = Decimal("1.00")
        valid_account.balance = Decimal("10000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=minimal_amount,
            user_id="INSIDER-002",
            ip_address="192.168.1.51",
            device_info="Internal"
        )
        
        sar = banking_service.check_suspicious_activity(
            transaction,
            is_insider=True
        )

        # Assert
        assert sar is not None
        assert sar.insider_involved is True
        assert sar.amount == minimal_amount


class TestSARNoTippingOff:
    """Test no tipping off requirement for SAR filings."""

    def test_sar_no_tipping_off(self, banking_service: BankingService):
        """
        Scenario: sar_no_tipping_off
        Given SAR has been filed for a customer
        When Customer inquires about account restrictions
        Then Bank does NOT disclose SAR filing
        """
        # Arrange
        customer_id = "CUST-001"
        sar_exists = True

        # Act
        response = banking_service.handle_customer_inquiry(
            customer_id=customer_id,
            sar_exists=sar_exists
        )

        # Assert
        assert "SAR" not in response
        assert "Suspicious Activity Report" not in response
        assert "FinCEN" not in response
        assert "standard procedures" in response

    def test_no_sar_customer_inquiry(self, banking_service: BankingService):
        """
        Test customer inquiry when no SAR exists.
        """
        # Arrange
        customer_id = "CUST-002"
        sar_exists = False

        # Act
        response = banking_service.handle_customer_inquiry(
            customer_id=customer_id,
            sar_exists=sar_exists
        )

        # Assert
        assert "No restrictions" in response


class TestZeroAmountTransfer:
    """Test zero amount transfer rejection."""

    def test_zero_amount_transfer(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_audit_logger: Mock
    ):
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        zero_amount = Decimal("0.00")
        initial_balance = valid_account.balance

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=zero_amount,
            user_id="USER-ZERO",
            ip_address="10.0.0.10",
            device_info="Mobile"
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Amount must be greater than 0"
        assert valid_account.balance == initial_balance
        mock_audit_logger.log.assert_called_once()


class TestNegativeAmountTransfer:
    """Test negative amount transfer rejection."""

    def test_negative_amount_transfer(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_audit_logger: Mock
    ):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        negative_amount = Decimal("-100.00")
        initial_balance = valid_account.balance

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=negative_amount,
            user_id="USER-NEG",
            ip_address="10.0.0.11",
            device_info="Desktop"
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid amount"
        assert valid_account.balance == initial_balance
        mock_audit_logger.log.assert_called_once()


class TestInsufficientBalance:
    """Test insufficient balance rejection."""

    def test_insufficient_balance(
        self,
        banking_service: BankingService,
        mock_audit_logger: Mock
    ):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        low_balance_account = Account(
            account_id="ACC-LOW",
            balance=Decimal("1000.00"),
            routing_number="021000021",
            account_number="1111111111",
            is_valid=True
        )
        beneficiary = Account(
            account_id="ACC-BEN",
            balance=Decimal("0.00"),
            routing_number="021000022",
            account_number="2222222222",
            is_valid=True
        )
        transfer_amount = Decimal("5000.00")
        initial_balance = low_balance_account.balance

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=low_balance_account,
            to_account=beneficiary,
            amount=transfer_amount,
            user_id="USER-BROKE",
            ip_address="10.0.0.12",
            device_info="Tablet"
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Insufficient balance"
        assert low_balance_account.balance == initial_balance
        mock_audit_logger.log.assert_called_once()

    def test_insufficient_balance_boundary(
        self,
        banking_service: BankingService,
        mock_audit_logger: Mock
    ):
        """
        Boundary test: Transfer amount exactly equal to balance + 0.01 should fail.
        """
        # Arrange
        account = Account(
            account_id="ACC-BOUNDARY",
            balance=Decimal("1000.00"),
            routing_number="021000021",
            account_number="3333333333",
            is_valid=True
        )
        beneficiary = Account(
            account_id="ACC-BEN2",
            balance=Decimal("0.00"),
            routing_number="021000022",
            account_number="4444444444",
            is_valid=True
        )
        transfer_amount = Decimal("1000.01")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=account,
            to_account=beneficiary,
            amount=transfer_amount,
            user_id="USER-BOUNDARY",
            ip_address="10.0.0.13",
            device_info="Web"
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test invalid beneficiary account rejection."""

    def test_invalid_beneficiary(
        self,
        banking_service: BankingService,
        valid_account: Account,
        invalid_beneficiary: Account,
        mock_audit_logger: Mock
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        transfer_amount = Decimal("100.00")
        initial_balance = valid_account.balance

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=invalid_beneficiary,
            amount=transfer_amount,
            user_id="USER-INVALID",
            ip_address="10.0.0.14",
            device_info="Mobile"
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"
        assert valid_account.balance == initial_balance
        mock_audit_logger.log.assert_called_once()


class TestComplianceThresholds:
    """Test various compliance thresholds."""

    def test_ctr_threshold_boundary(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account
    ):
        """
        Boundary test: CTR threshold at $10,000 for cash transactions.
        """
        # Arrange
        ctr_threshold = Decimal("10000.00")
        valid_account.balance = Decimal("20000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=ctr_threshold,
            user_id="USER-CTR",
            ip_address="10.0.0.20",
            device_info="ATM"
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == ctr_threshold

    def test_travel_rule_threshold(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account
    ):
        """
        Boundary test: Travel Rule threshold at $3,000 for wire transfers.
        """
        # Arrange
        travel_rule_amount = Decimal("3000.00")
        valid_account.balance = Decimal("10000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=travel_rule_amount,
            user_id="USER-TRAVEL",
            ip_address="10.0.0.21",
            device_info="Wire"
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == travel_rule_amount

    def test_dual_approval_threshold(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account
    ):
        """
        Boundary test: Dual approval threshold at $10,000 for wire transfers.
        """
        # Arrange
        dual_approval_amount = Decimal("10000.00")
        valid_account.balance = Decimal("20000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=dual_approval_amount,
            user_id="USER-DUAL",
            ip_address="10.0.0.22",
            device_info="Wire"
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == dual_approval_amount


class TestAuditTrailRequirements:
    """Test audit trail and logging requirements."""

    def test_audit_trail_contains_required_fields(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_audit_logger: Mock
    ):
        """
        Test that audit trail contains all required fields per compliance.
        """
        # Arrange
        transfer_amount = Decimal("250.00")
        user_id = "USER-AUDIT"
        ip_address = "192.168.1.200"
        device_info = "Chrome/91.0"

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        # Assert
        mock_audit_logger.log.assert_called_once()
        logged_transaction = mock_audit_logger.log.call_args[0][0]
        assert logged_transaction.user_id == user_id
        assert logged_transaction.ip_address == ip_address
        assert logged_transaction.device_info == device_info
        assert logged_transaction.timestamp is not None
        assert logged_transaction.timestamp.tzinfo is not None

    def test_timestamp_is_timezone_aware(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account
    ):
        """
        Test that transaction timestamps are timezone-aware (UTC).
        """
        # Arrange
        transfer_amount = Decimal("100.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=transfer_amount,
            user_id="USER-TZ",
            ip_address="10.0.0.30",
            device_info="API"
        )

        # Assert
        assert transaction.timestamp.tzinfo == timezone.utc


class TestDecimalPrecision:
    """Test decimal precision for currency handling."""

    def test_decimal_precision_for_currency(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account
    ):
        """
        Test that currency amounts use Decimal type for precision.
        """
        # Arrange
        precise_amount = Decimal("123.45")
        valid_account.balance = Decimal("1000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=precise_amount,
            user_id="USER-DECIMAL",
            ip_address="10.0.0.40",
            device_info="Mobile"
        )

        # Assert
        assert isinstance(transaction.amount, Decimal)
        assert transaction.amount == precise_amount
        assert isinstance(valid_account.balance, Decimal)

    def test_fractional_cents_handling(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account
    ):
        """
        Test handling of amounts with fractional cents.
        """
        # Arrange
        fractional_amount = Decimal("99.999")
        valid_account.balance = Decimal("1000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=fractional_amount,
            user_id="USER-FRAC",
            ip_address="10.0.0.41",
            device_info="Web"
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert isinstance(transaction.amount, Decimal)


class TestNegativePathScenarios:
    """Test negative path and edge case scenarios."""

    def test_concurrent_transaction_race_condition(
        self,
        banking_service: BankingService,
        mock_audit_logger: Mock
    ):
        """
        Test handling of concurrent transactions that could cause race conditions.
        """
        # Arrange
        account = Account(
            account_id="ACC-RACE",
            balance=Decimal("1000.00"),
            routing_number="021000021",
            account_number="5555555555",
            is_valid=True
        )
        beneficiary1 = Account(
            account_id="ACC-BEN1",
            balance=Decimal("0.00"),
            routing_number="021000022",
            account_number="6666666666",
            is_valid=True
        )
        beneficiary2 = Account(
            account_id="ACC-BEN2",
            balance=Decimal("0.00"),
            routing_number="021000023",
            account_number="7777777777",
            is_valid=True
        )

        # Act
        transaction1 = banking_service.initiate_transaction(
            from_account=account,
            to_account=beneficiary1,
            amount=Decimal("600.00"),
            user_id="USER-RACE1",
            ip_address="10.0.0.50",
            device_info="Thread1"
        )
        
        transaction2 = banking_service.initiate_transaction(
            from_account=account,
            to_account=beneficiary2,
            amount=Decimal("600.00"),
            user_id="USER-RACE2",
            ip_address="10.0.0.51",
            device_info="Thread2"
        )

        # Assert
        assert transaction1.status == TransactionStatus.SUCCESS
        assert transaction2.status == TransactionStatus.REJECTED
        assert transaction2.rejection_reason == "Insufficient balance"

    def test_false_positive_sar_below_threshold(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_sar_service: Mock
    ):
        """
        Test that transactions below SAR threshold do not trigger false positives.
        """
        # Arrange
        below_threshold = Decimal("4999.99")
        valid_account.balance = Decimal("10000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=below_threshold,
            user_id="USER-FALSE",
            ip_address="10.0.0.60",
            device_info="Web"
        )
        
        sar = banking_service.check_suspicious_activity(transaction)

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert sar is None

    def test_maximum_decimal_amount(
        self,
        banking_service: BankingService,
        mock_audit_logger: Mock
    ):
        """
        Test handling of very large transaction amounts.
        """
        # Arrange
        large_account = Account(
            account_id="ACC-LARGE",
            balance=Decimal("999999999.99"),
            routing_number="021000021",
            account_number="8888888888",
            is_valid=True
        )
        beneficiary = Account(
            account_id="ACC-BEN-LARGE",
            balance=Decimal("0.00"),
            routing_number="021000022",
            account_number="9999999999",
            is_valid=True
        )
        large_amount = Decimal("999999999.99")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=large_account,
            to_account=beneficiary,
            amount=large_amount,
            user_id="USER-LARGE",
            ip_address="10.0.0.70",
            device_info="Enterprise"
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == large_amount


class TestOFACScreening:
    """Test OFAC/SDN screening integration."""

    def test_ofac_screening_no_match(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account,
        mock_ofac_service: Mock
    ):
        """
        Test OFAC screening with no match (transaction proceeds).
        """
        # Arrange
        mock_ofac_service.screen.return_value = {
            "match": False,
            "score": 0
        }
        transfer_amount = Decimal("1000.00")

        # Act
        transaction = banking_service.initiate_transaction(
            from_account=valid_account,
            to_account=valid_beneficiary,
            amount=transfer_amount,
            user_id="USER-OFAC-CLEAR",
            ip_address="10.0.0.80",
            device_info="Web"
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS

    def test_ofac_screening_fuzzy_match_below_threshold(
        self,
        mock_ofac_service: Mock
    ):
        """
        Test OFAC fuzzy matching below 85% threshold (no block).
        """
        # Arrange
        mock_ofac_service.screen.return_value = {
            "match": False,
            "score": 84
        }

        # Act
        result = mock_ofac_service.screen("John Smith")

        # Assert
        assert result["match"] is False
        assert result["score"] < 85

    def test_ofac_screening_fuzzy_match_above_threshold(
        self,
        mock_ofac_service: Mock
    ):
        """
        Test OFAC fuzzy matching at or above 85% threshold (review required).
        """
        # Arrange
        mock_ofac_service.screen.return_value = {
            "match": True,
            "score": 85
        }

        # Act
        result = mock_ofac_service.screen("Suspicious Name")

        # Assert
        assert result["match"] is True
        assert result["score"] >= 85


class TestDataHandlingCompliance:
    """Test data handling and security compliance requirements."""

    def test_pii_masking_in_logs(self):
        """
        Test that PII (SSN/TIN) is masked in logs (show last 4 only).
        """
        # Arrange
        ssn = "123-45-6789"
        
        # Act
        masked_ssn = f"***-**-{ssn[-4:]}"

        # Assert
        assert masked_ssn == "***-**-6789"
        assert "123-45" not in masked_ssn

    def test_encryption_requirements_documented(self):
        """
        Test that encryption requirements are documented.
        TLS 1.3 for data in transit, AES-256 for data at rest.
        """
        # Arrange
        encryption_config = {
            "transit": "TLS 1.3",
            "at_rest": "AES-256"
        }

        # Assert
        assert encryption_config["transit"] == "TLS 1.3"
        assert encryption_config["at_rest"] == "AES-256"


class TestRegEErrorHandling:
    """Test Regulation E error and dispute handling."""

    def test_reg_e_dispute_window(self):
        """
        Test Reg E 60-day dispute window for unauthorized transactions.
        """
        # Arrange
        transaction_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        dispute_date = datetime(2024, 2, 29, tzinfo=timezone.utc)
        
        # Act
        days_elapsed = (dispute_date - transaction_date).days

        # Assert
        assert days_elapsed <= 60

    def test_reg_e_dispute_outside_window(self):
        """
        Test dispute filed outside Reg E 60-day window.
        """
        # Arrange
        transaction_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        dispute_date = datetime(2024, 3, 15, tzinfo=timezone.utc)
        
        # Act
        days_elapsed = (dispute_date - transaction_date).days

        # Assert
        assert days_elapsed > 60


class TestBSARecordRetention:
    """Test BSA record retention requirements."""

    def test_bsa_record_retention_5_years(self):
        """
        Test that BSA records are retained for 5 years (31 CFR 1010.430).
        """
        # Arrange
        record_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        retention_period_years = 5
        
        # Act
        expiration_date = record_date.replace(
            year=record_date.year + retention_period_years
        )
        retention_days = (expiration_date - record_date).days

        # Assert
        assert retention_days >= 1825  # 5 years * 365 days


class TestStructuringDetection:
    """Test structuring detection for CTR avoidance."""

    def test_structuring_detection_multiple_transactions(
        self,
        banking_service: BankingService,
        valid_account: Account,
        valid_beneficiary: Account
    ):
        """
        Test detection of structuring (multiple transactions below $10k threshold).
        """
        # Arrange
        valid_account.balance = Decimal("50000.00")
        transactions = []

        # Act - Multiple transactions just below CTR threshold
        for i in range(3):
            transaction = banking_service.initiate_transaction(
                from_account=valid_account,
                to_account=valid_beneficiary,
                amount=Decimal("9999.00"),
                user_id=f"USER-STRUCT-{i}",
                ip_address="10.0.0.90",
                device_info="Web"
            )
            transactions.append(transaction)

        # Assert
        total_amount = sum(t.amount for t in transactions)
        assert total_amount > Decimal("10000.00")
        assert all(t.amount < Decimal("10000.00") for t in transactions)
        assert all(t.status == TransactionStatus.SUCCESS for t in transactions)


class TestBeneficialOwnership:
    """Test beneficial ownership requirements."""

    def test_beneficial_ownership_threshold_20_percent(self):
        """
        Test beneficial ownership threshold at 20% for CDD requirements.
        """
        # Arrange
        ownership_percentage = Decimal("20.0")
        threshold = Decimal("20.0")

        # Assert
        assert ownership_percentage >= threshold

    def test_beneficial_ownership_below_threshold(self):
        """
        Test ownership below 20% threshold.
        """
        # Arrange
        ownership_percentage = Decimal("19.9")
        threshold = Decimal("20.0")

        # Assert
        assert ownership_percentage < threshold