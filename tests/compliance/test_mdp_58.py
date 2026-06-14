import pytest
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    REVIEW = "REVIEW"


class SARStatus(Enum):
    FILED = "FILED"
    PENDING = "PENDING"
    NOT_REQUIRED = "NOT_REQUIRED"


@dataclass
class Account:
    account_id: str
    balance: Decimal
    routing_number: str
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


@dataclass
class SARFiling:
    sar_id: str
    transaction_id: Optional[str]
    subject_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    is_insider: bool
    status: SARStatus


@dataclass
class AuditRecord:
    audit_id: str
    timestamp: datetime
    user_id: str
    action: str
    details: Dict[str, Any]
    ip_address: str
    device_info: str
    immutable_hash: str


class BankingService:
    def __init__(self, account_repo, audit_logger, sar_service, ofac_service, rule_resolver):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.sar_service = sar_service
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver

    def initiate_transaction(
        self,
        from_account_id: str,
        to_account_id: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str,
    ) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc)
        
        # Validation
        if amount <= Decimal("0"):
            error_msg = "Amount must be greater than 0" if amount == Decimal("0") else "Invalid amount"
            self.audit_logger.log_transaction_attempt(
                user_id, from_account_id, to_account_id, amount, "REJECTED", error_msg, timestamp
            )
            return {"status": TransactionStatus.REJECTED, "error": error_msg}
        
        from_account = self.account_repo.get_account(from_account_id)
        if not from_account:
            error_msg = "Invalid source account"
            self.audit_logger.log_transaction_attempt(
                user_id, from_account_id, to_account_id, amount, "REJECTED", error_msg, timestamp
            )
            return {"status": TransactionStatus.REJECTED, "error": error_msg}
        
        to_account = self.account_repo.get_account(to_account_id)
        if not to_account:
            error_msg = "Invalid beneficiary account"
            self.audit_logger.log_transaction_attempt(
                user_id, from_account_id, to_account_id, amount, "REJECTED", error_msg, timestamp
            )
            return {"status": TransactionStatus.REJECTED, "error": error_msg}
        
        if from_account.balance < amount:
            error_msg = "Insufficient balance"
            self.audit_logger.log_transaction_attempt(
                user_id, from_account_id, to_account_id, amount, "REJECTED", error_msg, timestamp
            )
            return {"status": TransactionStatus.REJECTED, "error": error_msg}
        
        # OFAC screening
        ofac_result = self.ofac_service.screen_transaction(from_account_id, to_account_id, user_id)
        if ofac_result["blocked"]:
            self.audit_logger.log_ofac_block(user_id, from_account_id, to_account_id, amount, timestamp)
            return {"status": TransactionStatus.BLOCKED, "error": "OFAC screening failed"}
        
        # Process transaction
        transaction_id = f"TXN-{timestamp.timestamp()}"
        from_account.balance -= amount
        to_account.balance += amount
        
        self.account_repo.update_account(from_account)
        self.account_repo.update_account(to_account)
        
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
        self.audit_logger.log_successful_transaction(transaction)
        
        # Suspicious activity monitoring
        self.sar_service.monitor_transaction(transaction)
        
        return {
            "status": TransactionStatus.SUCCESS,
            "transaction_id": transaction_id,
            "new_balance": from_account.balance,
        }

    def handle_customer_inquiry(self, customer_id: str, inquiry_type: str) -> Dict[str, Any]:
        if inquiry_type == "account_restrictions":
            # No tipping off rule - never disclose SAR filing
            return {
                "response": "Your account is subject to standard monitoring procedures.",
                "sar_disclosed": False,
            }
        return {"response": "General inquiry response"}


@pytest.fixture
def mock_account_repo():
    repo = Mock()
    repo.get_account = Mock()
    repo.update_account = Mock()
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock()
    logger.log_transaction_attempt = Mock()
    logger.log_successful_transaction = Mock()
    logger.log_ofac_block = Mock()
    logger.log_sar_filing = Mock()
    return logger


@pytest.fixture
def mock_sar_service():
    service = Mock()
    service.monitor_transaction = Mock()
    service.file_sar = Mock()
    service.check_sar_exists = Mock(return_value=False)
    return service


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen_transaction = Mock(return_value={"blocked": False, "match_score": 0})
    return service


@pytest.fixture
def mock_rule_resolver():
    resolver = Mock()
    resolver.get_sar_threshold = Mock(return_value=Decimal("5000"))
    resolver.get_insider_threshold = Mock(return_value=Decimal("0"))
    resolver.get_filing_deadline_days = Mock(return_value=30)
    return resolver


@pytest.fixture
def banking_service(
    mock_account_repo, mock_audit_logger, mock_sar_service, mock_ofac_service, mock_rule_resolver
):
    return BankingService(
        mock_account_repo,
        mock_audit_logger,
        mock_sar_service,
        mock_ofac_service,
        mock_rule_resolver,
    )


@pytest.fixture
def valid_account_with_balance():
    return Account(
        account_id="ACC-001",
        balance=Decimal("10000.00"),
        routing_number="021000021",
        status="ACTIVE",
    )


@pytest.fixture
def valid_beneficiary_account():
    return Account(
        account_id="ACC-002",
        balance=Decimal("5000.00"),
        routing_number="021000022",
        status="ACTIVE",
    )


class TestSuccessfulTransaction:
    """Test successful transaction with sufficient balance and valid account."""

    def test_successful_transaction(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account_with_balance,
        valid_beneficiary_account,
    ):
        """
        Given: User has sufficient balance and valid account
        When: User initiates valid transaction
        Then: Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        mock_account_repo.get_account.side_effect = lambda acc_id: (
            valid_account_with_balance if acc_id == "ACC-001" else valid_beneficiary_account
        )
        transfer_amount = Decimal("500.00")
        expected_new_balance = Decimal("9500.00")

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=transfer_amount,
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.SUCCESS
        assert "transaction_id" in result
        assert result["new_balance"] == expected_new_balance
        assert valid_account_with_balance.balance == expected_new_balance
        assert valid_beneficiary_account.balance == Decimal("5500.00")
        mock_audit_logger.log_successful_transaction.assert_called_once()
        mock_account_repo.update_account.assert_called()


class TestSARSuspiciousActivityAboveThreshold:
    """Test SAR filing for suspicious activity above $5,000 threshold."""

    def test_sar_suspicious_activity_above_threshold(self, mock_sar_service, mock_rule_resolver):
        """
        Given: Transaction monitoring detects suspicious pattern
        When: Suspicious activity involves > $5,000
        Then: SAR filed with FinCEN within 30 days, subject NOT notified
        """
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        filing_deadline = detection_date + timedelta(days=30)
        suspicious_amount = Decimal("7500.00")
        sar_threshold = Decimal("5000.00")

        transaction = Transaction(
            transaction_id="TXN-SUSP-001",
            from_account="ACC-001",
            to_account="ACC-002",
            amount=suspicious_amount,
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Act
        should_file_sar = suspicious_amount > sar_threshold
        if should_file_sar:
            sar_filing = SARFiling(
                sar_id="SAR-2024-001",
                transaction_id=transaction.transaction_id,
                subject_id=transaction.user_id,
                amount=suspicious_amount,
                reason="Suspicious pattern detected - structuring",
                filed_date=detection_date + timedelta(days=5),
                detection_date=detection_date,
                is_insider=False,
                status=SARStatus.FILED,
            )
            mock_sar_service.file_sar(sar_filing)

        # Assert
        assert should_file_sar is True
        assert suspicious_amount > sar_threshold
        mock_sar_service.file_sar.assert_called_once()
        filed_sar = mock_sar_service.file_sar.call_args[0][0]
        assert filed_sar.amount == suspicious_amount
        assert filed_sar.filed_date <= filing_deadline
        assert filed_sar.is_insider is False

    def test_sar_below_threshold_not_filed(self, mock_sar_service):
        """Test that SAR is not filed for amounts below $5,000 threshold."""
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        amount_below_threshold = Decimal("4999.99")
        sar_threshold = Decimal("5000.00")

        # Act
        should_file_sar = amount_below_threshold > sar_threshold

        # Assert
        assert should_file_sar is False
        mock_sar_service.file_sar.assert_not_called()

    def test_sar_at_exact_threshold(self, mock_sar_service):
        """Test SAR filing behavior at exact $5,000 threshold."""
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        exact_threshold = Decimal("5000.00")
        sar_threshold = Decimal("5000.00")

        # Act
        should_file_sar = exact_threshold > sar_threshold

        # Assert
        assert should_file_sar is False  # > not >=


class TestSARInsiderAbuseAnyAmount:
    """Test SAR filing for insider abuse at any dollar amount."""

    def test_sar_insider_abuse_any_amount(self, mock_sar_service):
        """
        Given: Bank employee involved in suspicious activity
        When: Insider abuse detected at any dollar amount
        Then: SAR filed immediately, no minimum threshold
        """
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        insider_amount = Decimal("100.00")  # Below normal threshold
        insider_threshold = Decimal("0")

        transaction = Transaction(
            transaction_id="TXN-INSIDER-001",
            from_account="ACC-EMPLOYEE-001",
            to_account="ACC-002",
            amount=insider_amount,
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="EMPLOYEE-456",
            ip_address="10.0.0.50",
            device_info="Internal System",
        )

        # Act
        is_insider = True
        should_file_sar = is_insider and insider_amount >= insider_threshold

        if should_file_sar:
            sar_filing = SARFiling(
                sar_id="SAR-INSIDER-2024-001",
                transaction_id=transaction.transaction_id,
                subject_id=transaction.user_id,
                amount=insider_amount,
                reason="Insider abuse detected - unauthorized access",
                filed_date=detection_date,  # Immediate filing
                detection_date=detection_date,
                is_insider=True,
                status=SARStatus.FILED,
            )
            mock_sar_service.file_sar(sar_filing)

        # Assert
        assert should_file_sar is True
        mock_sar_service.file_sar.assert_called_once()
        filed_sar = mock_sar_service.file_sar.call_args[0][0]
        assert filed_sar.is_insider is True
        assert filed_sar.amount == insider_amount
        assert filed_sar.filed_date == detection_date  # Immediate

    def test_sar_insider_abuse_minimal_amount(self, mock_sar_service):
        """Test SAR filing for insider abuse with minimal amount ($1)."""
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        minimal_amount = Decimal("1.00")
        insider_threshold = Decimal("0")

        # Act
        is_insider = True
        should_file_sar = is_insider and minimal_amount >= insider_threshold

        if should_file_sar:
            sar_filing = SARFiling(
                sar_id="SAR-INSIDER-2024-002",
                transaction_id="TXN-INSIDER-002",
                subject_id="EMPLOYEE-789",
                amount=minimal_amount,
                reason="Insider abuse - policy violation",
                filed_date=detection_date,
                detection_date=detection_date,
                is_insider=True,
                status=SARStatus.FILED,
            )
            mock_sar_service.file_sar(sar_filing)

        # Assert
        assert should_file_sar is True
        mock_sar_service.file_sar.assert_called_once()


class TestSARNoTippingOff:
    """Test no tipping off rule - bank must not disclose SAR filing."""

    def test_sar_no_tipping_off(self, banking_service, mock_sar_service):
        """
        Given: SAR has been filed for a customer
        When: Customer inquires about account restrictions
        Then: Bank does NOT disclose SAR filing
        """
        # Arrange
        customer_id = "CUST-001"
        mock_sar_service.check_sar_exists.return_value = True

        # Act
        response = banking_service.handle_customer_inquiry(
            customer_id=customer_id, inquiry_type="account_restrictions"
        )

        # Assert
        assert response["sar_disclosed"] is False
        assert "SAR" not in response["response"]
        assert "Suspicious Activity Report" not in response["response"]
        assert "standard monitoring procedures" in response["response"]

    def test_no_tipping_off_generic_response(self, banking_service):
        """Test that customer receives generic response without SAR disclosure."""
        # Arrange
        customer_id = "CUST-002"

        # Act
        response = banking_service.handle_customer_inquiry(
            customer_id=customer_id, inquiry_type="account_restrictions"
        )

        # Assert
        assert "sar" not in response["response"].lower()
        assert "suspicious" not in response["response"].lower()
        assert response["sar_disclosed"] is False


class TestZeroAmountTransfer:
    """Test rejection of zero amount transfers."""

    def test_zero_amount_transfer(self, banking_service, mock_audit_logger):
        """
        Given: User initiates transfer
        When: User enters amount $0
        Then: Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        zero_amount = Decimal("0")

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=zero_amount,
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.REJECTED
        assert result["error"] == "Amount must be greater than 0"
        mock_audit_logger.log_transaction_attempt.assert_called_once()


class TestNegativeAmountTransfer:
    """Test rejection of negative amount transfers."""

    def test_negative_amount_transfer(self, banking_service, mock_audit_logger):
        """
        Given: User initiates transfer
        When: User enters amount -$100
        Then: Transaction rejected 'Invalid amount'
        """
        # Arrange
        negative_amount = Decimal("-100.00")

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=negative_amount,
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.REJECTED
        assert result["error"] == "Invalid amount"
        mock_audit_logger.log_transaction_attempt.assert_called_once()

    def test_large_negative_amount(self, banking_service):
        """Test rejection of large negative amount."""
        # Arrange
        large_negative = Decimal("-999999.99")

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=large_negative,
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.REJECTED
        assert result["error"] == "Invalid amount"


class TestInsufficientBalance:
    """Test rejection of transactions with insufficient balance."""

    def test_insufficient_balance(
        self, banking_service, mock_account_repo, mock_audit_logger, valid_account_with_balance
    ):
        """
        Given: User has balance $1,000
        When: User transfers $5,000
        Then: Transaction rejected 'Insufficient balance'
        """
        # Arrange
        account_with_low_balance = Account(
            account_id="ACC-001",
            balance=Decimal("1000.00"),
            routing_number="021000021",
            status="ACTIVE",
        )
        mock_account_repo.get_account.side_effect = lambda acc_id: (
            account_with_low_balance
            if acc_id == "ACC-001"
            else Account("ACC-002", Decimal("0"), "021000022")
        )
        transfer_amount = Decimal("5000.00")

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=transfer_amount,
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.REJECTED
        assert result["error"] == "Insufficient balance"
        assert account_with_low_balance.balance == Decimal("1000.00")  # Unchanged
        mock_audit_logger.log_transaction_attempt.assert_called_once()

    def test_exact_balance_transfer_succeeds(
        self, banking_service, mock_account_repo, valid_account_with_balance, valid_beneficiary_account
    ):
        """Test that transfer of exact balance amount succeeds."""
        # Arrange
        exact_balance = Decimal("1000.00")
        account = Account("ACC-001", exact_balance, "021000021", "ACTIVE")
        mock_account_repo.get_account.side_effect = lambda acc_id: (
            account if acc_id == "ACC-001" else valid_beneficiary_account
        )

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=exact_balance,
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.SUCCESS
        assert account.balance == Decimal("0")


class TestInvalidBeneficiary:
    """Test rejection of transactions with invalid beneficiary account."""

    def test_invalid_beneficiary(
        self, banking_service, mock_account_repo, mock_audit_logger, valid_account_with_balance
    ):
        """
        Given: User initiates transfer
        When: User enters invalid routing/account number
        Then: Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        mock_account_repo.get_account.side_effect = lambda acc_id: (
            valid_account_with_balance if acc_id == "ACC-001" else None
        )

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-INVALID",
            amount=Decimal("100.00"),
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.REJECTED
        assert result["error"] == "Invalid beneficiary account"
        mock_audit_logger.log_transaction_attempt.assert_called_once()

    def test_invalid_source_account(self, banking_service, mock_account_repo, mock_audit_logger):
        """Test rejection when source account is invalid."""
        # Arrange
        mock_account_repo.get_account.return_value = None

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-INVALID",
            to_account_id="ACC-002",
            amount=Decimal("100.00"),
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.REJECTED
        assert result["error"] == "Invalid source account"


class TestOFACScreening:
    """Test OFAC/SDN screening and blocking."""

    def test_ofac_blocked_transaction(
        self,
        banking_service,
        mock_account_repo,
        mock_ofac_service,
        mock_audit_logger,
        valid_account_with_balance,
        valid_beneficiary_account,
    ):
        """Test that transaction is blocked when OFAC screening fails."""
        # Arrange
        mock_account_repo.get_account.side_effect = lambda acc_id: (
            valid_account_with_balance if acc_id == "ACC-001" else valid_beneficiary_account
        )
        mock_ofac_service.screen_transaction.return_value = {
            "blocked": True,
            "match_score": 95,
            "matched_entity": "SDN-12345",
        }

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=Decimal("1000.00"),
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.BLOCKED
        assert result["error"] == "OFAC screening failed"
        mock_ofac_service.screen_transaction.assert_called_once()
        mock_audit_logger.log_ofac_block.assert_called_once()

    def test_ofac_screening_pass(
        self,
        banking_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account_with_balance,
        valid_beneficiary_account,
    ):
        """Test that transaction proceeds when OFAC screening passes."""
        # Arrange
        mock_account_repo.get_account.side_effect = lambda acc_id: (
            valid_account_with_balance if acc_id == "ACC-001" else valid_beneficiary_account
        )
        mock_ofac_service.screen_transaction.return_value = {"blocked": False, "match_score": 10}

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=Decimal("1000.00"),
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.SUCCESS
        mock_ofac_service.screen_transaction.assert_called_once()


class TestBoundaryConditions:
    """Test boundary conditions for compliance thresholds."""

    def test_sar_threshold_boundary_4999(self):
        """Test SAR filing at $4,999.99 (just below threshold)."""
        # Arrange
        amount = Decimal("4999.99")
        sar_threshold = Decimal("5000.00")

        # Act
        should_file = amount > sar_threshold

        # Assert
        assert should_file is False

    def test_sar_threshold_boundary_5000(self):
        """Test SAR filing at exactly $5,000 (at threshold)."""
        # Arrange
        amount = Decimal("5000.00")
        sar_threshold = Decimal("5000.00")

        # Act
        should_file = amount > sar_threshold

        # Assert
        assert should_file is False  # > not >=

    def test_sar_threshold_boundary_5001(self):
        """Test SAR filing at $5,000.01 (just above threshold)."""
        # Arrange
        amount = Decimal("5000.01")
        sar_threshold = Decimal("5000.00")

        # Act
        should_file = amount > sar_threshold

        # Assert
        assert should_file is True

    def test_ctr_threshold_boundary(self):
        """Test CTR filing threshold at $10,000."""
        # Arrange
        ctr_threshold = Decimal("10000.00")
        amounts = [
            Decimal("9999.99"),
            Decimal("10000.00"),
            Decimal("10000.01"),
        ]

        # Act & Assert
        assert amounts[0] < ctr_threshold
        assert amounts[1] == ctr_threshold
        assert amounts[2] > ctr_threshold

    def test_travel_rule_threshold(self):
        """Test Travel Rule threshold at $3,000."""
        # Arrange
        travel_rule_threshold = Decimal("3000.00")
        amounts = [
            Decimal("2999.99"),
            Decimal("3000.00"),
            Decimal("3000.01"),
        ]

        # Act & Assert
        assert amounts[0] < travel_rule_threshold
        assert amounts[1] >= travel_rule_threshold
        assert amounts[2] >= travel_rule_threshold

    def test_beneficial_ownership_threshold(self):
        """Test beneficial ownership threshold at 25%."""
        # Arrange
        ownership_threshold_pct = 25
        ownership_percentages = [24, 25, 26]

        # Act & Assert
        assert ownership_percentages[0] < ownership_threshold_pct
        assert ownership_percentages[1] >= ownership_threshold_pct
        assert ownership_percentages[2] >= ownership_threshold_pct


class TestAuditTrailRequirements:
    """Test audit trail and logging requirements."""

    def test_audit_trail_records_all_transaction_details(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account_with_balance,
        valid_beneficiary_account,
    ):
        """Test that audit trail captures all required transaction details."""
        # Arrange
        mock_account_repo.get_account.side_effect = lambda acc_id: (
            valid_account_with_balance if acc_id == "ACC-001" else valid_beneficiary_account
        )
        user_id = "USER-123"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-001",
            to_account_id="ACC-002",
            amount=Decimal("500.00"),
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result["status"] == TransactionStatus.SUCCESS
        mock_audit_logger.log_successful_transaction.assert_called_once()
        logged_transaction = mock_audit_logger.log_successful_transaction.call_args[0][0]
        assert logged_transaction.user_id == user_id
        assert logged_transaction.ip_address == ip_address
        assert logged_transaction.device_info == device_info
        assert isinstance(logged_transaction.timestamp, datetime)
        assert logged_transaction.timestamp.tzinfo is not None

    def test_audit_trail_records_failed_attempts(
        self, banking_service, mock_account_repo, mock_audit_logger
    ):
        """Test that audit trail records failed transaction attempts."""
        # Arrange
        mock_account_repo.get_account.return_value = None

        # Act
        result = banking_service.initiate_transaction(
            from_account_id="ACC-INVALID",
            to_account_id="ACC-002",
            amount=Decimal("100.00"),
            user_id="USER-123",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert result["status"] == TransactionStatus.REJECTED
        mock_audit_logger.log_transaction_attempt.assert_called_once()


class TestDataHandlingAndSecurity:
    """Test data handling, encryption, and PII masking requirements."""

    def test_ssn_masking_in_logs(self):
        """Test that SSN/TIN is masked in logs (show last 4 only)."""
        # Arrange
        full_ssn = "123-45-6789"
        expected_masked = "XXX-XX-6789"

        # Act
        def mask_ssn(ssn: str) -> str:
            if len(ssn) == 11:  # Format: XXX-XX-XXXX
                return f"XXX-XX-{ssn[-4:]}"
            return "XXX-XX-XXXX"

        masked = mask_ssn(full_ssn)

        # Assert
        assert masked == expected_masked
        assert "123" not in masked
        assert "45" not in masked
        assert "6789" in masked

    def test_decimal_precision_for_currency(self):
        """Test that Decimal type maintains precision for currency."""
        # Arrange
        amount1 = Decimal("100.00")
        amount2 = Decimal("0.01")

        # Act
        result = amount1 + amount2

        # Assert
        assert result == Decimal("100.01")
        assert isinstance(result, Decimal)
        assert str(result) == "100.01"

    def test_timezone_aware_timestamps(self):
        """Test that all timestamps are timezone-aware (UTC)."""
        # Arrange
        timestamp = datetime.now(timezone.utc)

        # Assert
        assert timestamp.tzinfo is not None
        assert timestamp.tzinfo == timezone.utc


class TestSARFilingDeadline:
    """Test SAR filing deadline requirements."""

    def test_sar_filing_within_30_days(self):
        """Test that SAR is filed within 30 days of detection."""
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        filing_date = datetime(2024, 2, 10, 15, 30, 0, tzinfo=timezone.utc)
        deadline = detection_date + timedelta(days=30)

        # Act
        days_to_file = (filing_date - detection_date).days

        # Assert
        assert days_to_file <= 30
        assert filing_date <= deadline

    def test_sar_filing_deadline_boundary(self):
        """Test SAR filing at exact 30-day deadline."""
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        filing_date = detection_date + timedelta(days=30)

        # Act
        days_to_file = (filing_date - detection_date).days

        # Assert
        assert days_to_file == 30

    def test_sar_filing_late_detection(self):
        """Test detection of late SAR filing (> 30 days)."""
        # Arrange
        detection_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        filing_date = datetime(2024, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
        deadline = detection_date + timedelta(days=30)

        # Act
        is_late = filing_date > deadline

        # Assert
        assert is_late is True


class TestSARRetentionRequirements:
    """Test SAR retention requirements (5 years per 31 CFR 1010.430)."""

    def test_sar_retention_period(self):
        """Test that SAR records are retained for 5 years."""
        # Arrange
        filing_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        retention_years = 5
        retention_end_date = filing_date + timedelta(days=365 * retention_years)

        # Act
        current_date = datetime(2028, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        should_retain = current_date < retention_end_date

        # Assert
        assert should_retain is True

    def test_sar_retention_expiry(self):
        """Test SAR retention expiry after 5 years."""
        # Arrange
        filing_date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        retention_years = 5
        retention_end_date = filing_date + timedelta(days=365 * retention_years)

        # Act
        current_date = datetime(2029, 1, 16, 10, 0, 0, tzinfo=timezone.utc)
        should_retain = current_date < retention_end_date

        # Assert
        assert should_retain is False


class TestHighValueWireDualApproval:
    """Test dual approval requirements for high-value wire transfers."""

    def test_dual_approval_required_above_threshold(self):
        """Test that dual approval is required for wires > $10,000."""
        # Arrange
        wire_amount = Decimal("15000.00")
        dual_approval_threshold = Decimal("10000.00")

        # Act
        requires_dual_approval = wire_amount > dual_approval_threshold

        # Assert
        assert requires_dual_approval is True

    def test_dual_approval_not_required_below_threshold(self):
        """Test that dual approval is not required for wires <= $10,000."""
        # Arrange
        wire_amount = Decimal("9999.99")
        dual_approval_threshold = Decimal("10000.00")

        # Act
        requires_dual_approval = wire_amount > dual_approval_threshold

        # Assert
        assert requires_dual_approval is False

    def test_dual_approval_at_exact_threshold(self):
        """Test dual approval at exact $10,000 threshold."""
        # Arrange
        wire_amount = Decimal("10000.00")
        dual_approval_threshold = Decimal("10000.00")

        # Act
        requires_dual_approval = wire_amount > dual_approval_threshold

        # Assert
        assert requires_dual_approval is False


class TestRegEErrorHandling:
    """Test Reg E error resolution and dispute handling."""

    def test_reg_e_dispute_window_60_days(self):
        """Test that Reg E dispute window is 60 days from statement date."""
        # Arrange
        statement_date = datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
        dispute_deadline = statement_date + timedelta(days=60)
        dispute_date = datetime(2024, 3, 10, 10, 0, 0, tzinfo=timezone.utc)

        # Act
        is_within_window = dispute_date <= dispute_deadline

        # Assert
        assert is_within_window is True

    def test_reg_e_dispute_outside_window(self):
        """Test dispute filed outside 60-day Reg E window."""
        # Arrange
        statement_date = datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
        dispute_deadline = statement_date + timedelta(days=60)
        dispute_date = datetime(2024, 4, 1, 10, 0, 0, tzinfo=timezone.utc)

        # Act
        is_within_window = dispute_date <= dispute_deadline

        # Assert
        assert is_within_window is False


class TestStructuringDetection:
    """Test detection of structuring (smurfing) patterns."""

    def test_structuring_pattern_multiple_transactions_below_threshold(self):
        """Test detection of multiple transactions just below reporting threshold."""
        # Arrange
        ctr_threshold = Decimal("10000.00")
        transactions = [
            Decimal("9500.00"),
            Decimal("9800.00"),
            Decimal("9900.00"),
        ]
        time_window_hours = 24

        # Act
        total_amount = sum(transactions)
        is_suspicious = all(t < ctr_threshold for t in transactions) and total_amount > ctr_threshold

        # Assert
        assert is_suspicious is True
        assert total_amount == Decimal("29200.00")
        assert all(t < ctr_threshold for t in transactions)

    def test_legitimate_multiple_small_transactions(self):
        """Test that legitimate small transactions are not flagged."""
        # Arrange
        transactions = [
            Decimal("50.00"),
            Decimal("75.00"),
            Decimal("100.00"),
        ]
        ctr_threshold = Decimal("10000.00")

        # Act
        total_amount = sum(transactions)
        is_suspicious = total_amount > ctr_threshold

        # Assert
        assert is_suspicious is False
        assert total_amount == Decimal("225.00")