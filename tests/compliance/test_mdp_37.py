import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    PENDING_REVIEW = "PENDING_REVIEW"


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
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    device_info: Optional[str] = None


@dataclass
class SARFiling:
    sar_id: str
    transaction_id: Optional[str]
    customer_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    is_insider: bool
    subject_notified: bool = False


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
        to_routing: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        
        # Validate amount
        if amount == Decimal("0"):
            txn = Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Amount must be greater than 0",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(txn)
            return txn
        
        if amount < Decimal("0"):
            txn = Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid amount",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(txn)
            return txn
        
        # Get accounts
        from_account = self.account_repo.get_account(from_account_id)
        if not from_account or not from_account.is_valid:
            txn = Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid account",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(txn)
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
                rejection_reason="Insufficient balance",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(txn)
            return txn
        
        # Validate beneficiary
        if not self.account_repo.validate_beneficiary(to_account_id, to_routing):
            txn = Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(txn)
            return txn
        
        # Process transaction
        new_balance = from_account.balance - amount
        self.account_repo.update_balance(from_account_id, new_balance)
        
        txn = Transaction(
            transaction_id=f"TXN-{timestamp.timestamp()}",
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )
        
        self.audit_logger.log_transaction(txn)
        return txn

    def handle_customer_inquiry(self, customer_id: str, inquiry_type: str) -> str:
        if inquiry_type == "account_restrictions":
            # Never disclose SAR filing per 31 USC 5318(g)(2)
            return "Your account is subject to standard monitoring procedures."
        return "General inquiry response"


class SARService:
    def __init__(self, rule_resolver, audit_logger):
        self.rule_resolver = rule_resolver
        self.audit_logger = audit_logger
        self.filed_sars = {}

    def evaluate_and_file_sar(
        self,
        customer_id: str,
        amount: Decimal,
        reason: str,
        is_insider: bool = False,
        transaction_id: Optional[str] = None
    ) -> Optional[SARFiling]:
        detection_date = datetime.now(timezone.utc)
        
        # Insider abuse - file immediately at any amount
        if is_insider:
            sar = SARFiling(
                sar_id=f"SAR-{detection_date.timestamp()}",
                transaction_id=transaction_id,
                customer_id=customer_id,
                amount=amount,
                reason=reason,
                filed_date=detection_date,
                detection_date=detection_date,
                is_insider=True,
                subject_notified=False
            )
            self.filed_sars[sar.sar_id] = sar
            self.audit_logger.log_sar_filing(sar)
            return sar
        
        # Suspicious activity threshold
        sar_threshold = self.rule_resolver.get_sar_threshold()
        if amount > sar_threshold:
            filing_deadline = detection_date + timedelta(days=30)
            sar = SARFiling(
                sar_id=f"SAR-{detection_date.timestamp()}",
                transaction_id=transaction_id,
                customer_id=customer_id,
                amount=amount,
                reason=reason,
                filed_date=detection_date,
                detection_date=detection_date,
                is_insider=False,
                subject_notified=False
            )
            self.filed_sars[sar.sar_id] = sar
            self.audit_logger.log_sar_filing(sar)
            return sar
        
        return None

    def is_sar_filed_for_customer(self, customer_id: str) -> bool:
        return any(sar.customer_id == customer_id for sar in self.filed_sars.values())


class RuleResolver:
    def __init__(self, rules: Dict[str, Any]):
        self.rules = rules

    def get_sar_threshold(self) -> Decimal:
        return Decimal(str(self.rules.get("sar", {}).get("suspicious_threshold", 5000)))

    def get_insider_threshold(self) -> Decimal:
        return Decimal(str(self.rules.get("sar", {}).get("insider_threshold", 0)))

    def get_sar_filing_deadline_days(self) -> int:
        return self.rules.get("sar", {}).get("filing_deadline_days", 30)

    def get_no_tipping_off(self) -> bool:
        return self.rules.get("sar", {}).get("no_tipping_off", True)

    def get_ctr_threshold(self) -> Decimal:
        return Decimal("10000")

    def get_travel_rule_threshold(self) -> Decimal:
        return Decimal("3000")


# Fixtures

@pytest.fixture
def banking_rules() -> Dict[str, Any]:
    return {
        "sar": {
            "suspicious_threshold": 5000,
            "insider_threshold": 0,
            "filing_deadline_days": 30,
            "no_tipping_off": True,
            "retention_years": 5
        },
        "kyc_cdd": {
            "cip_required": True,
            "cdd_beneficial_ownership": True,
            "edd_high_risk": True,
            "beneficial_ownership_threshold_pct": 25
        }
    }


@pytest.fixture
def rule_resolver(banking_rules) -> RuleResolver:
    return RuleResolver(banking_rules)


@pytest.fixture
def mock_account_repo() -> Mock:
    repo = Mock()
    repo.get_account = Mock()
    repo.update_balance = Mock()
    repo.validate_beneficiary = Mock()
    return repo


@pytest.fixture
def mock_audit_logger() -> Mock:
    logger = Mock()
    logger.log_transaction = Mock()
    logger.log_sar_filing = Mock()
    logger.log_action = Mock()
    return logger


@pytest.fixture
def mock_ofac_service() -> Mock:
    service = Mock()
    service.screen = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def sar_service(rule_resolver, mock_audit_logger) -> SARService:
    return SARService(rule_resolver, mock_audit_logger)


@pytest.fixture
def banking_service(
    mock_account_repo,
    mock_audit_logger,
    sar_service,
    mock_ofac_service,
    rule_resolver
) -> BankingService:
    return BankingService(
        mock_account_repo,
        mock_audit_logger,
        sar_service,
        mock_ofac_service,
        rule_resolver
    )


@pytest.fixture
def valid_account() -> Account:
    return Account(
        account_id="ACC-12345",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        customer_id="CUST-001",
        is_valid=True
    )


@pytest.fixture
def low_balance_account() -> Account:
    return Account(
        account_id="ACC-67890",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        customer_id="CUST-002",
        is_valid=True
    )


# Test Cases

class TestSuccessfulTransaction:
    """Test successful transaction with sufficient balance and valid account."""

    def test_successful_transaction(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        
        from_account = "ACC-12345"
        to_account = "ACC-99999"
        to_routing = "021000022"
        amount = Decimal("500.00")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"
        
        # Act
        result = banking_service.initiate_transaction(
            from_account,
            to_account,
            to_routing,
            amount,
            user_id,
            ip_address,
            device_info
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == amount
        assert result.from_account == from_account
        assert result.to_account == to_account
        assert result.user_id == user_id
        assert result.ip_address == ip_address
        assert result.device_info == device_info
        assert result.rejection_reason is None
        
        # Verify balance updated
        expected_new_balance = valid_account.balance - amount
        mock_account_repo.update_balance.assert_called_once_with(from_account, expected_new_balance)
        
        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called_once()
        logged_txn = mock_audit_logger.log_transaction.call_args[0][0]
        assert logged_txn.status == TransactionStatus.SUCCESS
        assert logged_txn.user_id == user_id
        assert logged_txn.ip_address == ip_address


class TestSARSuspiciousActivityAboveThreshold:
    """Test SAR filing for suspicious activity above $5,000 threshold."""

    def test_sar_suspicious_activity_above_threshold(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock,
        rule_resolver: RuleResolver
    ):
        """
        Scenario: sar_suspicious_activity_above_threshold
        Given Transaction monitoring detects suspicious pattern
        When Suspicious activity involves > $5,000
        Then SAR filed with FinCEN within 30 days, subject NOT notified
        """
        # Arrange
        customer_id = "CUST-SUSPICIOUS-001"
        amount = Decimal("6000.00")
        reason = "Structuring detected - multiple deposits just under CTR threshold"
        transaction_id = "TXN-123456"
        
        # Act
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=False,
            transaction_id=transaction_id
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.customer_id == customer_id
        assert sar_filing.amount == amount
        assert sar_filing.reason == reason
        assert sar_filing.subject_notified is False
        assert sar_filing.is_insider is False
        
        # Verify filing deadline is within 30 days
        deadline = sar_filing.detection_date + timedelta(days=30)
        assert sar_filing.filed_date <= deadline
        
        # Verify audit logged
        mock_audit_logger.log_sar_filing.assert_called_once_with(sar_filing)

    def test_sar_at_exact_threshold(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """Test SAR filing at exact $5,000 threshold (boundary test)."""
        # Arrange
        customer_id = "CUST-BOUNDARY-001"
        amount = Decimal("5000.00")
        reason = "Suspicious pattern at threshold"
        
        # Act
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=False
        )
        
        # Assert - at threshold, should not file (> $5,000 required)
        assert sar_filing is None

    def test_sar_just_above_threshold(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """Test SAR filing just above $5,000 threshold (boundary test)."""
        # Arrange
        customer_id = "CUST-BOUNDARY-002"
        amount = Decimal("5000.01")
        reason = "Suspicious pattern just above threshold"
        
        # Act
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=False
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.amount == amount
        assert sar_filing.subject_notified is False


class TestSARInsiderAbuseAnyAmount:
    """Test SAR filing for insider abuse at any dollar amount."""

    def test_sar_insider_abuse_any_amount(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Scenario: sar_insider_abuse_any_amount
        Given Bank employee involved in suspicious activity
        When Insider abuse detected at any dollar amount
        Then SAR filed immediately, no minimum threshold
        """
        # Arrange
        customer_id = "EMP-INSIDER-001"
        amount = Decimal("100.00")  # Well below normal threshold
        reason = "Employee unauthorized access to customer accounts"
        
        # Act
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=True
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.customer_id == customer_id
        assert sar_filing.amount == amount
        assert sar_filing.is_insider is True
        assert sar_filing.subject_notified is False
        
        # Verify filed immediately (filed_date == detection_date)
        assert sar_filing.filed_date == sar_filing.detection_date
        
        # Verify audit logged
        mock_audit_logger.log_sar_filing.assert_called_once()

    def test_sar_insider_abuse_zero_amount(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """Test SAR filing for insider abuse with zero amount (boundary test)."""
        # Arrange
        customer_id = "EMP-INSIDER-002"
        amount = Decimal("0.00")
        reason = "Employee data breach - no monetary transaction"
        
        # Act
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=True
        )
        
        # Assert - insider abuse filed even at $0
        assert sar_filing is not None
        assert sar_filing.is_insider is True
        assert sar_filing.amount == Decimal("0.00")

    def test_sar_insider_abuse_large_amount(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """Test SAR filing for insider abuse with large amount."""
        # Arrange
        customer_id = "EMP-INSIDER-003"
        amount = Decimal("50000.00")
        reason = "Employee embezzlement"
        
        # Act
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=True
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.is_insider is True
        assert sar_filing.subject_notified is False


class TestSARNoTippingOff:
    """Test that bank does not disclose SAR filing to customer (31 USC 5318(g)(2))."""

    def test_sar_no_tipping_off(
        self,
        banking_service: BankingService,
        sar_service: SARService
    ):
        """
        Scenario: sar_no_tipping_off
        Given SAR has been filed for a customer
        When Customer inquires about account restrictions
        Then Bank does NOT disclose SAR filing
        """
        # Arrange
        customer_id = "CUST-SAR-001"
        amount = Decimal("10000.00")
        reason = "Suspicious wire transfers"
        
        # File SAR
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=False
        )
        assert sar_filing is not None
        assert sar_filing.subject_notified is False
        
        # Act - customer inquires
        response = banking_service.handle_customer_inquiry(
            customer_id=customer_id,
            inquiry_type="account_restrictions"
        )
        
        # Assert - response does not mention SAR
        assert "SAR" not in response
        assert "Suspicious Activity Report" not in response
        assert "FinCEN" not in response
        assert "standard monitoring" in response.lower()

    def test_sar_filing_never_notifies_subject(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """Test that SAR filing always sets subject_notified to False."""
        # Arrange
        customer_id = "CUST-SAR-002"
        amount = Decimal("7500.00")
        reason = "Multiple cash deposits"
        
        # Act
        sar_filing = sar_service.evaluate_and_file_sar(
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            is_insider=False
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.subject_notified is False


class TestZeroAmountTransfer:
    """Test rejection of zero-amount transfers."""

    def test_zero_amount_transfer(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account
    ):
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        
        from_account = "ACC-12345"
        to_account = "ACC-99999"
        to_routing = "021000022"
        amount = Decimal("0")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"
        
        # Act
        result = banking_service.initiate_transaction(
            from_account,
            to_account,
            to_routing,
            amount,
            user_id,
            ip_address,
            device_info
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Amount must be greater than 0"
        assert result.amount == Decimal("0")
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()
        
        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called_once()


class TestNegativeAmountTransfer:
    """Test rejection of negative-amount transfers."""

    def test_negative_amount_transfer(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account
    ):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        
        from_account = "ACC-12345"
        to_account = "ACC-99999"
        to_routing = "021000022"
        amount = Decimal("-100.00")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"
        
        # Act
        result = banking_service.initiate_transaction(
            from_account,
            to_account,
            to_routing,
            amount,
            user_id,
            ip_address,
            device_info
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid amount"
        assert result.amount == Decimal("-100.00")
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()
        
        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called_once()

    def test_large_negative_amount(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        valid_account: Account
    ):
        """Test rejection of large negative amount (boundary test)."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        amount = Decimal("-999999.99")
        
        # Act
        result = banking_service.initiate_transaction(
            "ACC-12345",
            "ACC-99999",
            "021000022",
            amount,
            "USER-001",
            "192.168.1.100",
            "Mozilla/5.0"
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid amount"


class TestInsufficientBalance:
    """Test rejection of transactions with insufficient balance."""

    def test_insufficient_balance(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        low_balance_account: Account
    ):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        mock_account_repo.get_account.return_value = low_balance_account
        mock_account_repo.validate_beneficiary.return_value = True
        
        from_account = "ACC-67890"
        to_account = "ACC-99999"
        to_routing = "021000022"
        amount = Decimal("5000.00")
        user_id = "USER-002"
        ip_address = "192.168.1.101"
        device_info = "Mozilla/5.0"
        
        # Act
        result = banking_service.initiate_transaction(
            from_account,
            to_account,
            to_routing,
            amount,
            user_id,
            ip_address,
            device_info
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"
        assert result.amount == amount
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()
        
        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called_once()

    def test_insufficient_balance_by_one_cent(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        low_balance_account: Account
    ):
        """Test insufficient balance by one cent (boundary test)."""
        # Arrange
        mock_account_repo.get_account.return_value = low_balance_account
        mock_account_repo.validate_beneficiary.return_value = True
        amount = Decimal("1000.01")  # Balance is 1000.00
        
        # Act
        result = banking_service.initiate_transaction(
            "ACC-67890",
            "ACC-99999",
            "021000022",
            amount,
            "USER-002",
            "192.168.1.101",
            "Mozilla/5.0"
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"

    def test_exact_balance_transfer(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        low_balance_account: Account
    ):
        """Test transfer of exact account balance (boundary test)."""
        # Arrange
        mock_account_repo.get_account.return_value = low_balance_account
        mock_account_repo.validate_beneficiary.return_value = True
        amount = Decimal("1000.00")  # Exact balance
        
        # Act
        result = banking_service.initiate_transaction(
            "ACC-67890",
            "ACC-99999",
            "021000022",
            amount,
            "USER-002",
            "192.168.1.101",
            "Mozilla/5.0"
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.rejection_reason is None
        mock_account_repo.update_balance.assert_called_once_with("ACC-67890", Decimal("0.00"))


class TestInvalidBeneficiary:
    """Test rejection of transactions with invalid beneficiary account."""

    def test_invalid_beneficiary(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = False
        
        from_account = "ACC-12345"
        to_account = "ACC-INVALID"
        to_routing = "999999999"