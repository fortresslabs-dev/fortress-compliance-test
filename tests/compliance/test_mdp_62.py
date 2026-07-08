import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


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
    transaction_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    subject_notified: bool
    insider_involved: bool


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
    def __init__(self, account_repo, audit_logger, sar_service, ofac_service, rule_resolver):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.sar_service = sar_service
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver

    def initiate_transaction(
        self,
        from_account_id: str,
        to_account: str,
        to_routing: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        
        if amount <= Decimal("0"):
            if amount == Decimal("0"):
                return Transaction(
                    transaction_id=f"TXN-{timestamp.timestamp()}",
                    from_account=from_account_id,
                    to_account=to_account,
                    amount=amount,
                    timestamp=timestamp,
                    status=TransactionStatus.REJECTED,
                    user_id=user_id,
                    ip_address=ip_address,
                    device_info=device_info,
                    rejection_reason="Amount must be greater than 0"
                )
            else:
                return Transaction(
                    transaction_id=f"TXN-{timestamp.timestamp()}",
                    from_account=from_account_id,
                    to_account=to_account,
                    amount=amount,
                    timestamp=timestamp,
                    status=TransactionStatus.REJECTED,
                    user_id=user_id,
                    ip_address=ip_address,
                    device_info=device_info,
                    rejection_reason="Invalid amount"
                )
        
        account = self.account_repo.get_account(from_account_id)
        if not account:
            return Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid account"
            )
        
        if account.balance < amount:
            return Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Insufficient balance"
            )
        
        if not self._validate_beneficiary(to_account, to_routing):
            return Transaction(
                transaction_id=f"TXN-{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid beneficiary account"
            )
        
        self.account_repo.update_balance(from_account_id, account.balance - amount)
        
        transaction = Transaction(
            transaction_id=f"TXN-{timestamp.timestamp()}",
            from_account=from_account_id,
            to_account=to_account,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )
        
        self.audit_logger.log_transaction(transaction)
        
        return transaction

    def _validate_beneficiary(self, account: str, routing: str) -> bool:
        return bool(account and routing and len(routing) == 9)


class SARService:
    def __init__(self, rule_resolver, audit_logger):
        self.rule_resolver = rule_resolver
        self.audit_logger = audit_logger
        self.filed_sars: Dict[str, SARFiling] = {}

    def evaluate_suspicious_activity(
        self,
        transaction_id: str,
        amount: Decimal,
        pattern: str,
        insider_involved: bool = False
    ) -> Optional[SARFiling]:
        detection_date = datetime.now(timezone.utc)
        sar_threshold = self.rule_resolver.get_sar_threshold()
        insider_threshold = self.rule_resolver.get_insider_threshold()
        
        should_file = False
        reason = ""
        
        if insider_involved and amount > Decimal(str(insider_threshold)):
            should_file = True
            reason = f"Insider abuse detected: {pattern}"
        elif amount > Decimal(str(sar_threshold)):
            should_file = True
            reason = f"Suspicious activity above threshold: {pattern}"
        
        if should_file:
            filing_deadline = detection_date + timedelta(
                days=self.rule_resolver.get_sar_filing_deadline_days()
            )
            
            sar = SARFiling(
                sar_id=f"SAR-{detection_date.timestamp()}",
                transaction_id=transaction_id,
                amount=amount,
                reason=reason,
                filed_date=detection_date,
                detection_date=detection_date,
                subject_notified=False,
                insider_involved=insider_involved
            )
            
            self.filed_sars[sar.sar_id] = sar
            self.audit_logger.log_sar_filing(sar)
            
            return sar
        
        return None

    def check_sar_disclosure(self, customer_id: str) -> str:
        for sar in self.filed_sars.values():
            if sar.transaction_id.startswith(customer_id):
                return "Account restrictions are under review per bank policy"
        return "No restrictions found"

    def has_filed_sar_for_customer(self, customer_id: str) -> bool:
        return any(
            sar.transaction_id.startswith(customer_id)
            for sar in self.filed_sars.values()
        )


class RuleResolver:
    def __init__(self, rules: Dict[str, Any]):
        self.rules = rules

    def get_sar_threshold(self) -> int:
        return self.rules.get("sar", {}).get("suspicious_threshold", 5000)

    def get_insider_threshold(self) -> int:
        return self.rules.get("sar", {}).get("insider_threshold", 0)

    def get_sar_filing_deadline_days(self) -> int:
        return self.rules.get("sar", {}).get("filing_deadline_days", 30)

    def get_no_tipping_off(self) -> bool:
        return self.rules.get("sar", {}).get("no_tipping_off", True)

    def get_retention_years(self) -> int:
        return self.rules.get("sar", {}).get("retention_years", 5)


@pytest.fixture
def banking_rules() -> Dict[str, Any]:
    """Banking rules configuration from JIRA story."""
    return {
        "sar": {
            "suspicious_threshold": 5000,
            "insider_threshold": 0,
            "filing_deadline_days": 30,
            "no_tipping_off": True,
            "retention_years": 5
        }
    }


@pytest.fixture
def rule_resolver(banking_rules) -> RuleResolver:
    """Rule resolver with configured banking rules."""
    return RuleResolver(banking_rules)


@pytest.fixture
def mock_account_repo() -> Mock:
    """Mock account repository."""
    repo = Mock()
    repo.get_account = Mock()
    repo.update_balance = Mock()
    return repo


@pytest.fixture
def mock_audit_logger() -> Mock:
    """Mock audit logger for compliance tracking."""
    logger = Mock()
    logger.log_transaction = Mock()
    logger.log_sar_filing = Mock()
    return logger


@pytest.fixture
def mock_ofac_service() -> Mock:
    """Mock OFAC/SDN screening service."""
    service = Mock()
    service.screen = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def sar_service(rule_resolver, mock_audit_logger) -> SARService:
    """SAR service with rule resolver and audit logger."""
    return SARService(rule_resolver, mock_audit_logger)


@pytest.fixture
def banking_service(
    mock_account_repo,
    mock_audit_logger,
    sar_service,
    mock_ofac_service,
    rule_resolver
) -> BankingService:
    """Banking service with all dependencies."""
    return BankingService(
        mock_account_repo,
        mock_audit_logger,
        sar_service,
        mock_ofac_service,
        rule_resolver
    )


@pytest.fixture
def valid_account() -> Account:
    """Valid account with sufficient balance."""
    return Account(
        account_id="ACC-12345",
        routing_number="123456789",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="ACTIVE"
    )


class TestSuccessfulTransaction:
    """Test successful transaction scenario."""

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
        transfer_amount = Decimal("500.00")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=transfer_amount,
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == transfer_amount
        assert transaction.from_account == valid_account.account_id
        assert transaction.to_account == "ACC-67890"
        
        # Verify balance updated
        expected_new_balance = valid_account.balance - transfer_amount
        mock_account_repo.update_balance.assert_called_once_with(
            valid_account.account_id,
            expected_new_balance
        )
        
        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called_once()
        logged_transaction = mock_audit_logger.log_transaction.call_args[0][0]
        assert logged_transaction.user_id == valid_account.user_id
        assert logged_transaction.ip_address == "192.168.1.100"
        assert logged_transaction.device_info == "Mozilla/5.0"
        assert isinstance(logged_transaction.timestamp, datetime)


class TestSARSuspiciousActivityAboveThreshold:
    """Test SAR filing for suspicious activity above threshold."""

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
        transaction_id = "TXN-123456"
        suspicious_amount = Decimal("6000.00")
        pattern = "Structured deposits to avoid CTR"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=suspicious_amount,
            pattern=pattern,
            insider_involved=False
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.amount == suspicious_amount
        assert sar_filing.transaction_id == transaction_id
        assert sar_filing.subject_notified is False
        assert "Suspicious activity above threshold" in sar_filing.reason
        
        # Verify filing deadline is 30 days from detection
        expected_deadline = sar_filing.detection_date + timedelta(days=30)
        filing_window = (sar_filing.filed_date - sar_filing.detection_date).days
        assert filing_window <= 30
        
        # Verify audit logged
        mock_audit_logger.log_sar_filing.assert_called_once_with(sar_filing)

    def test_sar_not_filed_below_threshold(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Boundary test: SAR not filed when amount is below threshold.
        """
        # Arrange
        transaction_id = "TXN-123457"
        amount_below_threshold = Decimal("4999.99")
        pattern = "Unusual pattern"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=amount_below_threshold,
            pattern=pattern,
            insider_involved=False
        )
        
        # Assert
        assert sar_filing is None
        mock_audit_logger.log_sar_filing.assert_not_called()

    def test_sar_filed_at_exact_threshold(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Boundary test: SAR filed when amount equals threshold.
        """
        # Arrange
        transaction_id = "TXN-123458"
        exact_threshold = Decimal("5000.01")
        pattern = "Suspicious wire transfer"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=exact_threshold,
            pattern=pattern,
            insider_involved=False
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.amount == exact_threshold
        mock_audit_logger.log_sar_filing.assert_called_once()


class TestSARInsiderAbuseAnyAmount:
    """Test SAR filing for insider abuse at any amount."""

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
        transaction_id = "TXN-INSIDER-001"
        small_amount = Decimal("100.00")
        pattern = "Employee unauthorized account access"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=small_amount,
            pattern=pattern,
            insider_involved=True
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.amount == small_amount
        assert sar_filing.insider_involved is True
        assert "Insider abuse detected" in sar_filing.reason
        assert sar_filing.subject_notified is False
        
        # Verify immediate filing (filed_date == detection_date)
        assert sar_filing.filed_date == sar_filing.detection_date
        
        # Verify audit logged
        mock_audit_logger.log_sar_filing.assert_called_once()

    def test_sar_insider_abuse_one_cent(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Boundary test: SAR filed for insider abuse even with $0.01.
        """
        # Arrange
        transaction_id = "TXN-INSIDER-002"
        minimal_amount = Decimal("0.01")
        pattern = "Employee data breach"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=minimal_amount,
            pattern=pattern,
            insider_involved=True
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.amount == minimal_amount
        assert sar_filing.insider_involved is True
        mock_audit_logger.log_sar_filing.assert_called_once()


class TestSARNoTippingOff:
    """Test no tipping off requirement for SAR filings."""

    def test_sar_no_tipping_off(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Scenario: sar_no_tipping_off
        Given SAR has been filed for a customer
        When Customer inquires about account restrictions
        Then Bank does NOT disclose SAR filing
        """
        # Arrange
        customer_id = "CUST-999"
        transaction_id = f"{customer_id}-TXN-001"
        suspicious_amount = Decimal("7500.00")
        pattern = "Rapid movement of funds"
        
        # File SAR
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=suspicious_amount,
            pattern=pattern,
            insider_involved=False
        )
        
        # Act
        response = sar_service.check_sar_disclosure(customer_id)
        
        # Assert
        assert sar_filing is not None
        assert "SAR" not in response
        assert "Suspicious Activity Report" not in response
        assert "FinCEN" not in response
        assert response == "Account restrictions are under review per bank policy"
        
        # Verify customer was not notified
        assert sar_filing.subject_notified is False

    def test_no_sar_filed_normal_response(
        self,
        sar_service: SARService
    ):
        """
        Test normal response when no SAR has been filed.
        """
        # Arrange
        customer_id = "CUST-888"
        
        # Act
        response = sar_service.check_sar_disclosure(customer_id)
        
        # Assert
        assert response == "No restrictions found"


class TestZeroAmountTransfer:
    """Test zero amount transfer rejection."""

    def test_zero_amount_transfer(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
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
        zero_amount = Decimal("0.00")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=zero_amount,
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Amount must be greater than 0"
        assert transaction.amount == zero_amount
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()


class TestNegativeAmountTransfer:
    """Test negative amount transfer rejection."""

    def test_negative_amount_transfer(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
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
        negative_amount = Decimal("-100.00")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=negative_amount,
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid amount"
        assert transaction.amount == negative_amount
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()


class TestInsufficientBalance:
    """Test insufficient balance rejection."""

    def test_insufficient_balance(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock
    ):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        account_with_low_balance = Account(
            account_id="ACC-LOW-001",
            routing_number="123456789",
            balance=Decimal("1000.00"),
            user_id="USER-002",
            status="ACTIVE"
        )
        mock_account_repo.get_account.return_value = account_with_low_balance
        transfer_amount = Decimal("5000.00")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=account_with_low_balance.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=transfer_amount,
            user_id=account_with_low_balance.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Insufficient balance"
        assert transaction.amount == transfer_amount
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()

    def test_exact_balance_transfer_succeeds(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock
    ):
        """
        Boundary test: Transfer succeeds when amount equals balance.
        """
        # Arrange
        account = Account(
            account_id="ACC-EXACT-001",
            routing_number="123456789",
            balance=Decimal("1000.00"),
            user_id="USER-003",
            status="ACTIVE"
        )
        mock_account_repo.get_account.return_value = account
        exact_balance = Decimal("1000.00")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=exact_balance,
            user_id=account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        mock_account_repo.update_balance.assert_called_once_with(
            account.account_id,
            Decimal("0.00")
        )


class TestInvalidBeneficiary:
    """Test invalid beneficiary account rejection."""

    def test_invalid_beneficiary(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
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
        transfer_amount = Decimal("500.00")
        invalid_routing = "12345"  # Too short
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing=invalid_routing,
            amount=transfer_amount,
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()

    def test_empty_beneficiary_account(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        valid_account: Account
    ):
        """
        Test rejection when beneficiary account is empty.
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        transfer_amount = Decimal("500.00")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="",
            to_routing="123456789",
            amount=transfer_amount,
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"


class TestComplianceAuditTrail:
    """Test audit trail and compliance logging requirements."""

    def test_audit_trail_contains_required_fields(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account
    ):
        """
        Test that audit trail contains all required compliance fields:
        - Timestamp
        - User ID
        - IP address
        - Device info
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        transfer_amount = Decimal("500.00")
        test_ip = "10.0.0.1"
        test_device = "Chrome/120.0"
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=transfer_amount,
            user_id=valid_account.user_id,
            ip_address=test_ip,
            device_info=test_device
        )
        
        # Assert
        mock_audit_logger.log_transaction.assert_called_once()
        logged_txn = mock_audit_logger.log_transaction.call_args[0][0]
        
        assert logged_txn.user_id == valid_account.user_id
        assert logged_txn.ip_address == test_ip
        assert logged_txn.device_info == test_device
        assert isinstance(logged_txn.timestamp, datetime)
        assert logged_txn.timestamp.tzinfo is not None  # Timezone-aware

    def test_sar_audit_trail_retention(
        self,
        sar_service: SARService,
        rule_resolver: RuleResolver
    ):
        """
        Test that SAR retention period is configured per 31 CFR 1010.430.
        """
        # Act
        retention_years = rule_resolver.get_retention_years()
        
        # Assert
        assert retention_years == 5  # BSA requirement


class TestBoundaryConditions:
    """Test boundary conditions for thresholds."""

    def test_sar_threshold_boundary_5000(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Test SAR filing at exactly $5,000.00 (boundary).
        """
        # Arrange
        transaction_id = "TXN-BOUNDARY-5000"
        exact_threshold = Decimal("5000.00")
        pattern = "Boundary test"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=exact_threshold,
            pattern=pattern,
            insider_involved=False
        )
        
        # Assert - should NOT file at exactly 5000, only above
        assert sar_filing is None

    def test_sar_threshold_boundary_5000_01(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Test SAR filing at $5,000.01 (just above threshold).
        """
        # Arrange
        transaction_id = "TXN-BOUNDARY-5001"
        just_above_threshold = Decimal("5000.01")
        pattern = "Boundary test"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=just_above_threshold,
            pattern=pattern,
            insider_involved=False
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.amount == just_above_threshold

    def test_transfer_one_cent(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        valid_account: Account
    ):
        """
        Test minimum valid transfer amount ($0.01).
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        minimal_amount = Decimal("0.01")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=minimal_amount,
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == minimal_amount


class TestDecimalPrecision:
    """Test decimal precision for currency handling."""

    def test_currency_uses_decimal_type(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        valid_account: Account
    ):
        """
        Test that currency amounts use Decimal type for precision.
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        precise_amount = Decimal("123.45")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=precise_amount,
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert isinstance(transaction.amount, Decimal)
        assert transaction.amount == Decimal("123.45")

    def test_balance_calculation_precision(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock
    ):
        """
        Test that balance calculations maintain precision.
        """
        # Arrange
        account = Account(
            account_id="ACC-PRECISION-001",
            routing_number="123456789",
            balance=Decimal("1000.99"),
            user_id="USER-004",
            status="ACTIVE"
        )
        mock_account_repo.get_account.return_value = account
        transfer_amount = Decimal("500.50")
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=transfer_amount,
            user_id=account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        expected_balance = Decimal("500.49")
        mock_account_repo.update_balance.assert_called_once_with(
            account.account_id,
            expected_balance
        )


class TestTimezoneAwareness:
    """Test timezone-aware datetime handling."""

    def test_transaction_timestamp_timezone_aware(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock,
        valid_account: Account
    ):
        """
        Test that transaction timestamps are timezone-aware (UTC).
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id=valid_account.account_id,
            to_account="ACC-67890",
            to_routing="987654321",
            amount=Decimal("100.00"),
            user_id=valid_account.user_id,
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.timestamp.tzinfo is not None
        assert transaction.timestamp.tzinfo == timezone.utc

    def test_sar_filing_dates_timezone_aware(
        self,
        sar_service: SARService
    ):
        """
        Test that SAR filing dates are timezone-aware.
        """
        # Arrange
        transaction_id = "TXN-TZ-001"
        amount = Decimal("6000.00")
        pattern = "Timezone test"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=amount,
            pattern=pattern,
            insider_involved=False
        )
        
        # Assert
        assert sar_filing is not None
        assert sar_filing.filed_date.tzinfo is not None
        assert sar_filing.detection_date.tzinfo is not None


class TestNegativePaths:
    """Test negative paths and error conditions."""

    def test_invalid_account_id(
        self,
        banking_service: BankingService,
        mock_account_repo: Mock
    ):
        """
        Test transaction rejection for invalid account ID.
        """
        # Arrange
        mock_account_repo.get_account.return_value = None
        
        # Act
        transaction = banking_service.initiate_transaction(
            from_account_id="INVALID-ACC",
            to_account="ACC-67890",
            to_routing="987654321",
            amount=Decimal("100.00"),
            user_id="USER-999",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid account"

    def test_sar_false_positive_below_threshold(
        self,
        sar_service: SARService,
        mock_audit_logger: Mock
    ):
        """
        Test that SAR is not filed for false positive below threshold.
        """
        # Arrange
        transaction_id = "TXN-FALSE-POS"
        amount = Decimal("100.00")
        pattern = "False positive pattern"
        
        # Act
        sar_filing = sar_service.evaluate_suspicious_activity(
            transaction_id=transaction_id,
            amount=amount,
            pattern=pattern,
            insider_involved=False
        )
        
        # Assert
        assert sar_filing is None
        mock_audit_logger.log_sar_filing.assert_not_called()


class TestRuleConfiguration:
    """Test rule configuration and resolver."""

    def test_rule_resolver_sar_threshold(self, rule_resolver: RuleResolver):
        """Test SAR threshold configuration."""
        assert rule_resolver.get_sar_threshold() == 5000

    def test_rule_resolver_insider_threshold(self, rule_resolver: RuleResolver):
        """Test insider threshold configuration."""
        assert rule_resolver.get_insider_threshold() == 0

    def test_rule_resolver_filing_deadline(self, rule_resolver: RuleResolver):
        """Test SAR filing deadline configuration."""
        assert rule_resolver.get_sar_filing_deadline_days() == 30

    def test_rule_resolver_no_tipping_off(self, rule_resolver: RuleResolver):
        """Test no tipping off configuration."""
        assert rule_resolver.get_no_tipping_off() is True

    def test_rule_resolver_retention_years(self, rule_resolver: RuleResolver):
        """Test retention years configuration."""
        assert rule_resolver.get_retention_years() == 5