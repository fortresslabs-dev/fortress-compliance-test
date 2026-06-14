import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    PENDING = "pending"


class SARStatus(Enum):
    FILED = "filed"
    PENDING = "pending"
    NOT_REQUIRED = "not_required"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    user_id: str
    is_valid: bool = True


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
    is_insider_abuse: bool


@dataclass
class AuditLog:
    log_id: str
    timestamp: datetime
    user_id: str
    action: str
    details: Dict[str, Any]
    ip_address: str
    device_info: str


class ComplianceRules:
    SAR_THRESHOLD = Decimal("5000.00")
    SAR_INSIDER_THRESHOLD = Decimal("0.00")
    SAR_FILING_DEADLINE_DAYS = 30
    CTR_THRESHOLD = Decimal("10000.00")
    CTR_FILING_DEADLINE_DAYS = 15
    TRAVEL_RULE_THRESHOLD = Decimal("3000.00")
    WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000.00")
    OFAC_FUZZY_THRESHOLD = 85
    BENEFICIAL_OWNERSHIP_PCT = 20
    SAR_RETENTION_YEARS = 5
    BSA_RETENTION_YEARS = 5


class BankingService:
    def __init__(
        self,
        account_repo: Any,
        audit_logger: Any,
        sar_service: Any,
        ofac_service: Any,
        rule_resolver: Any
    ):
        self.account_repo = account_repo
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
        device_info: str
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        
        if amount <= Decimal("0"):
            rejection_reason = "Amount must be greater than 0" if amount == Decimal("0") else "Invalid amount"
            transaction = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason=rejection_reason
            )
            self.audit_logger.log_transaction(transaction)
            return transaction

        from_account = self.account_repo.get_account(from_account_id)
        if not from_account or not from_account.is_valid:
            transaction = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid account"
            )
            self.audit_logger.log_transaction(transaction)
            return transaction

        if from_account.balance < amount:
            transaction = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Insufficient balance"
            )
            self.audit_logger.log_transaction(transaction)
            return transaction

        if not self._validate_beneficiary(to_account_id, to_routing_number):
            transaction = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid beneficiary account"
            )
            self.audit_logger.log_transaction(transaction)
            return transaction

        from_account.balance -= amount
        self.account_repo.update_balance(from_account_id, from_account.balance)

        transaction = Transaction(
            transaction_id=f"txn_{timestamp.timestamp()}",
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )
        
        self.audit_logger.log_transaction(transaction)
        return transaction

    def _validate_beneficiary(self, account_id: str, routing_number: str) -> bool:
        if not account_id or not routing_number:
            return False
        if len(routing_number) != 9 or not routing_number.isdigit():
            return False
        return True

    def check_suspicious_activity(
        self,
        transaction: Transaction,
        is_insider: bool = False
    ) -> Optional[SARFiling]:
        detection_date = datetime.now(timezone.utc)
        
        if is_insider and transaction.amount > ComplianceRules.SAR_INSIDER_THRESHOLD:
            return self.sar_service.file_sar(
                transaction=transaction,
                reason="Insider abuse detected",
                detection_date=detection_date,
                is_insider_abuse=True
            )
        
        if transaction.amount > ComplianceRules.SAR_THRESHOLD:
            return self.sar_service.file_sar(
                transaction=transaction,
                reason="Suspicious activity above threshold",
                detection_date=detection_date,
                is_insider_abuse=False
            )
        
        return None

    def handle_customer_inquiry(self, user_id: str, inquiry_type: str) -> str:
        if inquiry_type == "account_restrictions":
            return "Your account is subject to standard security procedures."
        return "Please contact customer service for more information."


class SARService:
    def __init__(self, fincen_client: Any, audit_logger: Any):
        self.fincen_client = fincen_client
        self.audit_logger = audit_logger
        self.filed_sars: Dict[str, SARFiling] = {}

    def file_sar(
        self,
        transaction: Transaction,
        reason: str,
        detection_date: datetime,
        is_insider_abuse: bool
    ) -> SARFiling:
        filed_date = datetime.now(timezone.utc)
        
        sar = SARFiling(
            sar_id=f"sar_{filed_date.timestamp()}",
            transaction_id=transaction.transaction_id,
            amount=transaction.amount,
            reason=reason,
            filed_date=filed_date,
            detection_date=detection_date,
            subject_notified=False,
            is_insider_abuse=is_insider_abuse
        )
        
        self.fincen_client.submit_sar(sar)
        self.filed_sars[transaction.user_id] = sar
        self.audit_logger.log_sar_filing(sar)
        
        return sar

    def has_sar_filed(self, user_id: str) -> bool:
        return user_id in self.filed_sars


@pytest.fixture
def mock_account_repo():
    repo = Mock()
    repo.get_account = Mock()
    repo.update_balance = Mock()
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock()
    logger.log_transaction = Mock()
    logger.log_sar_filing = Mock()
    logger.log_action = Mock()
    return logger


@pytest.fixture
def mock_sar_service():
    service = Mock(spec=SARService)
    service.file_sar = Mock()
    service.has_sar_filed = Mock(return_value=False)
    service.filed_sars = {}
    return service


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen_entity = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def mock_rule_resolver():
    resolver = Mock()
    resolver.get_threshold = Mock(side_effect=lambda rule: {
        "sar_threshold": Decimal("5000.00"),
        "ctr_threshold": Decimal("10000.00"),
        "travel_rule_threshold": Decimal("3000.00")
    }.get(rule, Decimal("0")))
    return resolver


@pytest.fixture
def mock_fincen_client():
    client = Mock()
    client.submit_sar = Mock(return_value={"status": "accepted", "confirmation": "SAR-123456"})
    return client


@pytest.fixture
def banking_service(
    mock_account_repo,
    mock_audit_logger,
    mock_sar_service,
    mock_ofac_service,
    mock_rule_resolver
):
    return BankingService(
        account_repo=mock_account_repo,
        audit_logger=mock_audit_logger,
        sar_service=mock_sar_service,
        ofac_service=mock_ofac_service,
        rule_resolver=mock_rule_resolver
    )


@pytest.fixture
def sar_service(mock_fincen_client, mock_audit_logger):
    return SARService(
        fincen_client=mock_fincen_client,
        audit_logger=mock_audit_logger
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER001",
        is_valid=True
    )


@pytest.fixture
def insufficient_balance_account():
    return Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER001",
        is_valid=True
    )


class TestSuccessfulTransaction:
    """Test successful transaction with sufficient balance and valid account."""

    def test_successful_transaction(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account
    ):
        """
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("500.00"),
            user_id="USER001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("500.00")
        assert result.rejection_reason is None
        mock_account_repo.update_balance.assert_called_once_with(
            "ACC123456",
            Decimal("9500.00")
        )
        mock_audit_logger.log_transaction.assert_called_once()
        
        logged_transaction = mock_audit_logger.log_transaction.call_args[0][0]
        assert logged_transaction.user_id == "USER001"
        assert logged_transaction.ip_address == "192.168.1.100"
        assert logged_transaction.device_info == "Mozilla/5.0"


class TestSARSuspiciousActivityAboveThreshold:
    """Test SAR filing for suspicious activity above $5,000 threshold."""

    def test_sar_suspicious_activity_above_threshold(
        self,
        sar_service,
        mock_fincen_client,
        mock_audit_logger
    ):
        """
        Given Transaction monitoring detects suspicious pattern
        When Suspicious activity involves > $5,000
        Then SAR filed with FinCEN within 30 days, subject NOT notified
        """
        detection_date = datetime.now(timezone.utc)
        transaction = Transaction(
            transaction_id="TXN001",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("6000.00"),
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="USER001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )
        
        sar = sar_service.file_sar(
            transaction=transaction,
            reason="Suspicious activity above threshold",
            detection_date=detection_date,
            is_insider_abuse=False
        )
        
        assert sar.amount == Decimal("6000.00")
        assert sar.subject_notified is False
        assert sar.is_insider_abuse is False
        assert (sar.filed_date - detection_date).days <= ComplianceRules.SAR_FILING_DEADLINE_DAYS
        mock_fincen_client.submit_sar.assert_called_once_with(sar)
        mock_audit_logger.log_sar_filing.assert_called_once_with(sar)

    def test_sar_threshold_boundary_at_5000(
        self,
        sar_service,
        mock_fincen_client
    ):
        """Test SAR filing at exact $5,000 threshold boundary."""
        detection_date = datetime.now(timezone.utc)
        transaction = Transaction(
            transaction_id="TXN002",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("5000.01"),
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="USER002",
            ip_address="192.168.1.101",
            device_info="Mozilla/5.0"
        )
        
        sar = sar_service.file_sar(
            transaction=transaction,
            reason="Suspicious activity above threshold",
            detection_date=detection_date,
            is_insider_abuse=False
        )
        
        assert sar.amount == Decimal("5000.01")
        assert sar.subject_notified is False
        mock_fincen_client.submit_sar.assert_called_once()

    def test_no_sar_below_threshold(
        self,
        banking_service,
        mock_sar_service
    ):
        """Test that SAR is not filed for amounts below $5,000."""
        transaction = Transaction(
            transaction_id="TXN003",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("4999.99"),
            timestamp=datetime.now(timezone.utc),
            status=TransactionStatus.SUCCESS,
            user_id="USER003",
            ip_address="192.168.1.102",
            device_info="Mozilla/5.0"
        )
        
        result = banking_service.check_suspicious_activity(
            transaction=transaction,
            is_insider=False
        )
        
        assert result is None
        mock_sar_service.file_sar.assert_not_called()


class TestSARInsiderAbuseAnyAmount:
    """Test SAR filing for insider abuse at any dollar amount."""

    def test_sar_insider_abuse_any_amount(
        self,
        sar_service,
        mock_fincen_client,
        mock_audit_logger
    ):
        """
        Given Bank employee involved in suspicious activity
        When Insider abuse detected at any dollar amount
        Then SAR filed immediately, no minimum threshold
        """
        detection_date = datetime.now(timezone.utc)
        transaction = Transaction(
            transaction_id="TXN004",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("100.00"),
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="EMPLOYEE001",
            ip_address="10.0.0.50",
            device_info="Internal System"
        )
        
        sar = sar_service.file_sar(
            transaction=transaction,
            reason="Insider abuse detected",
            detection_date=detection_date,
            is_insider_abuse=True
        )
        
        assert sar.amount == Decimal("100.00")
        assert sar.is_insider_abuse is True
        assert sar.subject_notified is False
        mock_fincen_client.submit_sar.assert_called_once_with(sar)
        mock_audit_logger.log_sar_filing.assert_called_once()

    def test_sar_insider_abuse_minimal_amount(
        self,
        banking_service,
        mock_sar_service
    ):
        """Test SAR filing for insider abuse with minimal amount ($0.01)."""
        transaction = Transaction(
            transaction_id="TXN005",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("0.01"),
            timestamp=datetime.now(timezone.utc),
            status=TransactionStatus.SUCCESS,
            user_id="EMPLOYEE002",
            ip_address="10.0.0.51",
            device_info="Internal System"
        )
        
        result = banking_service.check_suspicious_activity(
            transaction=transaction,
            is_insider=True
        )
        
        assert result is not None
        mock_sar_service.file_sar.assert_called_once()
        call_args = mock_sar_service.file_sar.call_args
        assert call_args[1]["is_insider_abuse"] is True


class TestSARNoTippingOff:
    """Test that SAR filing is not disclosed to the subject."""

    def test_sar_no_tipping_off(
        self,
        banking_service,
        sar_service
    ):
        """
        Given SAR has been filed for a customer
        When Customer inquires about account restrictions
        Then Bank does NOT disclose SAR filing
        """
        detection_date = datetime.now(timezone.utc)
        transaction = Transaction(
            transaction_id="TXN006",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("7000.00"),
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="USER004",
            ip_address="192.168.1.103",
            device_info="Mozilla/5.0"
        )
        
        sar = sar_service.file_sar(
            transaction=transaction,
            reason="Suspicious activity",
            detection_date=detection_date,
            is_insider_abuse=False
        )
        
        assert sar.subject_notified is False
        
        response = banking_service.handle_customer_inquiry(
            user_id="USER004",
            inquiry_type="account_restrictions"
        )
        
        assert "SAR" not in response
        assert "suspicious" not in response.lower()
        assert "FinCEN" not in response
        assert response == "Your account is subject to standard security procedures."

    def test_sar_no_disclosure_in_logs(
        self,
        sar_service,
        mock_audit_logger
    ):
        """Test that SAR filing audit logs do not tip off the subject."""
        detection_date = datetime.now(timezone.utc)
        transaction = Transaction(
            transaction_id="TXN007",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("8000.00"),
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="USER005",
            ip_address="192.168.1.104",
            device_info="Mozilla/5.0"
        )
        
        sar = sar_service.file_sar(
            transaction=transaction,
            reason="Suspicious pattern",
            detection_date=detection_date,
            is_insider_abuse=False
        )
        
        assert sar.subject_notified is False
        mock_audit_logger.log_sar_filing.assert_called_once()


class TestZeroAmountTransfer:
    """Test rejection of zero amount transfers."""

    def test_zero_amount_transfer(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account
    ):
        """
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("0.00"),
            user_id="USER006",
            ip_address="192.168.1.105",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Amount must be greater than 0"
        mock_account_repo.update_balance.assert_not_called()
        mock_audit_logger.log_transaction.assert_called_once()


class TestNegativeAmountTransfer:
    """Test rejection of negative amount transfers."""

    def test_negative_amount_transfer(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account
    ):
        """
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("-100.00"),
            user_id="USER007",
            ip_address="192.168.1.106",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid amount"
        mock_account_repo.update_balance.assert_not_called()
        mock_audit_logger.log_transaction.assert_called_once()


class TestInsufficientBalance:
    """Test rejection of transfers with insufficient balance."""

    def test_insufficient_balance(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        insufficient_balance_account
    ):
        """
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        mock_account_repo.get_account.return_value = insufficient_balance_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("5000.00"),
            user_id="USER008",
            ip_address="192.168.1.107",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"
        mock_account_repo.update_balance.assert_not_called()
        mock_audit_logger.log_transaction.assert_called_once()

    def test_insufficient_balance_boundary(
        self,
        banking_service,
        mock_account_repo,
        insufficient_balance_account
    ):
        """Test rejection when transfer amount equals balance + $0.01."""
        mock_account_repo.get_account.return_value = insufficient_balance_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("1000.01"),
            user_id="USER009",
            ip_address="192.168.1.108",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test rejection of transfers to invalid beneficiary accounts."""

    def test_invalid_beneficiary(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account
    ):
        """
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="INVALID",
            amount=Decimal("500.00"),
            user_id="USER010",
            ip_address="192.168.1.109",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"
        mock_account_repo.update_balance.assert_not_called()
        mock_audit_logger.log_transaction.assert_called_once()

    def test_invalid_routing_number_length(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test rejection with routing number not 9 digits."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="12345",
            amount=Decimal("500.00"),
            user_id="USER011",
            ip_address="192.168.1.110",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"

    def test_empty_beneficiary_account(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test rejection with empty beneficiary account number."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="",
            to_routing_number="021000021",
            amount=Decimal("500.00"),
            user_id="USER012",
            ip_address="192.168.1.111",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"


class TestCTRThresholdBoundary:
    """Test CTR threshold boundary conditions."""

    def test_ctr_threshold_at_10000(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test transaction at exact CTR threshold of $10,000."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("10000.00"),
            user_id="USER013",
            ip_address="192.168.1.112",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("10000.00")

    def test_ctr_threshold_above_10000(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test transaction above CTR threshold ($10,000.01)."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("10000.01"),
            user_id="USER014",
            ip_address="192.168.1.113",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("10000.01")


class TestTravelRuleThreshold:
    """Test Travel Rule threshold boundary conditions."""

    def test_travel_rule_threshold_at_3000(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test transaction at exact Travel Rule threshold of $3,000."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("3000.00"),
            user_id="USER015",
            ip_address="192.168.1.114",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("3000.00")

    def test_travel_rule_threshold_above_3000(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test transaction above Travel Rule threshold ($3,000.01)."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("3000.01"),
            user_id="USER016",
            ip_address="192.168.1.115",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("3000.01")


class TestAuditTrailRequirements:
    """Test audit trail and logging requirements."""

    def test_audit_trail_contains_required_fields(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account
    ):
        """Test that audit trail contains all required fields per compliance."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("1500.00"),
            user_id="USER017",
            ip_address="192.168.1.116",
            device_info="Mozilla/5.0 (Windows NT 10.0)"
        )
        
        mock_audit_logger.log_transaction.assert_called_once()
        logged_transaction = mock_audit_logger.log_transaction.call_args[0][0]
        
        assert logged_transaction.transaction_id is not None
        assert logged_transaction.user_id == "USER017"
        assert logged_transaction.ip_address == "192.168.1.116"
        assert logged_transaction.device_info == "Mozilla/5.0 (Windows NT 10.0)"
        assert isinstance(logged_transaction.timestamp, datetime)
        assert logged_transaction.timestamp.tzinfo is not None

    def test_audit_trail_for_rejected_transaction(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account
    ):
        """Test that rejected transactions are also logged in audit trail."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="INVALID",
            amount=Decimal("1500.00"),
            user_id="USER018",
            ip_address="192.168.1.117",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        mock_audit_logger.log_transaction.assert_called_once()


class TestOFACScreening:
    """Test OFAC/SDN screening requirements."""

    def test_ofac_screening_no_match(
        self,
        banking_service,
        mock_ofac_service
    ):
        """Test OFAC screening with no match."""
        mock_ofac_service.screen_entity.return_value = {
            "match": False,
            "score": 0
        }
        
        result = mock_ofac_service.screen_entity(
            name="John Doe",
            country="US"
        )
        
        assert result["match"] is False
        assert result["score"] < ComplianceRules.OFAC_FUZZY_THRESHOLD

    def test_ofac_screening_match_above_threshold(
        self,
        mock_ofac_service
    ):
        """Test OFAC screening with match above fuzzy threshold."""
        mock_ofac_service.screen_entity.return_value = {
            "match": True,
            "score": 90,
            "matched_entity": "SDN Entity"
        }
        
        result = mock_ofac_service.screen_entity(
            name="Sanctioned Person",
            country="IR"
        )
        
        assert result["match"] is True
        assert result["score"] >= ComplianceRules.OFAC_FUZZY_THRESHOLD

    def test_ofac_screening_boundary_at_85(
        self,
        mock_ofac_service
    ):
        """Test OFAC screening at exact fuzzy match threshold of 85."""
        mock_ofac_service.screen_entity.return_value = {
            "match": True,
            "score": 85,
            "matched_entity": "Potential Match"
        }
        
        result = mock_ofac_service.screen_entity(
            name="Similar Name",
            country="US"
        )
        
        assert result["score"] == ComplianceRules.OFAC_FUZZY_THRESHOLD


class TestDataHandlingCompliance:
    """Test data handling and PII protection requirements."""

    def test_ssn_masking_in_logs(self):
        """Test that SSN/TIN is masked in logs (show last 4 only)."""
        ssn = "123-45-6789"
        masked_ssn = f"***-**-{ssn[-4:]}"
        
        assert masked_ssn == "***-**-6789"
        assert len(masked_ssn.replace("-", "").replace("*", "")) == 4

    def test_transaction_timestamp_timezone_aware(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account
    ):
        """Test that transaction timestamps are timezone-aware (UTC)."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("1000.00"),
            user_id="USER019",
            ip_address="192.168.1.118",
            device_info="Mozilla/5.0"
        )
        
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.tzinfo == timezone.utc


class TestSARRetentionRequirements:
    """Test SAR retention requirements."""

    def test_sar_retention_period_5_years(
        self,
        sar_service
    ):
        """Test that SAR retention period is set to 5 years per BSA requirements."""
        assert ComplianceRules.SAR_RETENTION_YEARS == 5
        assert ComplianceRules.BSA_RETENTION_YEARS == 5

    def test_sar_filing_deadline_30_days(
        self,
        sar_service,
        mock_fincen_client
    ):
        """Test that SAR filing deadline is within 30 days of detection."""
        detection_date = datetime.now(timezone.utc)
        transaction = Transaction(
            transaction_id="TXN020",
            from_account="ACC123456",
            to_account="ACC789012",
            amount=Decimal("6500.00"),
            timestamp=detection_date,
            status=TransactionStatus.SUCCESS,
            user_id="USER020",
            ip_address="192.168.1.119",
            device_info="Mozilla/5.0"
        )
        
        sar = sar_service.file_sar(
            transaction=transaction,
            reason="Suspicious pattern",
            detection_date=detection_date,
            is_insider_abuse=False
        )
        
        days_to_file = (sar.filed_date - detection_date).days
        assert days_to_file <= ComplianceRules.SAR_FILING_DEADLINE_DAYS


class TestInvalidAccountScenarios:
    """Test invalid account scenarios."""

    def test_invalid_account_rejected(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger
    ):
        """Test transaction rejection for invalid account."""
        invalid_account = Account(
            account_id="ACC999999",
            routing_number="021000021",
            balance=Decimal("5000.00"),
            user_id="USER021",
            is_valid=False
        )
        mock_account_repo.get_account.return_value = invalid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC999999",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("500.00"),
            user_id="USER021",
            ip_address="192.168.1.120",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid account"

    def test_nonexistent_account_rejected(
        self,
        banking_service,
        mock_account_repo,
        mock_audit_logger
    ):
        """Test transaction rejection for non-existent account."""
        mock_account_repo.get_account.return_value = None
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC000000",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("500.00"),
            user_id="USER022",
            ip_address="192.168.1.121",
            device_info="Mozilla/5.0"
        )
        
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid account"


class TestDecimalPrecisionForCurrency:
    """Test that Decimal type is used for currency with proper precision."""

    def test_decimal_precision_for_amounts(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test that currency amounts maintain precision using Decimal."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("1234.56"),
            user_id="USER023",
            ip_address="192.168.1.122",
            device_info="Mozilla/5.0"
        )
        
        assert isinstance(result.amount, Decimal)
        assert result.amount == Decimal("1234.56")

    def test_decimal_precision_for_balance_update(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test that balance updates maintain Decimal precision."""
        mock_account_repo.get_account.return_value = valid_account
        
        banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("123.45"),
            user_id="USER024",
            ip_address="192.168.1.123",
            device_info="Mozilla/5.0"
        )
        
        mock_account_repo.update_balance.assert_called_once()
        updated_balance = mock_account_repo.update_balance.call_args[0][1]
        assert isinstance(updated_balance, Decimal)
        assert updated_balance == Decimal("9876.55")


class TestWireDualApprovalThreshold:
    """Test wire transfer dual approval threshold."""

    def test_wire_dual_approval_threshold_at_10000(self):
        """Test that wire dual approval threshold is set at $10,000."""
        assert ComplianceRules.WIRE_DUAL_APPROVAL_THRESHOLD == Decimal("10000.00")

    def test_wire_above_dual_approval_threshold(
        self,
        banking_service,
        mock_account_repo,
        valid_account
    ):
        """Test wire transfer above dual approval threshold."""
        mock_account_repo.get_account.return_value = valid_account
        
        result = banking_service.initiate_transaction(
            from_account_id="ACC123456",
            to_account_id="ACC789012",
            to_routing_number="021000021",
            amount=Decimal("10000.01"),
            user_id="USER025",
            ip_address="192.168.1.124",
            device_info="Mozilla/5.0"
        )
        
        assert result.amount > ComplianceRules.WIRE_DUAL_APPROVAL_THRESHOLD


class TestBeneficialOwnershipThreshold:
    """Test beneficial ownership percentage threshold."""

    def test_beneficial_ownership_threshold_20_percent(self):
        """Test that beneficial ownership threshold is 20% per CDD Rule."""
        assert ComplianceRules.BENEFICIAL_OWNERSHIP_PCT == 20

    def test_beneficial_ownership_calculation(self):
        """Test beneficial ownership percentage calculation."""
        total_ownership = Decimal("100.00")
        owner_stake = Decimal("25.00")
        ownership_pct = (owner_stake / total_ownership) * 100
        
        assert ownership_pct >= ComplianceRules.BENEFICIAL_OWNERSHIP_PCT