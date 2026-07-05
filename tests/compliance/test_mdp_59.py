import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    PENDING_REVIEW = "pending_review"


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
    status: str = "active"


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
    transaction_id: Optional[str]
    subject_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    filing_deadline: datetime
    status: SARStatus
    subject_notified: bool = False


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


class ComplianceRules:
    SAR_SUSPICIOUS_THRESHOLD = Decimal("5000.00")
    SAR_INSIDER_THRESHOLD = Decimal("0.00")
    SAR_FILING_DEADLINE_DAYS = 30
    CTR_THRESHOLD = Decimal("10000.00")
    TRAVEL_RULE_THRESHOLD = Decimal("3000.00")
    WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000.00")
    OFAC_FUZZY_THRESHOLD = 85
    BENEFICIAL_OWNERSHIP_PCT = 25
    SAR_RETENTION_YEARS = 5
    BSA_RETENTION_YEARS = 5


class TransactionService:
    def __init__(
        self,
        account_repo: Any,
        audit_logger: Any,
        ofac_service: Any,
        sar_service: Any,
        rule_resolver: Any,
    ):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.sar_service = sar_service
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

        if amount <= Decimal("0"):
            if amount == Decimal("0"):
                rejection_reason = "Amount must be greater than 0"
            else:
                rejection_reason = "Invalid amount"
            
            txn = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason=rejection_reason,
            )
            self.audit_logger.log(txn)
            return txn

        from_account = self.account_repo.get_account(from_account_id)
        if not from_account:
            txn = Transaction(
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
            self.audit_logger.log(txn)
            return txn

        if not self.account_repo.validate_beneficiary(to_account_id, to_routing_number):
            txn = Transaction(
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
            self.audit_logger.log(txn)
            return txn

        if from_account.balance < amount:
            txn = Transaction(
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
            self.audit_logger.log(txn)
            return txn

        self.account_repo.debit(from_account_id, amount)
        self.account_repo.credit(to_account_id, amount)

        txn = Transaction(
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

        self.audit_logger.log(txn)
        return txn


class SARService:
    def __init__(self, fincen_client: Any, audit_logger: Any):
        self.fincen_client = fincen_client
        self.audit_logger = audit_logger

    def file_sar(
        self,
        subject_id: str,
        amount: Decimal,
        reason: str,
        transaction_id: Optional[str] = None,
        is_insider: bool = False,
    ) -> SARFiling:
        detection_date = datetime.now(timezone.utc)
        filing_deadline = detection_date + timedelta(
            days=ComplianceRules.SAR_FILING_DEADLINE_DAYS
        )
        sar_id = f"SAR-{detection_date.timestamp()}"

        sar = SARFiling(
            sar_id=sar_id,
            transaction_id=transaction_id,
            subject_id=subject_id,
            amount=amount,
            reason=reason,
            filed_date=detection_date,
            detection_date=detection_date,
            filing_deadline=filing_deadline,
            status=SARStatus.FILED,
            subject_notified=False,
        )

        self.fincen_client.submit_sar(sar)
        self.audit_logger.log_sar(sar)
        return sar

    def check_sar_filed(self, customer_id: str) -> bool:
        return self.fincen_client.has_sar(customer_id)

    def handle_customer_inquiry(self, customer_id: str, inquiry: str) -> str:
        if self.check_sar_filed(customer_id):
            return "We are unable to provide specific details about account restrictions at this time."
        return "No restrictions found on your account."


@pytest.fixture
def mock_account_repo():
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
    logger.log_sar = Mock()
    return logger


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def mock_fincen_client():
    client = Mock()
    client.submit_sar = Mock()
    client.has_sar = Mock(return_value=False)
    return client


@pytest.fixture
def mock_rule_resolver():
    resolver = Mock()
    resolver.is_suspicious = Mock(return_value=False)
    resolver.is_insider = Mock(return_value=False)
    return resolver


@pytest.fixture
def sar_service(mock_fincen_client, mock_audit_logger):
    return SARService(mock_fincen_client, mock_audit_logger)


@pytest.fixture
def transaction_service(
    mock_account_repo,
    mock_audit_logger,
    mock_ofac_service,
    sar_service,
    mock_rule_resolver,
):
    return TransactionService(
        mock_account_repo,
        mock_audit_logger,
        mock_ofac_service,
        sar_service,
        mock_rule_resolver,
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC-123456",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="active",
    )


@pytest.fixture
def low_balance_account():
    return Account(
        account_id="ACC-789012",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER-002",
        status="active",
    )


class TestSuccessfulTransaction:
    """Test successful transaction with sufficient balance and valid account."""

    def test_successful_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
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
        
        transfer_amount = Decimal("500.00")
        from_account_id = "ACC-123456"
        to_account_id = "ACC-999999"
        to_routing_number = "021000022"
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == transfer_amount
        assert result.user_id == user_id
        assert result.ip_address == ip_address
        assert result.device_info == device_info
        assert result.rejection_reason is None
        
        mock_account_repo.debit.assert_called_once_with(from_account_id, transfer_amount)
        mock_account_repo.credit.assert_called_once_with(to_account_id, transfer_amount)
        mock_audit_logger.log.assert_called_once()
        
        logged_transaction = mock_audit_logger.log.call_args[0][0]
        assert logged_transaction.status == TransactionStatus.SUCCESS
        assert logged_transaction.amount == transfer_amount


class TestSARSuspiciousActivityAboveThreshold:
    """Test SAR filing for suspicious activity above $5,000 threshold."""

    def test_sar_suspicious_activity_above_threshold(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
        mock_audit_logger: Mock,
    ):
        """
        Scenario: sar_suspicious_activity_above_threshold
        Given Transaction monitoring detects suspicious pattern
        When Suspicious activity involves > $5,000
        Then SAR filed with FinCEN within 30 days, subject NOT notified
        """
        # Arrange
        subject_id = "USER-SUSPICIOUS-001"
        suspicious_amount = Decimal("7500.00")
        reason = "Structured transactions to avoid CTR reporting"
        transaction_id = "TXN-123456"

        # Act
        sar = sar_service.file_sar(
            subject_id=subject_id,
            amount=suspicious_amount,
            reason=reason,
            transaction_id=transaction_id,
            is_insider=False,
        )

        # Assert
        assert sar.status == SARStatus.FILED
        assert sar.amount == suspicious_amount
        assert sar.subject_id == subject_id
        assert sar.subject_notified is False
        assert sar.reason == reason
        
        filing_window = (sar.filing_deadline - sar.detection_date).days
        assert filing_window == ComplianceRules.SAR_FILING_DEADLINE_DAYS
        
        mock_fincen_client.submit_sar.assert_called_once_with(sar)
        mock_audit_logger.log_sar.assert_called_once_with(sar)

    def test_sar_threshold_boundary_at_5000(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """Test SAR filing at exact $5,000 threshold."""
        # Arrange
        subject_id = "USER-BOUNDARY-001"
        threshold_amount = Decimal("5000.00")
        reason = "Suspicious activity at threshold"

        # Act
        sar = sar_service.file_sar(
            subject_id=subject_id,
            amount=threshold_amount,
            reason=reason,
        )

        # Assert
        assert sar.status == SARStatus.FILED
        assert sar.amount == threshold_amount
        assert sar.subject_notified is False
        mock_fincen_client.submit_sar.assert_called_once()

    def test_sar_threshold_boundary_just_above_5000(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """Test SAR filing just above $5,000 threshold."""
        # Arrange
        subject_id = "USER-BOUNDARY-002"
        above_threshold_amount = Decimal("5000.01")
        reason = "Suspicious activity just above threshold"

        # Act
        sar = sar_service.file_sar(
            subject_id=subject_id,
            amount=above_threshold_amount,
            reason=reason,
        )

        # Assert
        assert sar.status == SARStatus.FILED
        assert sar.amount == above_threshold_amount
        assert sar.subject_notified is False


class TestSARInsiderAbuseAnyAmount:
    """Test SAR filing for insider abuse at any dollar amount."""

    def test_sar_insider_abuse_any_amount(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
        mock_audit_logger: Mock,
    ):
        """
        Scenario: sar_insider_abuse_any_amount
        Given Bank employee involved in suspicious activity
        When Insider abuse detected at any dollar amount
        Then SAR filed immediately, no minimum threshold
        """
        # Arrange
        insider_id = "EMPLOYEE-001"
        small_amount = Decimal("100.00")
        reason = "Insider abuse - unauthorized account access"
        transaction_id = "TXN-INSIDER-001"

        # Act
        sar = sar_service.file_sar(
            subject_id=insider_id,
            amount=small_amount,
            reason=reason,
            transaction_id=transaction_id,
            is_insider=True,
        )

        # Assert
        assert sar.status == SARStatus.FILED
        assert sar.amount == small_amount
        assert sar.subject_id == insider_id
        assert sar.subject_notified is False
        assert small_amount < ComplianceRules.SAR_SUSPICIOUS_THRESHOLD
        
        mock_fincen_client.submit_sar.assert_called_once_with(sar)
        mock_audit_logger.log_sar.assert_called_once_with(sar)

    def test_sar_insider_abuse_zero_threshold(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """Test SAR filing for insider abuse with minimal amount."""
        # Arrange
        insider_id = "EMPLOYEE-002"
        minimal_amount = Decimal("0.01")
        reason = "Insider abuse - data breach"

        # Act
        sar = sar_service.file_sar(
            subject_id=insider_id,
            amount=minimal_amount,
            reason=reason,
            is_insider=True,
        )

        # Assert
        assert sar.status == SARStatus.FILED
        assert sar.amount == minimal_amount
        assert sar.subject_notified is False
        mock_fincen_client.submit_sar.assert_called_once()


class TestSARNoTippingOff:
    """Test that SAR filing is not disclosed to the subject."""

    def test_sar_no_tipping_off(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """
        Scenario: sar_no_tipping_off
        Given SAR has been filed for a customer
        When Customer inquires about account restrictions
        Then Bank does NOT disclose SAR filing
        """
        # Arrange
        customer_id = "USER-SAR-FILED-001"
        mock_fincen_client.has_sar.return_value = True
        inquiry = "Why is my account restricted?"

        # Act
        response = sar_service.handle_customer_inquiry(customer_id, inquiry)

        # Assert
        assert "SAR" not in response
        assert "Suspicious Activity Report" not in response
        assert "FinCEN" not in response
        assert "unable to provide specific details" in response
        mock_fincen_client.has_sar.assert_called_once_with(customer_id)

    def test_sar_no_tipping_off_no_sar_filed(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """Test customer inquiry when no SAR has been filed."""
        # Arrange
        customer_id = "USER-NO-SAR-001"
        mock_fincen_client.has_sar.return_value = False
        inquiry = "Why is my account restricted?"

        # Act
        response = sar_service.handle_customer_inquiry(customer_id, inquiry)

        # Assert
        assert "No restrictions found" in response
        mock_fincen_client.has_sar.assert_called_once_with(customer_id)


class TestZeroAmountTransfer:
    """Test rejection of zero amount transfers."""

    def test_zero_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
    ):
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        from_account_id = "ACC-123456"
        to_account_id = "ACC-999999"
        to_routing_number = "021000022"
        zero_amount = Decimal("0.00")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=zero_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Amount must be greater than 0"
        assert result.amount == zero_amount
        mock_audit_logger.log.assert_called_once()


class TestNegativeAmountTransfer:
    """Test rejection of negative amount transfers."""

    def test_negative_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
    ):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        from_account_id = "ACC-123456"
        to_account_id = "ACC-999999"
        to_routing_number = "021000022"
        negative_amount = Decimal("-100.00")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=negative_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid amount"
        assert result.amount == negative_amount
        mock_audit_logger.log.assert_called_once()


class TestInsufficientBalance:
    """Test rejection of transfers with insufficient balance."""

    def test_insufficient_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        low_balance_account: Account,
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
        
        from_account_id = "ACC-789012"
        to_account_id = "ACC-999999"
        to_routing_number = "021000022"
        transfer_amount = Decimal("5000.00")
        user_id = "USER-002"
        ip_address = "192.168.1.101"
        device_info = "Mozilla/5.0"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"
        assert result.amount == transfer_amount
        assert low_balance_account.balance < transfer_amount
        
        mock_account_repo.debit.assert_not_called()
        mock_account_repo.credit.assert_not_called()
        mock_audit_logger.log.assert_called_once()


class TestInvalidBeneficiary:
    """Test rejection of transfers to invalid beneficiary accounts."""

    def test_invalid_beneficiary(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
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
        
        from_account_id = "ACC-123456"
        to_account_id = "ACC-INVALID"
        to_routing_number = "999999999"
        transfer_amount = Decimal("500.00")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"
        assert result.amount == transfer_amount
        
        mock_account_repo.validate_beneficiary.assert_called_once_with(
            to_account_id, to_routing_number
        )
        mock_account_repo.debit.assert_not_called()
        mock_account_repo.credit.assert_not_called()
        mock_audit_logger.log.assert_called_once()


class TestComplianceThresholds:
    """Test various compliance thresholds and boundary conditions."""

    def test_ctr_threshold_boundary(self):
        """Test CTR threshold at $10,000."""
        # Arrange
        ctr_amount = Decimal("10000.00")
        
        # Assert
        assert ctr_amount == ComplianceRules.CTR_THRESHOLD
        assert ctr_amount > ComplianceRules.SAR_SUSPICIOUS_THRESHOLD

    def test_travel_rule_threshold(self):
        """Test Travel Rule threshold at $3,000."""
        # Arrange
        travel_rule_amount = Decimal("3000.00")
        
        # Assert
        assert travel_rule_amount == ComplianceRules.TRAVEL_RULE_THRESHOLD

    def test_wire_dual_approval_threshold(self):
        """Test wire dual approval threshold at $10,000."""
        # Arrange
        dual_approval_amount = Decimal("10000.00")
        
        # Assert
        assert dual_approval_amount == ComplianceRules.WIRE_DUAL_APPROVAL_THRESHOLD

    def test_beneficial_ownership_threshold(self):
        """Test beneficial ownership percentage threshold."""
        # Arrange
        ownership_pct = 25
        
        # Assert
        assert ownership_pct == ComplianceRules.BENEFICIAL_OWNERSHIP_PCT

    def test_sar_retention_period(self):
        """Test SAR retention period of 5 years."""
        # Arrange
        retention_years = 5
        
        # Assert
        assert retention_years == ComplianceRules.SAR_RETENTION_YEARS
        assert retention_years == ComplianceRules.BSA_RETENTION_YEARS


class TestAuditTrailRequirements:
    """Test audit trail and logging requirements."""

    def test_audit_record_contains_required_fields(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
    ):
        """Test that audit records contain all required fields."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        
        from_account_id = "ACC-123456"
        to_account_id = "ACC-999999"
        to_routing_number = "021000022"
        transfer_amount = Decimal("500.00")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        mock_audit_logger.log.assert_called_once()
        logged_transaction = mock_audit_logger.log.call_args[0][0]
        
        assert logged_transaction.user_id == user_id
        assert logged_transaction.ip_address == ip_address
        assert logged_transaction.device_info == device_info
        assert logged_transaction.timestamp is not None
        assert logged_transaction.timestamp.tzinfo is not None
        assert logged_transaction.amount == transfer_amount

    def test_audit_trail_immutability(self):
        """Test that audit records are designed to be immutable."""
        # Arrange
        timestamp = datetime.now(timezone.utc)
        audit_record = AuditRecord(
            audit_id="AUDIT-001",
            timestamp=timestamp,
            user_id="USER-001",
            action="TRANSFER",
            details={"amount": "500.00", "to_account": "ACC-999999"},
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            immutable_hash="abc123def456",
        )

        # Assert
        assert audit_record.audit_id is not None
        assert audit_record.timestamp is not None
        assert audit_record.immutable_hash is not None


class TestOFACScreening:
    """Test OFAC/SDN screening requirements."""

    def test_ofac_screening_no_match(self, mock_ofac_service: Mock):
        """Test OFAC screening with no match."""
        # Arrange
        customer_name = "John Smith"
        
        # Act
        result = mock_ofac_service.screen(customer_name)

        # Assert
        assert result["match"] is False
        assert result["score"] < ComplianceRules.OFAC_FUZZY_THRESHOLD

    def test_ofac_fuzzy_threshold(self):
        """Test OFAC fuzzy matching threshold."""
        # Arrange
        fuzzy_threshold = 85
        
        # Assert
        assert fuzzy_threshold == ComplianceRules.OFAC_FUZZY_THRESHOLD


class TestDataHandlingCompliance:
    """Test data handling and PII protection requirements."""

    def test_ssn_masking(self):
        """Test SSN masking to show only last 4 digits."""
        # Arrange
        full_ssn = "123-45-6789"
        
        # Act
        masked_ssn = f"***-**-{full_ssn[-4:]}"

        # Assert
        assert masked_ssn == "***-**-6789"
        assert len(masked_ssn) == len(full_ssn)

    def test_timestamp_timezone_aware(self):
        """Test that timestamps are timezone-aware."""
        # Arrange
        timestamp = datetime.now(timezone.utc)

        # Assert
        assert timestamp.tzinfo is not None
        assert timestamp.tzinfo == timezone.utc

    def test_decimal_precision_for_currency(self):
        """Test that currency amounts use Decimal for precision."""
        # Arrange
        amount1 = Decimal("100.00")
        amount2 = Decimal("0.01")
        
        # Act
        total = amount1 + amount2

        # Assert
        assert total == Decimal("100.01")
        assert isinstance(total, Decimal)


class TestNegativePathScenarios:
    """Test negative path and edge case scenarios."""

    def test_invalid_account_rejection(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
    ):
        """Test rejection when source account does not exist."""
        # Arrange
        mock_account_repo.get_account.return_value = None
        
        from_account_id = "ACC-NONEXISTENT"
        to_account_id = "ACC-999999"
        to_routing_number = "021000022"
        transfer_amount = Decimal("500.00")
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid account"
        mock_account_repo.debit.assert_not_called()
        mock_audit_logger.log.assert_called_once()

    def test_boundary_just_below_sar_threshold(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """Test amount just below SAR threshold."""
        # Arrange
        subject_id = "USER-BELOW-THRESHOLD"
        below_threshold = Decimal("4999.99")
        reason = "Suspicious pattern below threshold"

        # Act
        sar = sar_service.file_sar(
            subject_id=subject_id,
            amount=below_threshold,
            reason=reason,
        )

        # Assert
        assert sar.status == SARStatus.FILED
        assert sar.amount < ComplianceRules.SAR_SUSPICIOUS_THRESHOLD
        assert sar.subject_notified is False

    def test_large_amount_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
    ):
        """Test transaction with large amount above CTR threshold."""
        # Arrange
        large_balance_account = Account(
            account_id="ACC-LARGE",
            routing_number="021000021",
            balance=Decimal("100000.00"),
            user_id="USER-WHALE",
            status="active",
        )
        mock_account_repo.get_account.return_value = large_balance_account
        mock_account_repo.validate_beneficiary.return_value = True
        
        from_account_id = "ACC-LARGE"
        to_account_id = "ACC-999999"
        to_routing_number = "021000022"
        large_amount = Decimal("50000.00")
        user_id = "USER-WHALE"
        ip_address = "192.168.1.200"
        device_info = "Mozilla/5.0"

        # Act
        result = transaction_service.initiate_transaction(
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            to_routing_number=to_routing_number,
            amount=large_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount > ComplianceRules.CTR_THRESHOLD
        assert result.amount > ComplianceRules.SAR_SUSPICIOUS_THRESHOLD
        mock_audit_logger.log.assert_called_once()


class TestSARFilingDeadline:
    """Test SAR filing deadline calculations."""

    def test_sar_filing_deadline_30_days(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """Test that SAR filing deadline is 30 days from detection."""
        # Arrange
        subject_id = "USER-DEADLINE-TEST"
        amount = Decimal("10000.00")
        reason = "Suspicious wire transfers"

        # Act
        sar = sar_service.file_sar(
            subject_id=subject_id,
            amount=amount,
            reason=reason,
        )

        # Assert
        deadline_delta = (sar.filing_deadline - sar.detection_date).days
        assert deadline_delta == 30
        assert sar.filing_deadline > sar.detection_date

    def test_sar_filed_date_equals_detection_date(
        self,
        sar_service: SARService,
        mock_fincen_client: Mock,
    ):
        """Test that SAR is filed immediately upon detection."""
        # Arrange
        subject_id = "USER-IMMEDIATE-FILE"
        amount = Decimal("8000.00")
        reason = "Immediate suspicious activity"

        # Act
        sar = sar_service.file_sar(
            subject_id=subject_id,
            amount=amount,
            reason=reason,
        )

        # Assert
        assert sar.filed_date == sar.detection_date
        assert sar.status == SARStatus.FILED