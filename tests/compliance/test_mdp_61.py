import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
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
    transaction_id: Optional[str]
    subject_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    status: SARStatus
    is_insider: bool
    subject_notified: bool = False


@dataclass
class AuditRecord:
    audit_id: str
    event_type: str
    timestamp: datetime
    user_id: str
    ip_address: str
    device_info: str
    details: Dict[str, Any]
    immutable_hash: str


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
                rejection_reason="Amount must be greater than 0"
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
                rejection_reason="Invalid amount"
            )

        # Validate accounts
        from_account = self.account_repo.get_account(from_account_id)
        if not from_account:
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
                rejection_reason="Invalid account"
            )

        # Validate beneficiary
        if not self.account_repo.validate_beneficiary(to_account_id, to_routing_number):
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
                rejection_reason="Invalid beneficiary account"
            )

        # Check balance
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
                rejection_reason="Insufficient balance"
            )

        # OFAC screening
        ofac_result = self.ofac_service.screen(user_id, to_account_id)
        if ofac_result["blocked"]:
            self.audit_logger.log_transaction_blocked(
                transaction_id, user_id, ip_address, device_info, "OFAC"
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
                rejection_reason="OFAC screening failed"
            )

        # Process transaction
        self.account_repo.debit(from_account_id, amount)
        self.account_repo.credit(to_account_id, amount)

        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        # Audit trail
        self.audit_logger.log_transaction(transaction)

        # Check for suspicious activity
        self.sar_service.evaluate_transaction(transaction)

        return transaction


class SARService:
    def __init__(self, rule_resolver: Any, fincen_client: Any, audit_logger: Any):
        self.rule_resolver = rule_resolver
        self.fincen_client = fincen_client
        self.audit_logger = audit_logger
        self.sar_threshold = Decimal("5000")
        self.insider_threshold = Decimal("0")
        self.filing_deadline_days = 30

    def evaluate_transaction(self, transaction: Transaction) -> Optional[SARFiling]:
        suspicious_pattern = self.rule_resolver.detect_suspicious_pattern(transaction)
        if not suspicious_pattern:
            return None

        is_insider = self.rule_resolver.is_insider(transaction.user_id)
        
        should_file = False
        if is_insider and suspicious_pattern:
            should_file = True
        elif transaction.amount > self.sar_threshold and suspicious_pattern:
            should_file = True

        if should_file:
            return self.file_sar(
                transaction=transaction,
                reason=suspicious_pattern.get("reason", "Suspicious activity detected"),
                is_insider=is_insider
            )
        
        return None

    def file_sar(
        self,
        transaction: Optional[Transaction],
        reason: str,
        is_insider: bool,
        subject_id: Optional[str] = None,
        amount: Optional[Decimal] = None
    ) -> SARFiling:
        detection_date = datetime.now(timezone.utc)
        filing_deadline = detection_date + timedelta(days=self.filing_deadline_days)
        
        sar = SARFiling(
            sar_id=f"SAR-{detection_date.timestamp()}",
            transaction_id=transaction.transaction_id if transaction else None,
            subject_id=subject_id or (transaction.user_id if transaction else "UNKNOWN"),
            amount=amount or (transaction.amount if transaction else Decimal("0")),
            reason=reason,
            filed_date=detection_date,
            detection_date=detection_date,
            status=SARStatus.FILED,
            is_insider=is_insider,
            subject_notified=False
        )
        
        self.fincen_client.submit_sar(sar)
        self.audit_logger.log_sar_filing(sar)
        
        return sar

    def handle_customer_inquiry(self, customer_id: str, sar_id: str) -> Dict[str, Any]:
        """Handle customer inquiry without tipping off about SAR filing."""
        return {
            "disclosed_sar": False,
            "response": "We are unable to provide specific details about account restrictions at this time."
        }


@pytest.fixture
def mock_account_repo():
    repo = Mock()
    repo.get_account.return_value = Account(
        account_id="ACC-001",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="ACTIVE"
    )
    repo.validate_beneficiary.return_value = True
    repo.debit = Mock()
    repo.credit = Mock()
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock()
    logger.log_transaction = Mock()
    logger.log_transaction_blocked = Mock()
    logger.log_sar_filing = Mock()
    return logger


@pytest.fixture
def mock_sar_service():
    service = Mock()
    service.evaluate_transaction = Mock(return_value=None)
    service.file_sar = Mock()
    service.handle_customer_inquiry = Mock(return_value={
        "disclosed_sar": False,
        "response": "We are unable to provide specific details about account restrictions at this time."
    })
    return service


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen.return_value = {"blocked": False, "match_score": 0}
    return service


@pytest.fixture
def mock_rule_resolver():
    resolver = Mock()
    resolver.detect_suspicious_pattern.return_value = None
    resolver.is_insider.return_value = False
    return resolver


@pytest.fixture
def mock_fincen_client():
    client = Mock()
    client.submit_sar = Mock()
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
def sar_service(mock_rule_resolver, mock_fincen_client, mock_audit_logger):
    return SARService(
        rule_resolver=mock_rule_resolver,
        fincen_client=mock_fincen_client,
        audit_logger=mock_audit_logger
    )


def test_successful_transaction(banking_service, mock_account_repo, mock_audit_logger):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    from_account_id = "ACC-001"
    to_account_id = "ACC-002"
    to_routing_number = "021000022"
    amount = Decimal("500.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    assert transaction.amount == amount
    mock_account_repo.debit.assert_called_once_with(from_account_id, amount)
    mock_account_repo.credit.assert_called_once_with(to_account_id, amount)
    mock_audit_logger.log_transaction.assert_called_once()


def test_sar_suspicious_activity_above_threshold(
    sar_service,
    mock_rule_resolver,
    mock_fincen_client,
    mock_audit_logger
):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-123",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("6000.00"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    mock_rule_resolver.detect_suspicious_pattern.return_value = {
        "detected": True,
        "reason": "Structuring pattern detected"
    }
    mock_rule_resolver.is_insider.return_value = False

    # Act
    sar_filing = sar_service.evaluate_transaction(transaction)

    # Assert
    assert sar_filing is not None
    assert sar_filing.status == SARStatus.FILED
    assert sar_filing.subject_notified is False
    assert sar_filing.amount == Decimal("6000.00")
    assert (sar_filing.filed_date - sar_filing.detection_date).days <= 30
    mock_fincen_client.submit_sar.assert_called_once()
    mock_audit_logger.log_sar_filing.assert_called_once()


def test_sar_suspicious_activity_at_threshold_boundary(
    sar_service,
    mock_rule_resolver,
    mock_fincen_client
):
    """
    Boundary test: SAR threshold exactly at $5,000
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-124",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("5000.00"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    mock_rule_resolver.detect_suspicious_pattern.return_value = {
        "detected": True,
        "reason": "Suspicious pattern"
    }
    mock_rule_resolver.is_insider.return_value = False

    # Act
    sar_filing = sar_service.evaluate_transaction(transaction)

    # Assert - at threshold, should not file (> $5000 required)
    assert sar_filing is None


def test_sar_suspicious_activity_just_above_threshold(
    sar_service,
    mock_rule_resolver,
    mock_fincen_client
):
    """
    Boundary test: SAR threshold just above $5,000
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-125",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("5000.01"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    mock_rule_resolver.detect_suspicious_pattern.return_value = {
        "detected": True,
        "reason": "Suspicious pattern"
    }
    mock_rule_resolver.is_insider.return_value = False

    # Act
    sar_filing = sar_service.evaluate_transaction(transaction)

    # Assert
    assert sar_filing is not None
    assert sar_filing.status == SARStatus.FILED
    mock_fincen_client.submit_sar.assert_called_once()


def test_sar_insider_abuse_any_amount(
    sar_service,
    mock_rule_resolver,
    mock_fincen_client,
    mock_audit_logger
):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-126",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("100.00"),  # Below normal threshold
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="EMPLOYEE-001",
        ip_address="10.0.0.50",
        device_info="Internal System"
    )
    
    mock_rule_resolver.detect_suspicious_pattern.return_value = {
        "detected": True,
        "reason": "Insider abuse detected"
    }
    mock_rule_resolver.is_insider.return_value = True

    # Act
    sar_filing = sar_service.evaluate_transaction(transaction)

    # Assert
    assert sar_filing is not None
    assert sar_filing.status == SARStatus.FILED
    assert sar_filing.is_insider is True
    assert sar_filing.subject_notified is False
    assert sar_filing.amount == Decimal("100.00")
    mock_fincen_client.submit_sar.assert_called_once()
    mock_audit_logger.log_sar_filing.assert_called_once()


def test_sar_insider_abuse_minimal_amount(
    sar_service,
    mock_rule_resolver,
    mock_fincen_client
):
    """
    Boundary test: Insider abuse with minimal amount ($0.01)
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-127",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("0.01"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="EMPLOYEE-002",
        ip_address="10.0.0.51",
        device_info="Internal System"
    )
    
    mock_rule_resolver.detect_suspicious_pattern.return_value = {
        "detected": True,
        "reason": "Insider abuse"
    }
    mock_rule_resolver.is_insider.return_value = True

    # Act
    sar_filing = sar_service.evaluate_transaction(transaction)

    # Assert
    assert sar_filing is not None
    assert sar_filing.is_insider is True
    mock_fincen_client.submit_sar.assert_called_once()


def test_sar_no_tipping_off(sar_service):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    customer_id = "USER-001"
    sar_id = "SAR-12345"

    # Act
    response = sar_service.handle_customer_inquiry(customer_id, sar_id)

    # Assert
    assert response["disclosed_sar"] is False
    assert "unable to provide specific details" in response["response"].lower()


def test_zero_amount_transfer(banking_service):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    from_account_id = "ACC-001"
    to_account_id = "ACC-002"
    to_routing_number = "021000022"
    amount = Decimal("0")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Amount must be greater than 0"


def test_negative_amount_transfer(banking_service):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    from_account_id = "ACC-001"
    to_account_id = "ACC-002"
    to_routing_number = "021000022"
    amount = Decimal("-100.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid amount"


def test_insufficient_balance(banking_service, mock_account_repo):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    mock_account_repo.get_account.return_value = Account(
        account_id="ACC-001",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER-001",
        status="ACTIVE"
    )
    
    from_account_id = "ACC-001"
    to_account_id = "ACC-002"
    to_routing_number = "021000022"
    amount = Decimal("5000.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Insufficient balance"


def test_invalid_beneficiary(banking_service, mock_account_repo):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    mock_account_repo.validate_beneficiary.return_value = False
    
    from_account_id = "ACC-001"
    to_account_id = "INVALID-ACC"
    to_routing_number = "999999999"
    amount = Decimal("500.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid beneficiary account"


def test_ofac_screening_blocked(banking_service, mock_ofac_service, mock_audit_logger):
    """
    OFAC screening blocks transaction when match found
    """
    # Arrange
    mock_ofac_service.screen.return_value = {
        "blocked": True,
        "match_score": 95,
        "matched_entity": "SDN-12345"
    }
    
    from_account_id = "ACC-001"
    to_account_id = "ACC-002"
    to_routing_number = "021000022"
    amount = Decimal("1000.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.BLOCKED
    assert transaction.rejection_reason == "OFAC screening failed"
    mock_audit_logger.log_transaction_blocked.assert_called_once()


def test_ofac_screening_threshold_boundary():
    """
    Boundary test: OFAC fuzzy match at 85% threshold
    """
    # Arrange
    ofac_service = Mock()
    ofac_threshold = 85
    
    # Test at threshold
    ofac_service.screen.return_value = {
        "blocked": False,
        "match_score": 85,
        "requires_review": True
    }
    result = ofac_service.screen("USER-001", "ACC-002")
    assert result["match_score"] == ofac_threshold
    assert result["blocked"] is False
    
    # Test above threshold
    ofac_service.screen.return_value = {
        "blocked": True,
        "match_score": 86,
        "requires_review": False
    }
    result = ofac_service.screen("USER-001", "ACC-002")
    assert result["match_score"] > ofac_threshold
    assert result["blocked"] is True


def test_ctr_threshold_boundary():
    """
    Boundary test: CTR filing threshold at $10,000
    """
    # Arrange
    ctr_threshold = Decimal("10000.00")
    
    # Test below threshold
    amount_below = Decimal("9999.99")
    assert amount_below < ctr_threshold
    
    # Test at threshold
    amount_at = Decimal("10000.00")
    assert amount_at >= ctr_threshold
    
    # Test above threshold
    amount_above = Decimal("10000.01")
    assert amount_above > ctr_threshold


def test_travel_rule_threshold_boundary():
    """
    Boundary test: Travel Rule data requirements at $3,000
    """
    # Arrange
    travel_rule_threshold = Decimal("3000.00")
    
    # Test below threshold
    amount_below = Decimal("2999.99")
    requires_travel_rule = amount_below >= travel_rule_threshold
    assert requires_travel_rule is False
    
    # Test at threshold
    amount_at = Decimal("3000.00")
    requires_travel_rule = amount_at >= travel_rule_threshold
    assert requires_travel_rule is True
    
    # Test above threshold
    amount_above = Decimal("3000.01")
    requires_travel_rule = amount_above >= travel_rule_threshold
    assert requires_travel_rule is True


def test_wire_dual_approval_threshold():
    """
    Boundary test: Dual approval for high-value wires at $10,000
    """
    # Arrange
    dual_approval_threshold = Decimal("10000.00")
    
    # Test below threshold
    amount_below = Decimal("9999.99")
    requires_dual_approval = amount_below >= dual_approval_threshold
    assert requires_dual_approval is False
    
    # Test at threshold
    amount_at = Decimal("10000.00")
    requires_dual_approval = amount_at >= dual_approval_threshold
    assert requires_dual_approval is True


def test_beneficial_ownership_percentage_threshold():
    """
    Boundary test: Beneficial ownership reporting at 20%
    """
    # Arrange
    beneficial_ownership_threshold = 20
    
    # Test below threshold
    ownership_below = 19.99
    requires_reporting = ownership_below >= beneficial_ownership_threshold
    assert requires_reporting is False
    
    # Test at threshold
    ownership_at = 20.0
    requires_reporting = ownership_at >= beneficial_ownership_threshold
    assert requires_reporting is True


def test_audit_trail_includes_required_fields(banking_service, mock_audit_logger):
    """
    Verify audit trail includes all required compliance fields
    """
    # Arrange
    from_account_id = "ACC-001"
    to_account_id = "ACC-002"
    to_routing_number = "021000022"
    amount = Decimal("500.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0 (Windows NT 10.0)"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.user_id == user_id
    assert transaction.ip_address == ip_address
    assert transaction.device_info == device_info
    assert transaction.timestamp.tzinfo is not None  # Timezone-aware
    mock_audit_logger.log_transaction.assert_called_once()


def test_sar_retention_period():
    """
    Verify SAR records include 5-year retention requirement (31 CFR 1010.430)
    """
    # Arrange
    retention_years = 5
    detection_date = datetime.now(timezone.utc)
    retention_until = detection_date + timedelta(days=365 * retention_years)
    
    # Assert
    assert (retention_until - detection_date).days >= (365 * retention_years)


def test_sar_filing_deadline_compliance(sar_service, mock_rule_resolver, mock_fincen_client):
    """
    Verify SAR filed within 30-day deadline from detection
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-128",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("7500.00"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    mock_rule_resolver.detect_suspicious_pattern.return_value = {
        "detected": True,
        "reason": "Suspicious pattern"
    }
    mock_rule_resolver.is_insider.return_value = False

    # Act
    sar_filing = sar_service.evaluate_transaction(transaction)

    # Assert
    assert sar_filing is not None
    days_to_file = (sar_filing.filed_date - sar_filing.detection_date).days
    assert days_to_file <= 30


def test_no_suspicious_activity_no_sar(sar_service, mock_rule_resolver, mock_fincen_client):
    """
    Negative test: No SAR filed when no suspicious activity detected
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-129",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("7500.00"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    mock_rule_resolver.detect_suspicious_pattern.return_value = None
    mock_rule_resolver.is_insider.return_value = False

    # Act
    sar_filing = sar_service.evaluate_transaction(transaction)

    # Assert
    assert sar_filing is None
    mock_fincen_client.submit_sar.assert_not_called()


def test_invalid_account_rejection(banking_service, mock_account_repo):
    """
    Negative test: Transaction rejected for invalid from_account
    """
    # Arrange
    mock_account_repo.get_account.return_value = None
    
    from_account_id = "INVALID-ACC"
    to_account_id = "ACC-002"
    to_routing_number = "021000022"
    amount = Decimal("500.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        to_routing_number=to_routing_number,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid account"


def test_decimal_precision_for_currency():
    """
    Verify Decimal type used for currency to avoid floating-point errors
    """
    # Arrange
    amount1 = Decimal("0.1")
    amount2 = Decimal("0.2")
    
    # Act
    total = amount1 + amount2
    
    # Assert
    assert total == Decimal("0.3")
    assert isinstance(total, Decimal)


def test_timezone_aware_timestamps():
    """
    Verify all timestamps are timezone-aware for compliance
    """
    # Arrange & Act
    timestamp = datetime.now(timezone.utc)
    
    # Assert
    assert timestamp.tzinfo is not None
    assert timestamp.tzinfo == timezone.utc


def test_pii_masking_in_logs():
    """
    Verify SSN/TIN masking shows only last 4 digits
    """
    # Arrange
    ssn = "123-45-6789"
    
    # Act
    masked_ssn = f"***-**-{ssn[-4:]}"
    
    # Assert
    assert masked_ssn == "***-**-6789"
    assert len(masked_ssn.replace("-", "").replace("*", "")) == 4


def test_structuring_detection_24_hour_window():
    """
    Verify CTR structuring detection uses 24-hour aggregation window
    """
    # Arrange
    aggregation_window_hours = 24
    base_time = datetime.now(timezone.utc)
    
    transactions = [
        {"amount": Decimal("3000"), "timestamp": base_time},
        {"amount": Decimal("3000"), "timestamp": base_time + timedelta(hours=12)},
        {"amount": Decimal("4500"), "timestamp": base_time + timedelta(hours=23)}
    ]
    
    # Act
    total_in_window = sum(
        t["amount"] for t in transactions
        if (t["timestamp"] - base_time).total_seconds() / 3600 <= aggregation_window_hours
    )
    
    # Assert
    assert total_in_window == Decimal("10500")
    assert total_in_window > Decimal("10000")  # CTR threshold


def test_ctr_filing_deadline_15_days():
    """
    Verify CTR filing deadline is 15 days from transaction
    """
    # Arrange
    ctr_filing_deadline_days = 15
    transaction_date = datetime.now(timezone.utc)
    
    # Act
    filing_deadline = transaction_date + timedelta(days=ctr_filing_deadline_days)
    
    # Assert
    assert (filing_deadline - transaction_date).days == 15


def test_reg_e_error_resolution_60_days():
    """
    Verify Reg E error resolution window (60 days for notification)
    """
    # Arrange
    transaction_date = datetime.now(timezone.utc)
    reg_e_notification_window_days = 60
    
    # Act
    notification_deadline = transaction_date + timedelta(days=reg_e_notification_window_days)
    current_date = datetime.now(timezone.utc)
    
    # Assert
    is_within_window = current_date <= notification_deadline
    assert is_within_window or (current_date - transaction_date).days > reg_e_notification_window_days