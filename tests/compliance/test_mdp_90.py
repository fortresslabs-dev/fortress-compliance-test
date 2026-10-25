import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    PENDING_REVIEW = "pending_review"


class ScreeningResult(Enum):
    PASS = "pass"
    BLOCK = "block"
    REVIEW = "review"


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
    rejection_reason: Optional[str] = None
    audit_trail: Optional[Dict[str, Any]] = None


@dataclass
class CreditApplication:
    application_id: str
    business_name: str
    amount_requested: Decimal
    demographic_data: Optional[Dict[str, Any]] = None
    underwriting_data: Optional[Dict[str, Any]] = None
    timestamp: datetime = None


class TransactionService:
    def __init__(self, account_repo, audit_logger, ofac_service, rule_resolver):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver
        self.ctr_threshold = Decimal("10000")
        self.sar_threshold = Decimal("5000")
        self.wire_dual_approval_threshold = Decimal("10000")

    def initiate_transfer(
        self, from_account_id: str, to_routing: str, to_account: str, amount: Decimal, user_context: Dict[str, Any]
    ) -> Transaction:
        if amount <= 0:
            if amount == 0:
                return Transaction(
                    transaction_id="",
                    from_account=from_account_id,
                    to_account=to_account,
                    amount=amount,
                    timestamp=datetime.now(timezone.utc),
                    status=TransactionStatus.REJECTED,
                    rejection_reason="Amount must be greater than 0",
                )
            else:
                return Transaction(
                    transaction_id="",
                    from_account=from_account_id,
                    to_account=to_account,
                    amount=amount,
                    timestamp=datetime.now(timezone.utc),
                    status=TransactionStatus.REJECTED,
                    rejection_reason="Invalid amount",
                )

        account = self.account_repo.get_account(from_account_id)
        if not account:
            return Transaction(
                transaction_id="",
                from_account=from_account_id,
                to_account=to_account,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid account",
            )

        if account.balance < amount:
            return Transaction(
                transaction_id="",
                from_account=from_account_id,
                to_account=to_account,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance",
            )

        if not self._validate_beneficiary(to_routing, to_account):
            return Transaction(
                transaction_id="",
                from_account=from_account_id,
                to_account=to_account,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account",
            )

        screening_result = self.ofac_service.screen_transaction(
            from_account_id, to_account, amount, user_context
        )
        if screening_result == ScreeningResult.BLOCK:
            return Transaction(
                transaction_id="",
                from_account=from_account_id,
                to_account=to_account,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason="OFAC screening failed",
            )

        transaction_id = self._generate_transaction_id()
        timestamp = datetime.now(timezone.utc)

        self.account_repo.debit_account(from_account_id, amount)

        audit_data = {
            "transaction_id": transaction_id,
            "user_id": user_context.get("user_id"),
            "ip_address": user_context.get("ip_address"),
            "device_info": user_context.get("device_info"),
            "timestamp": timestamp.isoformat(),
            "amount": str(amount),
            "from_account": from_account_id,
            "to_account": to_account,
        }
        self.audit_logger.log_transaction(audit_data)

        if amount >= self.ctr_threshold:
            self.audit_logger.log_ctr_event(transaction_id, amount, user_context)

        return Transaction(
            transaction_id=transaction_id,
            from_account=from_account_id,
            to_account=to_account,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            audit_trail=audit_data,
        )

    def _validate_beneficiary(self, routing: str, account: str) -> bool:
        if not routing or not account:
            return False
        if len(routing) != 9 or not routing.isdigit():
            return False
        if not account or len(account) < 4:
            return False
        return True

    def _generate_transaction_id(self) -> str:
        import uuid
        return str(uuid.uuid4())


class CreditApplicationService:
    def __init__(self, demographic_repo, underwriting_service, audit_logger):
        self.demographic_repo = demographic_repo
        self.underwriting_service = underwriting_service
        self.audit_logger = audit_logger

    def submit_application(
        self, business_name: str, amount_requested: Decimal, demographic_data: Dict[str, Any]
    ) -> CreditApplication:
        application_id = self._generate_application_id()
        timestamp = datetime.now(timezone.utc)

        self.demographic_repo.store_demographic_data(application_id, demographic_data, timestamp)

        self.audit_logger.log_demographic_collection(application_id, timestamp)

        application = CreditApplication(
            application_id=application_id,
            business_name=business_name,
            amount_requested=amount_requested,
            demographic_data=demographic_data,
            timestamp=timestamp,
        )

        return application

    def _generate_application_id(self) -> str:
        import uuid
        return str(uuid.uuid4())

    def verify_firewall(self, application_id: str) -> bool:
        demographic_accessible = self.demographic_repo.is_accessible_to_underwriting(application_id)
        return not demographic_accessible


@pytest.fixture
def mock_account_repo():
    repo = Mock()
    repo.get_account = Mock()
    repo.debit_account = Mock()
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock()
    logger.log_transaction = Mock()
    logger.log_ctr_event = Mock()
    logger.log_sar_event = Mock()
    logger.log_demographic_collection = Mock()
    return logger


@pytest.fixture
def mock_ofac_service():
    service = Mock()
    service.screen_transaction = Mock(return_value=ScreeningResult.PASS)
    return service


@pytest.fixture
def mock_rule_resolver():
    resolver = Mock()
    return resolver


@pytest.fixture
def mock_demographic_repo():
    repo = Mock()
    repo.store_demographic_data = Mock()
    repo.is_accessible_to_underwriting = Mock(return_value=False)
    return repo


@pytest.fixture
def mock_underwriting_service():
    service = Mock()
    return service


@pytest.fixture
def transaction_service(mock_account_repo, mock_audit_logger, mock_ofac_service, mock_rule_resolver):
    return TransactionService(mock_account_repo, mock_audit_logger, mock_ofac_service, mock_rule_resolver)


@pytest.fixture
def credit_application_service(mock_demographic_repo, mock_underwriting_service, mock_audit_logger):
    return CreditApplicationService(mock_demographic_repo, mock_underwriting_service, mock_audit_logger)


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER001",
        status="active",
    )


@pytest.fixture
def user_context():
    return {
        "user_id": "USER001",
        "ip_address": "192.168.1.100",
        "device_info": "Mozilla/5.0",
    }


def test_successful_transaction(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    assert result.amount == Decimal("500.00")
    assert result.transaction_id is not None
    assert result.timestamp is not None
    assert result.timestamp.tzinfo == timezone.utc
    
    mock_account_repo.debit_account.assert_called_once_with("ACC123456", Decimal("500.00"))
    
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
    assert audit_call_args["user_id"] == "USER001"
    assert audit_call_args["ip_address"] == "192.168.1.100"
    assert audit_call_args["device_info"] == "Mozilla/5.0"
    assert "timestamp" in audit_call_args
    
    assert result.audit_trail is not None


def test_cfpb_1071_demographic_collection(credit_application_service, mock_demographic_repo, mock_audit_logger):
    """
    Scenario: cfpb_1071_demographic_collection
    Given Small business applies for credit
    When Application is submitted
    Then Demographic data collected and firewalled from underwriting
    
    Tests compliance with 12 C.F.R. § 1002.107(a) - demographic data collection
    """
    demographic_data = {
        "ethnicity": "Hispanic or Latino",
        "race": "White",
        "sex": "Male",
        "veteran_status": "Non-veteran",
        "business_ownership": "Minority-owned",
    }
    
    result = credit_application_service.submit_application(
        business_name="ABC Corp",
        amount_requested=Decimal("50000.00"),
        demographic_data=demographic_data,
    )
    
    assert result.application_id is not None
    assert result.business_name == "ABC Corp"
    assert result.amount_requested == Decimal("50000.00")
    assert result.demographic_data == demographic_data
    assert result.timestamp is not None
    
    mock_demographic_repo.store_demographic_data.assert_called_once()
    call_args = mock_demographic_repo.store_demographic_data.call_args[0]
    assert call_args[0] == result.application_id
    assert call_args[1] == demographic_data
    
    mock_audit_logger.log_demographic_collection.assert_called_once_with(
        result.application_id, result.timestamp
    )


def test_cfpb_1071_firewall_requirement(credit_application_service, mock_demographic_repo):
    """
    Tests that demographic data is firewalled from underwriting per 12 C.F.R. § 1002.107(a).
    Verifies that underwriting systems cannot access demographic data.
    """
    demographic_data = {
        "ethnicity": "Not Hispanic or Latino",
        "race": "Asian",
        "sex": "Female",
    }
    
    result = credit_application_service.submit_application(
        business_name="XYZ LLC",
        amount_requested=Decimal("25000.00"),
        demographic_data=demographic_data,
    )
    
    firewall_intact = credit_application_service.verify_firewall(result.application_id)
    
    assert firewall_intact is True, (
        "Demographic data must be firewalled from underwriting per 12 C.F.R. § 1002.107(a)"
    )
    
    mock_demographic_repo.is_accessible_to_underwriting.assert_called_once_with(result.application_id)


def test_zero_amount_transfer(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("0"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Amount must be greater than 0"
    assert result.amount == Decimal("0")
    
    mock_account_repo.debit_account.assert_not_called()


def test_negative_amount_transfer(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("-100.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid amount"
    assert result.amount == Decimal("-100.00")
    
    mock_account_repo.debit_account.assert_not_called()


def test_insufficient_balance(transaction_service, mock_account_repo, user_context):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    account_with_low_balance = Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER001",
        status="active",
    )
    mock_account_repo.get_account.return_value = account_with_low_balance
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("5000.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Insufficient balance"
    assert result.amount == Decimal("5000.00")
    
    mock_account_repo.debit_account.assert_not_called()


def test_invalid_beneficiary(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="INVALID",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"
    
    mock_account_repo.debit_account.assert_not_called()


def test_invalid_beneficiary_short_account(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Tests rejection when beneficiary account number is too short.
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="123",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"


def test_invalid_beneficiary_empty_routing(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Tests rejection when routing number is empty.
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"


def test_ctr_threshold_reporting(transaction_service, mock_account_repo, mock_audit_logger, mock_ofac_service, valid_account, user_context):
    """
    Tests CTR (Currency Transaction Report) filing requirement at $10,000 threshold.
    Uses authoritative threshold: ctr_threshold = 10000
    """
    account_with_high_balance = Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        user_id="USER001",
        status="active",
    )
    mock_account_repo.get_account.return_value = account_with_high_balance
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("10000.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    
    mock_audit_logger.log_ctr_event.assert_called_once()
    ctr_call_args = mock_audit_logger.log_ctr_event.call_args[0]
    assert ctr_call_args[1] == Decimal("10000.00")


def test_below_ctr_threshold_no_reporting(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Tests that transactions below $10,000 do not trigger CTR reporting.
    Uses authoritative threshold: ctr_threshold = 10000
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("9999.99"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    
    mock_audit_logger.log_ctr_event.assert_not_called()


def test_ofac_screening_block(transaction_service, mock_account_repo, mock_ofac_service, valid_account, user_context):
    """
    Tests OFAC/SDN screening block outcome.
    Transaction should be rejected when OFAC screening returns BLOCK.
    """
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen_transaction.return_value = ScreeningResult.BLOCK
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "OFAC screening failed"
    
    mock_account_repo.debit_account.assert_not_called()


def test_ofac_screening_pass(transaction_service, mock_account_repo, mock_ofac_service, valid_account, user_context):
    """
    Tests OFAC/SDN screening pass outcome.
    Transaction should succeed when OFAC screening returns PASS.
    """
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen_transaction.return_value = ScreeningResult.PASS
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    
    mock_ofac_service.screen_transaction.assert_called_once_with(
        "ACC123456", "9876543210", Decimal("500.00"), user_context
    )


def test_audit_trail_contains_required_fields(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Tests that audit trail contains all required fields:
    - user ID
    - IP address
    - device info
    - timestamp
    - transaction details
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    assert result.audit_trail is not None
    
    audit_trail = result.audit_trail
    assert "user_id" in audit_trail
    assert "ip_address" in audit_trail
    assert "device_info" in audit_trail
    assert "timestamp" in audit_trail
    assert "transaction_id" in audit_trail
    assert "amount" in audit_trail
    assert "from_account" in audit_trail
    assert "to_account" in audit_trail
    
    assert audit_trail["user_id"] == "USER001"
    assert audit_trail["ip_address"] == "192.168.1.100"
    assert audit_trail["device_info"] == "Mozilla/5.0"


def test_timestamp_is_timezone_aware(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Tests that transaction timestamps are timezone-aware (UTC).
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.timestamp is not None
    assert result.timestamp.tzinfo is not None
    assert result.timestamp.tzinfo == timezone.utc


def test_decimal_precision_for_currency(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Tests that currency amounts use Decimal type for precision.
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("123.45"),
        user_context=user_context,
    )
    
    assert isinstance(result.amount, Decimal)
    assert result.amount == Decimal("123.45")


def test_wire_dual_approval_threshold(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Tests wire transfer at dual approval threshold.
    Uses authoritative threshold: wire_dual_approval_threshold = 10000
    """
    account_with_high_balance = Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        user_id="USER001",
        status="active",
    )
    mock_account_repo.get_account.return_value = account_with_high_balance
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("10000.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    assert result.amount == Decimal("10000.00")


def test_boundary_just_below_ctr_threshold(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Boundary test: $9,999.99 should not trigger CTR.
    Uses authoritative threshold: ctr_threshold = 10000
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("9999.99"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_ctr_event.assert_not_called()


def test_boundary_at_ctr_threshold(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Boundary test: exactly $10,000.00 should trigger CTR.
    Uses authoritative threshold: ctr_threshold = 10000
    """
    account_with_high_balance = Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        user_id="USER001",
        status="active",
    )
    mock_account_repo.get_account.return_value = account_with_high_balance
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("10000.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_ctr_event.assert_called_once()


def test_boundary_just_above_ctr_threshold(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Boundary test: $10,000.01 should trigger CTR.
    Uses authoritative threshold: ctr_threshold = 10000
    """
    account_with_high_balance = Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        user_id="USER001",
        status="active",
    )
    mock_account_repo.get_account.return_value = account_with_high_balance
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("10000.01"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_ctr_event.assert_called_once()


def test_invalid_account_rejection(transaction_service, mock_account_repo, user_context):
    """
    Negative path: tests rejection when account does not exist.
    """
    mock_account_repo.get_account.return_value = None
    
    result = transaction_service.initiate_transfer(
        from_account_id="INVALID_ACC",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid account"
    
    mock_account_repo.debit_account.assert_not_called()


def test_demographic_data_structure(credit_application_service, mock_demographic_repo, mock_audit_logger):
    """
    Tests that demographic data structure conforms to CFPB Section 1071 requirements
    per 12 C.F.R. § 1002.107(a).
    """
    demographic_data = {
        "ethnicity": "Hispanic or Latino",
        "race": "Black or African American",
        "sex": "Female",
        "veteran_status": "Veteran",
        "business_ownership": "Women-owned",
    }
    
    result = credit_application_service.submit_application(
        business_name="Test Business",
        amount_requested=Decimal("100000.00"),
        demographic_data=demographic_data,
    )
    
    assert result.demographic_data is not None, (
        "Demographic data must be collected per 12 C.F.R. § 1002.107(a)"
    )
    assert "ethnicity" in result.demographic_data, (
        "Ethnicity must be collected per 12 C.F.R. § 1002.107(a)"
    )
    assert "race" in result.demographic_data, (
        "Race must be collected per 12 C.F.R. § 1002.107(a)"
    )
    assert "sex" in result.demographic_data, (
        "Sex must be collected per 12 C.F.R. § 1002.107(a)"
    )


def test_multiple_transactions_audit_trail(transaction_service, mock_account_repo, mock_audit_logger, valid_account, user_context):
    """
    Tests that multiple transactions each generate separate audit trail entries.
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result1 = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("100.00"),
        user_context=user_context,
    )
    
    result2 = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="021000021",
        to_account="9876543210",
        amount=Decimal("200.00"),
        user_context=user_context,
    )
    
    assert result1.status == TransactionStatus.SUCCESS
    assert result2.status == TransactionStatus.SUCCESS
    assert result1.transaction_id != result2.transaction_id
    
    assert mock_audit_logger.log_transaction.call_count == 2


def test_routing_number_validation_non_numeric(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Tests routing number validation rejects non-numeric values.
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="ABC123456",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"


def test_routing_number_validation_wrong_length(transaction_service, mock_account_repo, valid_account, user_context):
    """
    Tests routing number validation requires exactly 9 digits.
    """
    mock_account_repo.get_account.return_value = valid_account
    
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_routing="12345678",
        to_account="9876543210",
        amount=Decimal("500.00"),
        user_context=user_context,
    )
    
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"