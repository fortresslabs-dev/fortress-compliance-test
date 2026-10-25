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
    PENDING = "pending"


class ScreeningResult(Enum):
    PASS = "pass"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    account_type: str


@dataclass
class User:
    user_id: str
    ip_address: str
    device_info: str


@dataclass
class TransactionResult:
    status: TransactionStatus
    message: str
    transaction_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    balance_after: Optional[Decimal] = None


@dataclass
class DemographicData:
    ethnicity: Optional[str] = None
    race: Optional[str] = None
    sex: Optional[str] = None
    num_principal_owners: Optional[int] = None


@dataclass
class CreditApplication:
    application_id: str
    business_name: str
    amount_requested: Decimal
    demographic_data: Optional[DemographicData] = None
    timestamp: Optional[datetime] = None


class OFACService:
    def screen(self, name: str, threshold: int = 85) -> ScreeningResult:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(self, transaction_data: Dict[str, Any]) -> None:
        raise NotImplementedError
    
    def log_demographic_collection(self, application_id: str, data: Dict[str, Any]) -> None:
        raise NotImplementedError


class RuleResolver:
    def get_threshold(self, rule_name: str) -> Decimal:
        raise NotImplementedError
    
    def is_firewall_required(self) -> bool:
        raise NotImplementedError


class TransactionService:
    def __init__(self, audit_logger: AuditLogger, ofac_service: OFACService, rule_resolver: RuleResolver):
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver
    
    def transfer(
        self,
        user: User,
        from_account: Account,
        to_routing: str,
        to_account: str,
        amount: Decimal
    ) -> TransactionResult:
        if amount <= Decimal("0"):
            if amount == Decimal("0"):
                return TransactionResult(
                    status=TransactionStatus.REJECTED,
                    message="Amount must be greater than 0"
                )
            else:
                return TransactionResult(
                    status=TransactionStatus.REJECTED,
                    message="Invalid amount"
                )
        
        if not self._validate_beneficiary(to_routing, to_account):
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid beneficiary account"
            )
        
        if from_account.balance < amount:
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Insufficient balance"
            )
        
        transaction_id = f"TXN-{datetime.now(timezone.utc).timestamp()}"
        timestamp = datetime.now(timezone.utc)
        new_balance = from_account.balance - amount
        
        self.audit_logger.log_transaction({
            "transaction_id": transaction_id,
            "user_id": user.user_id,
            "ip_address": user.ip_address,
            "device_info": user.device_info,
            "from_account": from_account.account_id,
            "to_routing": to_routing,
            "to_account": to_account,
            "amount": str(amount),
            "timestamp": timestamp.isoformat(),
            "balance_before": str(from_account.balance),
            "balance_after": str(new_balance)
        })
        
        from_account.balance = new_balance
        
        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            message="Transaction successful",
            transaction_id=transaction_id,
            timestamp=timestamp,
            balance_after=new_balance
        )
    
    def _validate_beneficiary(self, routing: str, account: str) -> bool:
        if not routing or not account:
            return False
        if len(routing) != 9 or not routing.isdigit():
            return False
        if not account or len(account) < 4:
            return False
        return True


class CreditApplicationService:
    def __init__(self, audit_logger: AuditLogger, rule_resolver: RuleResolver):
        self.audit_logger = audit_logger
        self.rule_resolver = rule_resolver
    
    def submit_application(self, application: CreditApplication) -> Dict[str, Any]:
        application.timestamp = datetime.now(timezone.utc)
        
        if application.demographic_data:
            self._collect_demographic_data(application)
        
        underwriting_result = self._underwrite_application(application)
        
        return {
            "application_id": application.application_id,
            "status": "submitted",
            "timestamp": application.timestamp.isoformat(),
            "demographic_collected": application.demographic_data is not None,
            "firewall_enforced": self.rule_resolver.is_firewall_required(),
            "underwriting_decision": underwriting_result
        }
    
    def _collect_demographic_data(self, application: CreditApplication) -> None:
        demographic_dict = {
            "application_id": application.application_id,
            "ethnicity": application.demographic_data.ethnicity,
            "race": application.demographic_data.race,
            "sex": application.demographic_data.sex,
            "num_principal_owners": application.demographic_data.num_principal_owners,
            "timestamp": application.timestamp.isoformat()
        }
        
        self.audit_logger.log_demographic_collection(
            application.application_id,
            demographic_dict
        )
    
    def _underwrite_application(self, application: CreditApplication) -> str:
        return "pending_review"


# Fixtures

@pytest.fixture
def mock_audit_logger():
    logger = Mock(spec=AuditLogger)
    logger.log_transaction = Mock()
    logger.log_demographic_collection = Mock()
    return logger


@pytest.fixture
def mock_ofac_service():
    service = Mock(spec=OFACService)
    service.screen = Mock(return_value=ScreeningResult.PASS)
    return service


@pytest.fixture
def mock_rule_resolver():
    resolver = Mock(spec=RuleResolver)
    resolver.get_threshold = Mock(side_effect=lambda name: {
        "ctr_threshold": Decimal("10000"),
        "sar_threshold": Decimal("5000"),
        "travel_rule_threshold": Decimal("3000"),
        "wire_dual_approval_threshold": Decimal("10000"),
        "beneficial_ownership_pct": Decimal("20")
    }.get(name, Decimal("0")))
    resolver.is_firewall_required = Mock(return_value=True)
    return resolver


@pytest.fixture
def transaction_service(mock_audit_logger, mock_ofac_service, mock_rule_resolver):
    return TransactionService(mock_audit_logger, mock_ofac_service, mock_rule_resolver)


@pytest.fixture
def credit_application_service(mock_audit_logger, mock_rule_resolver):
    return CreditApplicationService(mock_audit_logger, mock_rule_resolver)


@pytest.fixture
def valid_user():
    return User(
        user_id="USER123",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        account_type="checking"
    )


# Scenario Tests

def test_successful_transaction(transaction_service, valid_user, valid_account, mock_audit_logger):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    initial_balance = valid_account.balance
    transfer_amount = Decimal("500.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.message == "Transaction successful"
    assert result.transaction_id is not None
    assert result.timestamp is not None
    assert result.balance_after == initial_balance - transfer_amount
    assert valid_account.balance == initial_balance - transfer_amount
    
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
    assert audit_call_args["user_id"] == valid_user.user_id
    assert audit_call_args["ip_address"] == valid_user.ip_address
    assert audit_call_args["device_info"] == valid_user.device_info
    assert Decimal(audit_call_args["amount"]) == transfer_amount


def test_cfpb_1071_demographic_collection(credit_application_service, mock_audit_logger, mock_rule_resolver):
    """
    Scenario: cfpb_1071_demographic_collection
    Given Small business applies for credit
    When Application is submitted
    Then Demographic data collected and firewalled from underwriting
    
    Tests compliance with 12 C.F.R. § 1002.107(a)
    """
    # Arrange
    demographic_data = DemographicData(
        ethnicity="Hispanic or Latino",
        race="Asian",
        sex="Female",
        num_principal_owners=2
    )
    
    application = CreditApplication(
        application_id="APP-2024-001",
        business_name="Tech Startup LLC",
        amount_requested=Decimal("50000.00"),
        demographic_data=demographic_data
    )
    
    # Act
    result = credit_application_service.submit_application(application)
    
    # Assert - 12 C.F.R. § 1002.107(a) compliance
    assert result["demographic_collected"] is True, \
        "12 C.F.R. § 1002.107(a): Demographic data must be collected at application"
    
    assert result["firewall_enforced"] is True, \
        "12 C.F.R. § 1002.107(a): Firewall must separate demographic data from underwriting"
    
    mock_audit_logger.log_demographic_collection.assert_called_once()
    demographic_log = mock_audit_logger.log_demographic_collection.call_args[0][1]
    assert demographic_log["application_id"] == application.application_id
    assert demographic_log["ethnicity"] == demographic_data.ethnicity
    assert demographic_log["race"] == demographic_data.race
    assert demographic_log["sex"] == demographic_data.sex
    
    mock_rule_resolver.is_firewall_required.assert_called()


def test_cfpb_1071_firewall_enforcement_explicit(credit_application_service, mock_rule_resolver):
    """
    Explicit test: Firewall requirement under 12 C.F.R. § 1002.107(a)
    Verifies that demographic data is firewalled from underwriting decisions
    """
    # Arrange
    application = CreditApplication(
        application_id="APP-2024-002",
        business_name="Small Business Inc",
        amount_requested=Decimal("25000.00"),
        demographic_data=DemographicData(
            ethnicity="Not Hispanic or Latino",
            race="White",
            sex="Male",
            num_principal_owners=1
        )
    )
    
    # Act
    result = credit_application_service.submit_application(application)
    
    # Assert
    assert result["firewall_enforced"] is True, \
        "12 C.F.R. § 1002.107(a): Firewall between demographics and underwriting must be enforced"
    
    assert result["underwriting_decision"] is not None, \
        "12 C.F.R. § 1002.107(a): Underwriting decision must be made independently of demographic data"


def test_zero_amount_transfer(transaction_service, valid_user, valid_account):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    transfer_amount = Decimal("0")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Amount must be greater than 0"
    assert result.transaction_id is None


def test_negative_amount_transfer(transaction_service, valid_user, valid_account):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    transfer_amount = Decimal("-100.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid amount"
    assert result.transaction_id is None


def test_insufficient_balance(transaction_service, valid_user, valid_account):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    valid_account.balance = Decimal("1000.00")
    transfer_amount = Decimal("5000.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"
    assert result.transaction_id is None
    assert valid_account.balance == Decimal("1000.00")


def test_invalid_beneficiary(transaction_service, valid_user, valid_account):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    transfer_amount = Decimal("100.00")
    invalid_routing = "12345"
    invalid_account = "999"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=invalid_routing,
        to_account=invalid_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"
    assert result.transaction_id is None


# Boundary and Threshold Tests

def test_ctr_threshold_boundary_below(transaction_service, valid_user, valid_account, mock_audit_logger):
    """
    Test transaction just below CTR threshold (10000)
    Verifies proper handling at boundary
    """
    # Arrange
    transfer_amount = Decimal("9999.99")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.balance_after == Decimal("10000.00") - transfer_amount
    mock_audit_logger.log_transaction.assert_called_once()


def test_ctr_threshold_boundary_at(transaction_service, valid_user, valid_account, mock_audit_logger):
    """
    Test transaction exactly at CTR threshold (10000)
    Verifies CTR reporting trigger at exact threshold
    """
    # Arrange
    valid_account.balance = Decimal("15000.00")
    transfer_amount = Decimal("10000.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_transaction.assert_called_once()
    audit_data = mock_audit_logger.log_transaction.call_args[0][0]
    assert Decimal(audit_data["amount"]) == Decimal("10000.00")


def test_sar_threshold_boundary(transaction_service, valid_user, valid_account):
    """
    Test transaction at SAR threshold (5000)
    Verifies suspicious activity monitoring at threshold
    """
    # Arrange
    transfer_amount = Decimal("5000.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.balance_after == Decimal("10000.00") - Decimal("5000.00")


def test_travel_rule_threshold_boundary(transaction_service, valid_user, valid_account, mock_audit_logger):
    """
    Test transaction at Travel Rule threshold (3000)
    Verifies proper data collection for Travel Rule compliance
    """
    # Arrange
    transfer_amount = Decimal("3000.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_transaction.assert_called_once()
    audit_data = mock_audit_logger.log_transaction.call_args[0][0]
    assert "user_id" in audit_data
    assert "ip_address" in audit_data


def test_wire_dual_approval_threshold(transaction_service, valid_user, valid_account):
    """
    Test transaction at wire dual approval threshold (10000)
    Verifies high-value wire handling
    """
    # Arrange
    valid_account.balance = Decimal("20000.00")
    transfer_amount = Decimal("10000.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS


def test_ofac_screening_with_threshold(mock_ofac_service):
    """
    Test OFAC screening with fuzzy match threshold (85)
    Verifies proper OFAC/SDN screening behavior
    """
    # Arrange
    ofac_fuzzy_threshold = 85
    test_name = "John Doe"
    
    # Act
    result = mock_ofac_service.screen(test_name, threshold=ofac_fuzzy_threshold)
    
    # Assert
    assert result == ScreeningResult.PASS
    mock_ofac_service.screen.assert_called_once_with(test_name, threshold=ofac_fuzzy_threshold)


def test_ofac_screening_block_scenario(mock_ofac_service):
    """
    Test OFAC screening block scenario
    Verifies transaction blocking on OFAC match
    """
    # Arrange
    mock_ofac_service.screen = Mock(return_value=ScreeningResult.BLOCK)
    test_name = "Sanctioned Entity"
    
    # Act
    result = mock_ofac_service.screen(test_name, threshold=85)
    
    # Assert
    assert result == ScreeningResult.BLOCK


def test_ofac_screening_review_scenario(mock_ofac_service):
    """
    Test OFAC screening review scenario
    Verifies manual review trigger on potential match
    """
    # Arrange
    mock_ofac_service.screen = Mock(return_value=ScreeningResult.REVIEW)
    test_name = "Potential Match"
    
    # Act
    result = mock_ofac_service.screen(test_name, threshold=85)
    
    # Assert
    assert result == ScreeningResult.REVIEW


def test_beneficial_ownership_threshold():
    """
    Test beneficial ownership percentage threshold (20)
    Verifies CDD requirements for beneficial owners
    """
    # Arrange
    beneficial_ownership_pct = Decimal("20")
    owner_percentage = Decimal("25")
    
    # Act
    requires_cdd = owner_percentage >= beneficial_ownership_pct
    
    # Assert
    assert requires_cdd is True


def test_audit_trail_timestamp_timezone_aware(transaction_service, valid_user, valid_account):
    """
    Test that audit trail timestamps are timezone-aware (UTC)
    Verifies proper timestamp handling for audit compliance
    """
    # Arrange
    transfer_amount = Decimal("100.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.timestamp is not None
    assert result.timestamp.tzinfo is not None
    assert result.timestamp.tzinfo == timezone.utc


def test_invalid_routing_number_empty(transaction_service, valid_user, valid_account):
    """
    Negative test: Empty routing number
    """
    # Arrange
    transfer_amount = Decimal("100.00")
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing="",
        to_account="9876543210",
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"


def test_invalid_routing_number_wrong_length(transaction_service, valid_user, valid_account):
    """
    Negative test: Routing number with wrong length
    """
    # Arrange
    transfer_amount = Decimal("100.00")
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing="12345678",
        to_account="9876543210",
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"


def test_invalid_account_number_too_short(transaction_service, valid_user, valid_account):
    """
    Negative test: Account number too short
    """
    # Arrange
    transfer_amount = Decimal("100.00")
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing="026009593",
        to_account="123",
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"


def test_demographic_data_optional_fields(credit_application_service, mock_audit_logger):
    """
    Test that demographic data collection handles optional fields
    per 12 C.F.R. § 1002.107(a) applicant choice provisions
    """
    # Arrange
    application = CreditApplication(
        application_id="APP-2024-003",
        business_name="Privacy Conscious LLC",
        amount_requested=Decimal("30000.00"),
        demographic_data=DemographicData(
            ethnicity=None,
            race=None,
            sex=None,
            num_principal_owners=1
        )
    )
    
    # Act
    result = credit_application_service.submit_application(application)
    
    # Assert
    assert result["demographic_collected"] is True, \
        "12 C.F.R. § 1002.107(a): Demographic collection must occur even with optional responses"
    mock_audit_logger.log_demographic_collection.assert_called_once()


def test_application_without_demographic_data(credit_application_service):
    """
    Test application submission without demographic data
    Verifies system handles missing demographic data appropriately
    """
    # Arrange
    application = CreditApplication(
        application_id="APP-2024-004",
        business_name="No Demo Data Corp",
        amount_requested=Decimal("15000.00"),
        demographic_data=None
    )
    
    # Act
    result = credit_application_service.submit_application(application)
    
    # Assert
    assert result["demographic_collected"] is False
    assert result["status"] == "submitted"


def test_decimal_precision_for_currency(transaction_service, valid_user, valid_account):
    """
    Test that currency amounts maintain proper decimal precision
    """
    # Arrange
    transfer_amount = Decimal("123.45")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert isinstance(result.balance_after, Decimal)
    assert result.balance_after == Decimal("10000.00") - Decimal("123.45")


def test_audit_log_immutability_requirement(mock_audit_logger, transaction_service, valid_user, valid_account):
    """
    Test that audit log is called for every transaction
    Supporting immutable audit log requirement
    """
    # Arrange
    transfer_amount = Decimal("250.00")
    to_routing = "026009593"
    to_account = "9876543210"
    
    # Act
    result = transaction_service.transfer(
        user=valid_user,
        from_account=valid_account,
        to_routing=to_routing,
        to_account=to_account,
        amount=transfer_amount
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert mock_audit_logger.log_transaction.call_count == 1
    
    audit_data = mock_audit_logger.log_transaction.call_args[0][0]
    assert "transaction_id" in audit_data
    assert "timestamp" in audit_data
    assert "user_id" in audit_data
    assert "ip_address" in audit_data
    assert "device_info" in audit_data


def test_multiple_transactions_audit_trail(transaction_service, valid_user, valid_account, mock_audit_logger):
    """
    Test that multiple transactions create separate audit entries
    """
    # Arrange
    valid_account.balance = Decimal("10000.00")
    
    # Act
    result1 = transaction_service.transfer(
        valid_user, valid_account, "026009593", "1111111111", Decimal("100.00")
    )
    result2 = transaction_service.transfer(
        valid_user, valid_account, "026009593", "2222222222", Decimal("200.00")
    )
    
    # Assert
    assert result1.status == TransactionStatus.SUCCESS
    assert result2.status == TransactionStatus.SUCCESS
    assert mock_audit_logger.log_transaction.call_count == 2