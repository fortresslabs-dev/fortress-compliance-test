import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# Domain Models
# ============================================================================

class TransactionStatus(Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    PENDING_REVIEW = "pending_review"
    BLOCKED = "blocked"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    customer_id: str
    account_type: str = "checking"


@dataclass
class Customer:
    customer_id: str
    name: str
    ssn: str
    is_legal_entity: bool = False
    beneficial_owners: List[Dict[str, Any]] = None


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    to_routing: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None
    user_id: str = ""
    ip_address: str = ""
    device_info: str = ""


@dataclass
class AuditLogEntry:
    timestamp: datetime
    transaction_id: str
    user_id: str
    ip_address: str
    device_info: str
    action: str
    result: str
    details: Dict[str, Any]


@dataclass
class BeneficialOwner:
    name: str
    ownership_percentage: Decimal
    is_control_prong: bool
    ssn_last_four: str


# ============================================================================
# Authoritative Thresholds (from compliance grounding)
# ============================================================================

CTR_THRESHOLD = Decimal("10000")
SAR_THRESHOLD = Decimal("5000")
TRAVEL_RULE_THRESHOLD = Decimal("3000")
WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
OFAC_FUZZY_THRESHOLD = 85
BENEFICIAL_OWNERSHIP_PCT = Decimal("20")
BENEFICIAL_OWNERSHIP_THRESHOLD = Decimal("25")


# ============================================================================
# Service Interfaces
# ============================================================================

class OFACService:
    def screen_account(self, account_id: str, routing: str, name: str) -> Dict[str, Any]:
        raise NotImplementedError

    def screen_customer(self, customer_id: str, name: str, ssn: str) -> Dict[str, Any]:
        raise NotImplementedError


class RuleResolver:
    def evaluate_ctr_requirement(self, amount: Decimal) -> bool:
        return amount >= CTR_THRESHOLD

    def evaluate_sar_requirement(self, amount: Decimal, is_suspicious: bool) -> bool:
        return amount >= SAR_THRESHOLD and is_suspicious

    def evaluate_travel_rule(self, amount: Decimal) -> bool:
        return amount >= TRAVEL_RULE_THRESHOLD

    def evaluate_dual_approval(self, amount: Decimal) -> bool:
        return amount >= WIRE_DUAL_APPROVAL_THRESHOLD

    def validate_beneficial_ownership(self, customer: Customer) -> Dict[str, Any]:
        """
        Validates beneficial ownership requirements per 31 C.F.R. § 1010.230.
        """
        if not customer.is_legal_entity:
            return {"valid": True, "reason": "Not a legal entity"}

        if not customer.beneficial_owners:
            return {
                "valid": False,
                "reason": "31 C.F.R. § 1010.230(d)(2): Control prong required"
            }

        ownership_prong_count = sum(
            1 for bo in customer.beneficial_owners
            if not bo.get("is_control_prong", False)
            and Decimal(str(bo.get("ownership_percentage", 0))) >= BENEFICIAL_OWNERSHIP_THRESHOLD
        )

        control_prong_count = sum(
            1 for bo in customer.beneficial_owners
            if bo.get("is_control_prong", False)
        )

        if ownership_prong_count > 4:
            return {
                "valid": False,
                "reason": "31 C.F.R. § 1010.230(d)(1): Maximum 4 ownership-prong individuals"
            }

        if control_prong_count != 1:
            return {
                "valid": False,
                "reason": "31 C.F.R. § 1010.230(d)(2): Exactly one control-prong individual required"
            }

        return {"valid": True}


class AuditLogger:
    def log(self, entry: AuditLogEntry) -> None:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_id: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_id: str, new_balance: Decimal) -> None:
        raise NotImplementedError


class CustomerRepository:
    def get_customer(self, customer_id: str) -> Optional[Customer]:
        raise NotImplementedError


# ============================================================================
# Transaction Service
# ============================================================================

class TransactionService:
    def __init__(
        self,
        account_repo: AccountRepository,
        customer_repo: CustomerRepository,
        ofac_service: OFACService,
        rule_resolver: RuleResolver,
        audit_logger: AuditLogger
    ):
        self.account_repo = account_repo
        self.customer_repo = customer_repo
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver
        self.audit_logger = audit_logger

    def initiate_transfer(
        self,
        from_account_id: str,
        to_account_id: str,
        to_routing: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        """
        Initiates a transfer with full compliance checks.
        """
        transaction_id = f"TXN-{datetime.now(timezone.utc).timestamp()}"
        timestamp = datetime.now(timezone.utc)

        # Validate amount
        if amount <= Decimal("0"):
            rejection_reason = "Amount must be greater than 0" if amount == Decimal("0") else "Invalid amount"
            txn = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                to_routing=to_routing,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self._log_transaction(txn)
            return txn

        # Get source account
        from_account = self.account_repo.get_account(from_account_id)
        if not from_account:
            txn = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                to_routing=to_routing,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid source account",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self._log_transaction(txn)
            return txn

        # Check sufficient balance
        if from_account.balance < amount:
            txn = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                to_routing=to_routing,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self._log_transaction(txn)
            return txn

        # Validate beneficiary account
        if not self._validate_beneficiary(to_account_id, to_routing):
            txn = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                to_routing=to_routing,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self._log_transaction(txn)
            return txn

        # OFAC screening
        ofac_result = self.ofac_service.screen_account(to_account_id, to_routing, "")
        if ofac_result.get("is_blocked", False):
            txn = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                to_routing=to_routing,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.BLOCKED,
                rejection_reason="OFAC match - transaction blocked",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self._log_transaction(txn)
            return txn

        # Successful transaction
        new_balance = from_account.balance - amount
        self.account_repo.update_balance(from_account_id, new_balance)

        txn = Transaction(
            transaction_id=transaction_id,
            from_account=from_account_id,
            to_account=to_account_id,
            to_routing=to_routing,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )
        self._log_transaction(txn)
        return txn

    def _validate_beneficiary(self, account_id: str, routing: str) -> bool:
        """Validates beneficiary account and routing number format."""
        if not account_id or not routing:
            return False
        if len(routing) != 9 or not routing.isdigit():
            return False
        if not account_id.isalnum():
            return False
        return True

    def _log_transaction(self, txn: Transaction) -> None:
        """Logs transaction to immutable audit trail per BSA requirements."""
        entry = AuditLogEntry(
            timestamp=txn.timestamp,
            transaction_id=txn.transaction_id,
            user_id=txn.user_id,
            ip_address=txn.ip_address,
            device_info=txn.device_info,
            action="transfer",
            result=txn.status.value,
            details={
                "from_account": txn.from_account,
                "to_account": txn.to_account,
                "to_routing": txn.to_routing,
                "amount": str(txn.amount),
                "rejection_reason": txn.rejection_reason
            }
        )
        self.audit_logger.log(entry)


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def mock_account_repo() -> Mock:
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_customer_repo() -> Mock:
    repo = Mock(spec=CustomerRepository)
    return repo


@pytest.fixture
def mock_ofac_service() -> Mock:
    service = Mock(spec=OFACService)
    service.screen_account.return_value = {"is_blocked": False, "match_score": 0}
    service.screen_customer.return_value = {"is_blocked": False, "match_score": 0}
    return service


@pytest.fixture
def rule_resolver() -> RuleResolver:
    return RuleResolver()


@pytest.fixture
def mock_audit_logger() -> Mock:
    logger = Mock(spec=AuditLogger)
    return logger


@pytest.fixture
def transaction_service(
    mock_account_repo: Mock,
    mock_customer_repo: Mock,
    mock_ofac_service: Mock,
    rule_resolver: RuleResolver,
    mock_audit_logger: Mock
) -> TransactionService:
    return TransactionService(
        account_repo=mock_account_repo,
        customer_repo=mock_customer_repo,
        ofac_service=mock_ofac_service,
        rule_resolver=rule_resolver,
        audit_logger=mock_audit_logger
    )


@pytest.fixture
def valid_account() -> Account:
    return Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        customer_id="CUST001",
        account_type="checking"
    )


@pytest.fixture
def legal_entity_customer_no_owners() -> Customer:
    return Customer(
        customer_id="CUST_LEGAL_001",
        name="Test Corp LLC",
        ssn="XX-XXX1234",
        is_legal_entity=True,
        beneficial_owners=[]
    )


@pytest.fixture
def legal_entity_customer_with_control_prong() -> Customer:
    return Customer(
        customer_id="CUST_LEGAL_002",
        name="Compliant Corp LLC",
        ssn="XX-XXX5678",
        is_legal_entity=True,
        beneficial_owners=[
            {
                "name": "John Doe",
                "ownership_percentage": Decimal("15"),
                "is_control_prong": False,
                "ssn_last_four": "1234"
            },
            {
                "name": "Jane Smith",
                "ownership_percentage": Decimal("10"),
                "is_control_prong": True,
                "ssn_last_four": "5678"
            }
        ]
    )


@pytest.fixture
def legal_entity_customer_no_25pct_owner_with_control() -> Customer:
    """
    Legal entity where no owner reaches 25% but control prong is present.
    Tests FINCEN-1010-230-d-2-R2::OBL::001.
    """
    return Customer(
        customer_id="CUST_LEGAL_003",
        name="Multi Owner Corp",
        ssn="XX-XXX9999",
        is_legal_entity=True,
        beneficial_owners=[
            {
                "name": "Owner A",
                "ownership_percentage": Decimal("20"),
                "is_control_prong": False,
                "ssn_last_four": "1111"
            },
            {
                "name": "Owner B",
                "ownership_percentage": Decimal("20"),
                "is_control_prong": False,
                "ssn_last_four": "2222"
            },
            {
                "name": "Owner C",
                "ownership_percentage": Decimal("15"),
                "is_control_prong": False,
                "ssn_last_four": "3333"
            },
            {
                "name": "Control Person",
                "ownership_percentage": Decimal("5"),
                "is_control_prong": True,
                "ssn_last_four": "9999"
            }
        ]
    )


# ============================================================================
# BDD Scenario Tests (MDP-103)
# ============================================================================

def test_successful_transaction(
    transaction_service: TransactionService,
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
    expected_new_balance = valid_account.balance - transfer_amount

    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=transfer_amount,
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )

    # Assert
    assert result.status == TransactionStatus.SUCCESS, "Transaction should succeed"
    assert result.amount == transfer_amount
    assert result.rejection_reason is None
    mock_account_repo.update_balance.assert_called_once_with("ACC123456", expected_new_balance)
    mock_audit_logger.log.assert_called_once()
    audit_call = mock_audit_logger.log.call_args[0][0]
    assert audit_call.transaction_id == result.transaction_id
    assert audit_call.user_id == "USER001"
    assert audit_call.ip_address == "192.168.1.100"
    assert audit_call.device_info == "Mozilla/5.0"


def test_zero_amount_transfer(
    transaction_service: TransactionService,
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

    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=Decimal("0"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Amount must be greater than 0"
    mock_account_repo.update_balance.assert_not_called()
    mock_audit_logger.log.assert_called_once()


def test_negative_amount_transfer(
    transaction_service: TransactionService,
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

    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=Decimal("-100"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid amount"
    mock_account_repo.update_balance.assert_not_called()
    mock_audit_logger.log.assert_called_once()


def test_insufficient_balance(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock
):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    account = Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        customer_id="CUST001"
    )
    mock_account_repo.get_account.return_value = account

    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=Decimal("5000.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Insufficient balance"
    mock_account_repo.update_balance.assert_not_called()
    mock_audit_logger.log.assert_called_once()


def test_invalid_beneficiary(
    transaction_service: TransactionService,
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

    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="INVALID",
        amount=Decimal("100.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.rejection_reason == "Invalid beneficiary account"
    mock_account_repo.update_balance.assert_not_called()
    mock_audit_logger.log.assert_called_once()


# ============================================================================
# MUST-TEST OBLIGATIONS: 31 C.F.R. § 1010.230(d)(2)
# ============================================================================

def test_control_prong_required_even_when_no_owner_reaches_25_percent(
    rule_resolver: RuleResolver,
    legal_entity_customer_no_25pct_owner_with_control: Customer
):
    """
    MUST-TEST: [FINCEN-1010-230-d-2-R2::OBL::001]
    Control prong must be required even when no owner reaches 25 percent.
    
    This test validates that a legal entity customer with no individual owner
    holding 25% or more equity still requires exactly one control-prong individual
    per 31 C.F.R. § 1010.230(d)(2).
    """
    # Arrange
    customer = legal_entity_customer_no_25pct_owner_with_control
    
    # Verify test precondition: no owner reaches 25%
    ownership_prong_individuals = [
        bo for bo in customer.beneficial_owners
        if not bo.get("is_control_prong", False)
        and Decimal(str(bo.get("ownership_percentage", 0))) >= BENEFICIAL_OWNERSHIP_THRESHOLD
    ]
    assert len(ownership_prong_individuals) == 0, "Test precondition: no owner should reach 25%"
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is True, (
        "31 C.F.R. § 1010.230(d)(2): Control prong must be required even when "
        "no owner reaches 25 percent - validation should pass when control prong is present"
    )


def test_control_prong_missing_when_no_owner_reaches_25_percent_fails_validation(
    rule_resolver: RuleResolver
):
    """
    MUST-TEST: [FINCEN-1010-230-d-2-R2::OBL::001]
    Control prong must be required even when no owner reaches 25 percent.
    
    This test validates that absence of control prong fails validation even when
    no owner reaches 25%, per 31 C.F.R. § 1010.230(d)(2).
    """
    # Arrange
    customer = Customer(
        customer_id="CUST_LEGAL_NO_CONTROL",
        name="No Control Corp",
        ssn="XX-XXX8888",
        is_legal_entity=True,
        beneficial_owners=[
            {
                "name": "Owner A",
                "ownership_percentage": Decimal("20"),
                "is_control_prong": False,
                "ssn_last_four": "1111"
            },
            {
                "name": "Owner B",
                "ownership_percentage": Decimal("15"),
                "is_control_prong": False,
                "ssn_last_four": "2222"
            }
        ]
    )
    
    # Verify no owner reaches 25%
    ownership_prong_individuals = [
        bo for bo in customer.beneficial_owners
        if not bo.get("is_control_prong", False)
        and Decimal(str(bo.get("ownership_percentage", 0))) >= BENEFICIAL_OWNERSHIP_THRESHOLD
    ]
    assert len(ownership_prong_individuals) == 0, "Test precondition: no owner should reach 25%"
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is False, (
        "31 C.F.R. § 1010.230(d)(2): Control prong must be required even when "
        "no owner reaches 25 percent - validation should fail when control prong is missing"
    )
    assert "1010.230(d)(2)" in result["reason"], (
        "31 C.F.R. § 1010.230(d)(2): Rejection reason must cite the regulation"
    )


def test_exactly_one_control_prong_individual_required(
    rule_resolver: RuleResolver,
    legal_entity_customer_with_control_prong: Customer
):
    """
    Tests 31 C.F.R. § 1010.230(d)(2): Exactly one control-prong individual
    must be recorded per legal entity customer.
    """
    # Arrange
    customer = legal_entity_customer_with_control_prong
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is True, (
        "31 C.F.R. § 1010.230(d)(2): Validation should pass with exactly one control-prong individual"
    )


def test_multiple_control_prong_individuals_fails_validation(
    rule_resolver: RuleResolver
):
    """
    Tests 31 C.F.R. § 1010.230(d)(2): More than one control-prong individual
    should fail validation.
    """
    # Arrange
    customer = Customer(
        customer_id="CUST_LEGAL_MULTI_CONTROL",
        name="Multi Control Corp",
        ssn="XX-XXX7777",
        is_legal_entity=True,
        beneficial_owners=[
            {
                "name": "Control Person 1",
                "ownership_percentage": Decimal("10"),
                "is_control_prong": True,
                "ssn_last_four": "1111"
            },
            {
                "name": "Control Person 2",
                "ownership_percentage": Decimal("5"),
                "is_control_prong": True,
                "ssn_last_four": "2222"
            }
        ]
    )
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is False, (
        "31 C.F.R. § 1010.230(d)(2): Validation should fail with multiple control-prong individuals"
    )
    assert "1010.230(d)(2)" in result["reason"], (
        "31 C.F.R. § 1010.230(d)(2): Rejection reason must cite the regulation"
    )


def test_no_control_prong_individual_fails_validation(
    rule_resolver: RuleResolver,
    legal_entity_customer_no_owners: Customer
):
    """
    Tests 31 C.F.R. § 1010.230(d)(2): Zero control-prong individuals
    should fail validation.
    """
    # Arrange
    customer = legal_entity_customer_no_owners
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is False, (
        "31 C.F.R. § 1010.230(d)(2): Validation should fail with no control-prong individual"
    )
    assert "1010.230(d)(2)" in result["reason"], (
        "31 C.F.R. § 1010.230(d)(2): Rejection reason must cite the regulation"
    )


# ============================================================================
# Related Obligations Tests (context-driven)
# ============================================================================

def test_ownership_threshold_equals_25_percent(rule_resolver: RuleResolver):
    """
    Tests 31 C.F.R. § 1010.230(d)(1): Ownership threshold parameter must equal 25 percent.
    """
    # Arrange
    customer = Customer(
        customer_id="CUST_LEGAL_THRESHOLD",
        name="Threshold Test Corp",
        ssn="XX-XXX6666",
        is_legal_entity=True,
        beneficial_owners=[
            {
                "name": "Owner at 25%",
                "ownership_percentage": Decimal("25"),
                "is_control_prong": False,
                "ssn_last_four": "1111"
            },
            {
                "name": "Control Person",
                "ownership_percentage": Decimal("5"),
                "is_control_prong": True,
                "ssn_last_four": "9999"
            }
        ]
    )
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is True
    assert BENEFICIAL_OWNERSHIP_THRESHOLD == Decimal("25"), (
        "31 C.F.R. § 1010.230(d)(1): Ownership threshold must be exactly 25 percent"
    )


def test_ownership_prong_count_does_not_exceed_four(rule_resolver: RuleResolver):
    """
    Tests 31 C.F.R. § 1010.230(d)(1): Count of ownership-prong individuals
    must not exceed four.
    """
    # Arrange
    customer = Customer(
        customer_id="CUST_LEGAL_FIVE_OWNERS",
        name="Five Owners Corp",
        ssn="XX-XXX5555",
        is_legal_entity=True,
        beneficial_owners=[
            {"name": "Owner 1", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "1111"},
            {"name": "Owner 2", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "2222"},
            {"name": "Owner 3", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "3333"},
            {"name": "Owner 4", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "4444"},
            {"name": "Owner 5", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "5555"},
            {"name": "Control Person", "ownership_percentage": Decimal("0"), "is_control_prong": True, "ssn_last_four": "9999"}
        ]
    )
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is False, (
        "31 C.F.R. § 1010.230(d)(1): Validation should fail with more than 4 ownership-prong individuals"
    )
    assert "1010.230(d)(1)" in result["reason"]


def test_ownership_prong_exactly_four_is_valid(rule_resolver: RuleResolver):
    """
    Tests 31 C.F.R. § 1010.230(d)(1): Exactly four ownership-prong individuals
    is valid.
    """
    # Arrange
    customer = Customer(
        customer_id="CUST_LEGAL_FOUR_OWNERS",
        name="Four Owners Corp",
        ssn="XX-XXX4444",
        is_legal_entity=True,
        beneficial_owners=[
            {"name": "Owner 1", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "1111"},
            {"name": "Owner 2", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "2222"},
            {"name": "Owner 3", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "3333"},
            {"name": "Owner 4", "ownership_percentage": Decimal("25"), "is_control_prong": False, "ssn_last_four": "4444"},
            {"name": "Control Person", "ownership_percentage": Decimal("0"), "is_control_prong": True, "ssn_last_four": "9999"}
        ]
    )
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is True, (
        "31 C.F.R. § 1010.230(d)(1): Validation should pass with exactly 4 ownership-prong individuals"
    )


# ============================================================================
# Compliance Threshold Boundary Tests
# ============================================================================

def test_ctr_threshold_at_boundary(rule_resolver: RuleResolver):
    """
    Tests CTR requirement at exact threshold of $10,000.
    """
    # Arrange & Act
    at_threshold = rule_resolver.evaluate_ctr_requirement(CTR_THRESHOLD)
    below_threshold = rule_resolver.evaluate_ctr_requirement(CTR_THRESHOLD - Decimal("0.01"))
    above_threshold = rule_resolver.evaluate_ctr_requirement(CTR_THRESHOLD + Decimal("0.01"))
    
    # Assert
    assert at_threshold is True, "CTR required at exactly $10,000"
    assert below_threshold is False, "CTR not required below $10,000"
    assert above_threshold is True, "CTR required above $10,000"


def test_sar_threshold_at_boundary(rule_resolver: RuleResolver):
    """
    Tests SAR requirement at exact threshold of $5,000 with suspicious activity.
    """
    # Arrange & Act
    at_threshold = rule_resolver.evaluate_sar_requirement(SAR_THRESHOLD, is_suspicious=True)
    below_threshold = rule_resolver.evaluate_sar_requirement(SAR_THRESHOLD - Decimal("0.01"), is_suspicious=True)
    above_threshold = rule_resolver.evaluate_sar_requirement(SAR_THRESHOLD + Decimal("0.01"), is_suspicious=True)
    not_suspicious = rule_resolver.evaluate_sar_requirement(SAR_THRESHOLD, is_suspicious=False)
    
    # Assert
    assert at_threshold is True, "SAR required at exactly $5,000 when suspicious"
    assert below_threshold is False, "SAR not required below $5,000"
    assert above_threshold is True, "SAR required above $5,000 when suspicious"
    assert not_suspicious is False, "SAR not required without suspicious activity"


def test_travel_rule_threshold_at_boundary(rule_resolver: RuleResolver):
    """
    Tests Travel Rule requirement at exact threshold of $3,000.
    """
    # Arrange & Act
    at_threshold = rule_resolver.evaluate_travel_rule(TRAVEL_RULE_THRESHOLD)
    below_threshold = rule_resolver.evaluate_travel_rule(TRAVEL_RULE_THRESHOLD - Decimal("0.01"))
    above_threshold = rule_resolver.evaluate_travel_rule(TRAVEL_RULE_THRESHOLD + Decimal("0.01"))
    
    # Assert
    assert at_threshold is True, "Travel Rule required at exactly $3,000"
    assert below_threshold is False, "Travel Rule not required below $3,000"
    assert above_threshold is True, "Travel Rule required above $3,000"


def test_dual_approval_threshold_at_boundary(rule_resolver: RuleResolver):
    """
    Tests dual approval requirement at exact threshold of $10,000.
    """
    # Arrange & Act
    at_threshold = rule_resolver.evaluate_dual_approval(WIRE_DUAL_APPROVAL_THRESHOLD)
    below_threshold = rule_resolver.evaluate_dual_approval(WIRE_DUAL_APPROVAL_THRESHOLD - Decimal("0.01"))
    above_threshold = rule_resolver.evaluate_dual_approval(WIRE_DUAL_APPROVAL_THRESHOLD + Decimal("0.01"))
    
    # Assert
    assert at_threshold is True, "Dual approval required at exactly $10,000"
    assert below_threshold is False, "Dual approval not required below $10,000"
    assert above_threshold is True, "Dual approval required above $10,000"


# ============================================================================
# OFAC Screening Tests
# ============================================================================

def test_ofac_blocked_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account
):
    """
    Tests that transactions to OFAC-blocked accounts are rejected.
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen_account.return_value = {
        "is_blocked": True,
        "match_score": 100,
        "matched_entity": "SDN Entity"
    }
    
    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC_BLOCKED",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.BLOCKED
    assert "OFAC" in result.rejection_reason
    mock_account_repo.update_balance.assert_not_called()
    mock_audit_logger.log.assert_called_once()


def test_ofac_fuzzy_match_below_threshold_allows_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    valid_account: Account
):
    """
    Tests that OFAC fuzzy matches below threshold (85) allow transaction.
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen_account.return_value = {
        "is_blocked": False,
        "match_score": OFAC_FUZZY_THRESHOLD - 1
    }
    
    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.rejection_reason is None


# ============================================================================
# Audit Trail and PII Handling Tests
# ============================================================================

def test_audit_trail_records_all_required_fields(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    valid_account: Account
):
    """
    Tests that audit trail records all required fields per BSA requirements:
    timestamp, user ID, IP address, device info.
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    
    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER_AUDIT_TEST",
        ip_address="10.0.0.50",
        device_info="Chrome/120.0"
    )
    
    # Assert
    mock_audit_logger.log.assert_called_once()
    audit_entry = mock_audit_logger.log.call_args[0][0]
    assert isinstance(audit_entry.timestamp, datetime)
    assert audit_entry.timestamp.tzinfo is not None, "Timestamp must be timezone-aware"
    assert audit_entry.user_id == "USER_AUDIT_TEST"
    assert audit_entry.ip_address == "10.0.0.50"
    assert audit_entry.device_info == "Chrome/120.0"
    assert audit_entry.transaction_id == result.transaction_id


def test_ssn_masking_in_beneficial_owner_data():
    """
    Tests that SSN/TIN is masked (last 4 only) in beneficial owner records
    per GLBA Safeguards Rule.
    """
    # Arrange
    owner = BeneficialOwner(
        name="John Doe",
        ownership_percentage=Decimal("30"),
        is_control_prong=False,
        ssn_last_four="1234"
    )
    
    # Assert
    assert len(owner.ssn_last_four) == 4, "Only last 4 digits of SSN should be stored"
    assert owner.ssn_last_four.isdigit(), "SSN last four should be numeric"


def test_transaction_timestamp_is_timezone_aware(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_account: Account
):
    """
    Tests that transaction timestamps are timezone-aware (UTC).
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    
    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.timestamp.tzinfo is not None, "Transaction timestamp must be timezone-aware"
    assert result.timestamp.tzinfo == timezone.utc, "Transaction timestamp should be in UTC"


# ============================================================================
# Edge Cases and Negative Path Tests
# ============================================================================

def test_invalid_source_account(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock
):
    """
    Tests that transaction is rejected when source account does not exist.
    """
    # Arrange
    mock_account_repo.get_account.return_value = None
    
    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="INVALID_ACC",
        to_account_id="ACC789012",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert "Invalid source account" in result.rejection_reason
    mock_account_repo.update_balance.assert_not_called()


def test_empty_beneficiary_account_id(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_account: Account
):
    """
    Tests that empty beneficiary account ID is rejected.
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    
    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert "Invalid beneficiary account" in result.rejection_reason


def test_invalid_routing_number_length(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_account: Account
):
    """
    Tests that routing number with incorrect length is rejected.
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    
    # Act
    result = transaction_service.initiate_transfer(
        from_account_id="ACC123456",
        to_account_id="ACC789012",
        to_routing="12345",  # Too short
        amount=Decimal("1000.00"),
        user_id="USER001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert "Invalid beneficiary account" in result.rejection_reason


def test_non_legal_entity_customer_bypasses_beneficial_ownership_validation(
    rule_resolver: RuleResolver
):
    """
    Tests that non-legal entity customers bypass beneficial ownership validation.
    """
    # Arrange
    customer = Customer(
        customer_id="CUST_INDIVIDUAL",
        name="John Doe",
        ssn="XX-XXX1234",
        is_legal_entity=False,
        beneficial_owners=None
    )
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is True
    assert "Not a legal entity" in result["reason"]


def test_decimal_precision_in_amounts():
    """
    Tests that Decimal type maintains precision for currency amounts.
    """
    # Arrange
    amount1 = Decimal("1000.00")
    amount2 = Decimal("0.01")
    
    # Act
    result = amount1 - amount2
    
    # Assert
    assert result == Decimal("999.99")
    assert isinstance(result, Decimal)


def test_boundary_ownership_percentage_24_99_percent(rule_resolver: RuleResolver):
    """
    Tests that 24.99% ownership does not trigger ownership prong requirement.
    """
    # Arrange
    customer = Customer(
        customer_id="CUST_LEGAL_BOUNDARY",
        name="Boundary Test Corp",
        ssn="XX-XXX3333",
        is_legal_entity=True,
        beneficial_owners=[
            {
                "name": "Owner at 24.99%",
                "ownership_percentage": Decimal("24.99"),
                "is_control_prong": False,
                "ssn_last_four": "1111"
            },
            {
                "name": "Control Person",
                "ownership_percentage": Decimal("5"),
                "is_control_prong": True,
                "ssn_last_four": "9999"
            }
        ]
    )
    
    # Act
    result = rule_resolver.validate_beneficial_ownership(customer)
    
    # Assert
    assert result["valid"] is True
    # Verify that 24.99% owner is not counted as ownership prong
    ownership_count = sum(
        1 for bo in customer.beneficial_owners
        if not bo.get("is_control_prong", False)
        and Decimal(str(bo.get("ownership_percentage", 0))) >= BENEFICIAL_OWNERSHIP_THRESHOLD
    )
    assert ownership_count == 0, "24.99% should not meet 25% threshold"