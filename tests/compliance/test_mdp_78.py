import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# Constants based on U.S. banking compliance requirements
CTR_THRESHOLD = Decimal("10000")
SAR_THRESHOLD = Decimal("5000")
TRAVEL_RULE_THRESHOLD = Decimal("3000")
WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
OFAC_FUZZY_THRESHOLD = 85
BENEFICIAL_OWNERSHIP_PCT = 20


class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    PENDING_REVIEW = "PENDING_REVIEW"
    BLOCKED = "BLOCKED"


class OFACStatus(Enum):
    CLEAR = "CLEAR"
    MATCH = "MATCH"
    REVIEW = "REVIEW"


@dataclass
class Account:
    account_number: str
    routing_number: str
    balance: Decimal
    user_id: str
    status: str = "ACTIVE"


@dataclass
class TransactionRequest:
    from_account: str
    to_account: str
    to_routing: str
    amount: Decimal
    user_id: str
    ip_address: str
    device_info: str
    timestamp: datetime


@dataclass
class TransactionResult:
    status: TransactionStatus
    transaction_id: Optional[str]
    message: str
    audit_log_id: Optional[str]
    new_balance: Optional[Decimal]
    ofac_status: Optional[OFACStatus] = None
    ctr_filed: bool = False
    sar_filed: bool = False


class AuditLogger:
    def log_transaction(
        self,
        transaction_id: str,
        user_id: str,
        amount: Decimal,
        status: str,
        ip_address: str,
        device_info: str,
        timestamp: datetime,
        decision_reason: str,
        metadata: Dict[str, Any]
    ) -> str:
        raise NotImplementedError

    def log_compliance_event(
        self,
        event_type: str,
        user_id: str,
        details: Dict[str, Any],
        timestamp: datetime
    ) -> str:
        raise NotImplementedError


class OFACService:
    def screen_account(self, account_number: str, routing_number: str, name: str) -> OFACStatus:
        raise NotImplementedError

    def get_match_score(self, account_number: str) -> int:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_number: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_number: str, new_balance: Decimal) -> bool:
        raise NotImplementedError

    def lock_account(self, account_number: str) -> bool:
        raise NotImplementedError


class ComplianceEngine:
    def requires_ctr(self, amount: Decimal) -> bool:
        return amount >= CTR_THRESHOLD

    def requires_sar(self, amount: Decimal, pattern_suspicious: bool = False) -> bool:
        return amount >= SAR_THRESHOLD or pattern_suspicious

    def requires_dual_approval(self, amount: Decimal) -> bool:
        return amount >= WIRE_DUAL_APPROVAL_THRESHOLD

    def requires_travel_rule_data(self, amount: Decimal) -> bool:
        return amount >= TRAVEL_RULE_THRESHOLD


class TransactionService:
    def __init__(
        self,
        account_repo: AccountRepository,
        audit_logger: AuditLogger,
        ofac_service: OFACService,
        compliance_engine: ComplianceEngine
    ):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.compliance_engine = compliance_engine

    def process_transaction(self, request: TransactionRequest) -> TransactionResult:
        timestamp = request.timestamp or datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        # Validate amount
        if request.amount == Decimal("0"):
            self._log_rejection(request, transaction_id, "Amount must be greater than 0")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Amount must be greater than 0",
                audit_log_id=transaction_id,
                new_balance=None
            )

        if request.amount < Decimal("0"):
            self._log_rejection(request, transaction_id, "Invalid amount")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Invalid amount",
                audit_log_id=transaction_id,
                new_balance=None
            )

        # Get source account
        from_account = self.account_repo.get_account(request.from_account)
        if not from_account:
            self._log_rejection(request, transaction_id, "Invalid source account")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Invalid source account",
                audit_log_id=transaction_id,
                new_balance=None
            )

        # Check sufficient balance
        if from_account.balance < request.amount:
            self._log_rejection(request, transaction_id, "Insufficient balance")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Insufficient balance",
                audit_log_id=transaction_id,
                new_balance=None
            )

        # Validate beneficiary account
        if not self._validate_beneficiary(request.to_account, request.to_routing):
            self._log_rejection(request, transaction_id, "Invalid beneficiary account")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Invalid beneficiary account",
                audit_log_id=transaction_id,
                new_balance=None
            )

        # OFAC screening
        ofac_status = self.ofac_service.screen_account(
            request.to_account,
            request.to_routing,
            "Beneficiary Name"
        )

        if ofac_status == OFACStatus.MATCH:
            self._log_ofac_block(request, transaction_id)
            return TransactionResult(
                status=TransactionStatus.BLOCKED,
                transaction_id=transaction_id,
                message="Transaction blocked - OFAC match",
                audit_log_id=transaction_id,
                new_balance=None,
                ofac_status=ofac_status
            )

        # Process transaction
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account, new_balance)

        # Compliance checks
        ctr_filed = False
        sar_filed = False

        if self.compliance_engine.requires_ctr(request.amount):
            ctr_filed = True
            self.audit_logger.log_compliance_event(
                "CTR_FILED",
                request.user_id,
                {"amount": str(request.amount), "transaction_id": transaction_id},
                timestamp
            )

        if self.compliance_engine.requires_sar(request.amount):
            sar_filed = True
            self.audit_logger.log_compliance_event(
                "SAR_FILED",
                request.user_id,
                {"amount": str(request.amount), "transaction_id": transaction_id},
                timestamp
            )

        # Audit trail
        audit_log_id = self.audit_logger.log_transaction(
            transaction_id=transaction_id,
            user_id=self._mask_pii(request.user_id),
            amount=request.amount,
            status="SUCCESS",
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=timestamp,
            decision_reason="Transaction approved",
            metadata={
                "from_account": self._mask_account(request.from_account),
                "to_account": self._mask_account(request.to_account),
                "ctr_filed": ctr_filed,
                "sar_filed": sar_filed,
                "ofac_status": ofac_status.value if ofac_status else None
            }
        )

        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction successful",
            audit_log_id=audit_log_id,
            new_balance=new_balance,
            ofac_status=ofac_status,
            ctr_filed=ctr_filed,
            sar_filed=sar_filed
        )

    def _validate_beneficiary(self, account_number: str, routing_number: str) -> bool:
        if not account_number or not routing_number:
            return False
        if len(routing_number) != 9:
            return False
        if not routing_number.isdigit():
            return False
        return True

    def _log_rejection(self, request: TransactionRequest, transaction_id: str, reason: str):
        self.audit_logger.log_transaction(
            transaction_id=transaction_id,
            user_id=self._mask_pii(request.user_id),
            amount=request.amount,
            status="REJECTED",
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=request.timestamp,
            decision_reason=reason,
            metadata={}
        )

    def _log_ofac_block(self, request: TransactionRequest, transaction_id: str):
        self.audit_logger.log_transaction(
            transaction_id=transaction_id,
            user_id=self._mask_pii(request.user_id),
            amount=request.amount,
            status="BLOCKED",
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=request.timestamp,
            decision_reason="OFAC match",
            metadata={"ofac_blocked": True}
        )

    def _mask_pii(self, user_id: str) -> str:
        """Mask SSN/TIN showing only last 4 digits per GLBA requirements."""
        if len(user_id) > 4:
            return "*" * (len(user_id) - 4) + user_id[-4:]
        return user_id

    def _mask_account(self, account_number: str) -> str:
        """Mask account number showing only last 4 digits."""
        if len(account_number) > 4:
            return "*" * (len(account_number) - 4) + account_number[-4:]
        return account_number


# Fixtures

@pytest.fixture
def mock_account_repo() -> Mock:
    """Mock account repository for testing."""
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_audit_logger() -> Mock:
    """Mock audit logger for testing."""
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = "AUDIT-12345"
    logger.log_compliance_event.return_value = "COMPLIANCE-12345"
    return logger


@pytest.fixture
def mock_ofac_service() -> Mock:
    """Mock OFAC service for testing."""
    service = Mock(spec=OFACService)
    service.screen_account.return_value = OFACStatus.CLEAR
    service.get_match_score.return_value = 0
    return service


@pytest.fixture
def compliance_engine() -> ComplianceEngine:
    """Real compliance engine for testing."""
    return ComplianceEngine()


@pytest.fixture
def transaction_service(
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    compliance_engine: ComplianceEngine
) -> TransactionService:
    """Transaction service with mocked dependencies."""
    return TransactionService(
        account_repo=mock_account_repo,
        audit_logger=mock_audit_logger,
        ofac_service=mock_ofac_service,
        compliance_engine=compliance_engine
    )


@pytest.fixture
def valid_account() -> Account:
    """Valid account with sufficient balance."""
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-123456789",
        status="ACTIVE"
    )


@pytest.fixture
def transaction_timestamp() -> datetime:
    """Fixed timestamp for deterministic testing."""
    return datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)


# Test Cases - Scenario: successful_transaction

def test_successful_transaction_with_valid_account_and_balance(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("500.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.transaction_id is not None
    assert result.message == "Transaction successful"
    assert result.new_balance == Decimal("9500.00")
    assert result.audit_log_id == "AUDIT-12345"

    # Verify balance was updated
    mock_account_repo.update_balance.assert_called_once_with(
        "1234567890",
        Decimal("9500.00")
    )

    # Verify audit trail was recorded
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["user_id"] == "*****6789"  # PII masked
    assert call_args["amount"] == Decimal("500.00")
    assert call_args["status"] == "SUCCESS"
    assert call_args["ip_address"] == "192.168.1.100"
    assert call_args["device_info"] == "Mozilla/5.0"
    assert call_args["timestamp"] == transaction_timestamp


def test_successful_transaction_records_immutable_audit_log(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """
    Verify immutable audit log requirement per 31 CFR 1010.430.
    All transaction details must be recorded with timestamp.
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="SSN-123456789",
        ip_address="10.0.0.1",
        device_info="iOS 17.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_transaction.assert_called_once()

    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert "transaction_id" in call_args
    assert call_args["timestamp"] == transaction_timestamp
    assert "metadata" in call_args
    assert call_args["user_id"] == "*****6789"  # SSN masked per GLBA


# Test Cases - Scenario: zero_amount_transfer

def test_zero_amount_transfer_rejected(
    transaction_service: TransactionService,
    mock_audit_logger: Mock,
    transaction_timestamp: datetime
):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("0"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Amount must be greater than 0"
    assert result.new_balance is None

    # Verify rejection was logged
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["status"] == "REJECTED"
    assert call_args["decision_reason"] == "Amount must be greater than 0"


# Test Cases - Scenario: negative_amount_transfer

def test_negative_amount_transfer_rejected(
    transaction_service: TransactionService,
    mock_audit_logger: Mock,
    transaction_timestamp: datetime
):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("-100.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Safari/17.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid amount"
    assert result.new_balance is None

    # Verify rejection was logged
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["status"] == "REJECTED"
    assert call_args["decision_reason"] == "Invalid amount"


def test_negative_amount_boundary_cases(
    transaction_service: TransactionService,
    transaction_timestamp: datetime
):
    """Test various negative amount edge cases."""
    # Arrange & Act & Assert
    for amount in [Decimal("-0.01"), Decimal("-1000.00"), Decimal("-999999.99")]:
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=amount,
            user_id="USER-123456789",
            ip_address="192.168.1.100",
            device_info="Test",
            timestamp=transaction_timestamp
        )
        result = transaction_service.process_transaction(request)
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"


# Test Cases - Scenario: insufficient_balance

def test_insufficient_balance_rejected(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    transaction_timestamp: datetime
):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    account = Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER-123456789",
        status="ACTIVE"
    )
    mock_account_repo.get_account.return_value = account

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("5000.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Firefox/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"
    assert result.new_balance is None

    # Verify balance was not updated
    mock_account_repo.update_balance.assert_not_called()

    # Verify rejection was logged
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["status"] == "REJECTED"
    assert call_args["decision_reason"] == "Insufficient balance"


def test_insufficient_balance_boundary_case(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    transaction_timestamp: datetime
):
    """Test transaction amount exactly one cent over balance."""
    # Arrange
    account = Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER-123456789",
        status="ACTIVE"
    )
    mock_account_repo.get_account.return_value = account

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("1000.01"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Test",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"


# Test Cases - Scenario: invalid_beneficiary

def test_invalid_beneficiary_routing_number_rejected(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    mock_account_repo.get_account.return_value = valid_account

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="INVALID",  # Invalid routing number
        amount=Decimal("500.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"
    assert result.new_balance is None

    # Verify rejection was logged
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["status"] == "REJECTED"
    assert call_args["decision_reason"] == "Invalid beneficiary account"


def test_invalid_beneficiary_empty_account_number(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test empty beneficiary account number."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account

    request = TransactionRequest(
        from_account="1234567890",
        to_account="",  # Empty account number
        to_routing="021000021",
        amount=Decimal("500.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Test",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"


def test_invalid_beneficiary_wrong_routing_length(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test routing number with incorrect length (not 9 digits)."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="12345",  # Too short
        amount=Decimal("500.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Test",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"


# OFAC/SDN Screening Tests

def test_ofac_match_blocks_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test transaction blocked when OFAC match detected."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen_account.return_value = OFACStatus.MATCH

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.BLOCKED
    assert result.message == "Transaction blocked - OFAC match"
    assert result.ofac_status == OFACStatus.MATCH
    assert result.new_balance is None

    # Verify balance was not updated
    mock_account_repo.update_balance.assert_not_called()

    # Verify OFAC block was logged
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["status"] == "BLOCKED"
    assert call_args["decision_reason"] == "OFAC match"


def test_ofac_clear_allows_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test transaction proceeds when OFAC screening is clear."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.ofac_status == OFACStatus.CLEAR


# CTR Filing Tests

def test_ctr_filed_for_transaction_at_threshold(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    transaction_timestamp: datetime
):
    """Test CTR filed for transaction at $10,000 threshold."""
    # Arrange
    account = Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("20000.00"),
        user_id="USER-123456789",
        status="ACTIVE"
    )
    mock_account_repo.get_account.return_value = account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=CTR_THRESHOLD,  # Exactly $10,000
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.ctr_filed is True

    # Verify CTR compliance event was logged
    mock_audit_logger.log_compliance_event.assert_any_call(
        "CTR_FILED",
        "USER-123456789",
        {"amount": "10000", "transaction_id": result.transaction_id},
        transaction_timestamp
    )


def test_ctr_filed_for_transaction_above_threshold(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    transaction_timestamp: datetime
):
    """Test CTR filed for transaction above $10,000 threshold."""
    # Arrange
    account = Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        user_id="USER-123456789",
        status="ACTIVE"
    )
    mock_account_repo.get_account.return_value = account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("15000.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.ctr_filed is True


def test_ctr_not_filed_below_threshold(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test CTR not filed for transaction below $10,000 threshold."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("9999.99"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.ctr_filed is False


# SAR Filing Tests

def test_sar_filed_for_transaction_at_threshold(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    transaction_timestamp: datetime
):
    """Test SAR filed for transaction at $5,000 threshold."""
    # Arrange
    account = Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("20000.00"),
        user_id="USER-123456789",
        status="ACTIVE"
    )
    mock_account_repo.get_account.return_value = account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=SAR_THRESHOLD,  # Exactly $5,000
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.sar_filed is True

    # Verify SAR compliance event was logged
    mock_audit_logger.log_compliance_event.assert_any_call(
        "SAR_FILED",
        "USER-123456789",
        {"amount": "5000", "transaction_id": result.transaction_id},
        transaction_timestamp
    )


def test_sar_not_filed_below_threshold(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test SAR not filed for transaction below $5,000 threshold."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("4999.99"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.sar_filed is False


# PII Masking Tests

def test_ssn_masked_in_audit_log(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test SSN/TIN masked per GLBA Safeguards Rule (show last 4 only)."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="123-45-6789",  # SSN format
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS

    # Verify SSN was masked in audit log
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["user_id"] == "*******6789"  # Only last 4 visible


def test_account_number_masked_in_audit_metadata(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    transaction_timestamp: datetime
):
    """Test account numbers masked in audit log metadata."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS

    # Verify account numbers were masked in metadata
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    metadata = call_args["metadata"]
    assert metadata["from_account"] == "******7890"
    assert metadata["to_account"] == "******3210"


# Compliance Engine Tests

def test_compliance_engine_requires_ctr_at_threshold():
    """Test compliance engine CTR threshold logic."""
    # Arrange
    engine = ComplianceEngine()

    # Act & Assert
    assert engine.requires_ctr(Decimal("10000.00")) is True
    assert engine.requires_ctr(Decimal("10000.01")) is True
    assert engine.requires_ctr(Decimal("9999.99")) is False


def test_compliance_engine_requires_sar_at_threshold():
    """Test compliance engine SAR threshold logic."""
    # Arrange
    engine = ComplianceEngine()

    # Act & Assert
    assert engine.requires_sar(Decimal("5000.00")) is True
    assert engine.requires_sar(Decimal("5000.01")) is True
    assert engine.requires_sar(Decimal("4999.99")) is False


def test_compliance_engine_requires_dual_approval_at_threshold():
    """Test compliance engine dual approval threshold logic."""
    # Arrange
    engine = ComplianceEngine()

    # Act & Assert
    assert engine.requires_dual_approval(Decimal("10000.00")) is True
    assert engine.requires_dual_approval(Decimal("10000.01")) is True
    assert engine.requires_dual_approval(Decimal("9999.99")) is False


def test_compliance_engine_requires_travel_rule_data_at_threshold():
    """Test compliance engine travel rule threshold logic."""
    # Arrange
    engine = ComplianceEngine()

    # Act & Assert
    assert engine.requires_travel_rule_data(Decimal("3000.00")) is True
    assert engine.requires_travel_rule_data(Decimal("3000.01")) is True
    assert engine.requires_travel_rule_data(Decimal("2999.99")) is False


# Edge Case Tests

def test_invalid_source_account_rejected(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    transaction_timestamp: datetime
):
    """Test transaction rejected when source account does not exist."""
    # Arrange
    mock_account_repo.get_account.return_value = None

    request = TransactionRequest(
        from_account="9999999999",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid source account"


def test_transaction_with_exact_balance_succeeds(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    transaction_timestamp: datetime
):
    """Test transaction with amount exactly equal to balance."""
    # Arrange
    account = Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER-123456789",
        status="ACTIVE"
    )
    mock_account_repo.get_account.return_value = account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("1000.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.new_balance == Decimal("0.00")


def test_high_precision_decimal_amounts(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    transaction_timestamp: datetime
):
    """Test transaction with high precision decimal amounts."""
    # Arrange
    account = Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("1000.123456"),
        user_id="USER-123456789",
        status="ACTIVE"
    )
    mock_account_repo.get_account.return_value = account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.123456"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=transaction_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.new_balance == Decimal("900.000000")


def test_timezone_aware_timestamp_recorded(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    mock_ofac_service: Mock,
    valid_account: Account
):
    """Test that timezone-aware timestamps are properly recorded."""
    # Arrange
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen_account.return_value = OFACStatus.CLEAR

    utc_timestamp = datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc)

    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER-123456789",
        ip_address="192.168.1.100",
        device_info="Chrome/120.0",
        timestamp=utc_timestamp
    )

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_transaction.assert_called_once()
    call_args = mock_audit_logger.log_transaction.call_args[1]
    assert call_args["timestamp"] == utc_timestamp
    assert call_args["timestamp"].tzinfo == timezone.utc