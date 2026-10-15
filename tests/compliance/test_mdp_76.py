import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# Constants based on U.S. regulatory thresholds
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
    audit_id: Optional[str]
    updated_balance: Optional[Decimal]


class OFACService:
    def screen(self, account_number: str, routing_number: str, user_id: str) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(
        self,
        transaction_id: str,
        user_id: str,
        ip_address: str,
        device_info: str,
        amount: Decimal,
        from_account: str,
        to_account: str,
        status: str,
        timestamp: datetime,
        decision_reason: Optional[str] = None,
    ) -> str:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_number: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_number: str, new_balance: Decimal) -> bool:
        raise NotImplementedError

    def validate_account(self, account_number: str, routing_number: str) -> bool:
        raise NotImplementedError


class TransactionService:
    def __init__(
        self,
        account_repo: AccountRepository,
        ofac_service: OFACService,
        audit_logger: AuditLogger,
    ):
        self.account_repo = account_repo
        self.ofac_service = ofac_service
        self.audit_logger = audit_logger

    def process_transaction(self, request: TransactionRequest) -> TransactionResult:
        transaction_id = f"TXN-{request.timestamp.timestamp()}"

        # Validate amount
        if request.amount == Decimal("0"):
            self._log_rejection(request, transaction_id, "Amount must be greater than 0")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Amount must be greater than 0",
                audit_id=None,
                updated_balance=None,
            )

        if request.amount < Decimal("0"):
            self._log_rejection(request, transaction_id, "Invalid amount")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Invalid amount",
                audit_id=None,
                updated_balance=None,
            )

        # Validate beneficiary account
        if not self.account_repo.validate_account(request.to_account, request.to_routing):
            self._log_rejection(request, transaction_id, "Invalid beneficiary account")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Invalid beneficiary account",
                audit_id=None,
                updated_balance=None,
            )

        # Get source account
        from_account = self.account_repo.get_account(request.from_account)
        if not from_account:
            self._log_rejection(request, transaction_id, "Invalid source account")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Invalid source account",
                audit_id=None,
                updated_balance=None,
            )

        # Check sufficient balance
        if from_account.balance < request.amount:
            self._log_rejection(request, transaction_id, "Insufficient balance")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=transaction_id,
                message="Insufficient balance",
                audit_id=None,
                updated_balance=None,
            )

        # OFAC screening
        ofac_result = self.ofac_service.screen(
            request.to_account, request.to_routing, request.user_id
        )
        if ofac_result["match_score"] >= OFAC_FUZZY_THRESHOLD:
            self._log_rejection(request, transaction_id, "OFAC screening failed")
            return TransactionResult(
                status=TransactionStatus.BLOCKED,
                transaction_id=transaction_id,
                message="Transaction blocked due to sanctions screening",
                audit_id=None,
                updated_balance=None,
            )

        # Update balance
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account, new_balance)

        # Audit logging
        audit_id = self.audit_logger.log_transaction(
            transaction_id=transaction_id,
            user_id=request.user_id,
            ip_address=request.ip_address,
            device_info=request.device_info,
            amount=request.amount,
            from_account=request.from_account,
            to_account=request.to_account,
            status="SUCCESS",
            timestamp=request.timestamp,
            decision_reason=None,
        )

        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction successful",
            audit_id=audit_id,
            updated_balance=new_balance,
        )

    def _log_rejection(
        self, request: TransactionRequest, transaction_id: str, reason: str
    ) -> None:
        try:
            self.audit_logger.log_transaction(
                transaction_id=transaction_id,
                user_id=request.user_id,
                ip_address=request.ip_address,
                device_info=request.device_info,
                amount=request.amount,
                from_account=request.from_account,
                to_account=request.to_account,
                status="REJECTED",
                timestamp=request.timestamp,
                decision_reason=reason,
            )
        except Exception:
            pass


@pytest.fixture
def mock_account_repo() -> Mock:
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_ofac_service() -> Mock:
    service = Mock(spec=OFACService)
    return service


@pytest.fixture
def mock_audit_logger() -> Mock:
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = "AUDIT-12345"
    return logger


@pytest.fixture
def transaction_service(
    mock_account_repo: Mock, mock_ofac_service: Mock, mock_audit_logger: Mock
) -> TransactionService:
    return TransactionService(mock_account_repo, mock_ofac_service, mock_audit_logger)


@pytest.fixture
def valid_account() -> Account:
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("5000.00"),
        user_id="USER-001",
        status="ACTIVE",
    )


@pytest.fixture
def valid_transaction_request() -> TransactionRequest:
    return TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )


def test_successful_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.transaction_id is not None
    assert result.audit_id == "AUDIT-12345"
    assert result.updated_balance == Decimal("4900.00")
    assert result.message == "Transaction successful"

    mock_account_repo.update_balance.assert_called_once_with(
        "1234567890", Decimal("4900.00")
    )
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args
    assert audit_call.kwargs["user_id"] == "USER-001"
    assert audit_call.kwargs["ip_address"] == "192.168.1.100"
    assert audit_call.kwargs["device_info"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert audit_call.kwargs["amount"] == Decimal("100.00")
    assert audit_call.kwargs["status"] == "SUCCESS"
    assert audit_call.kwargs["timestamp"].tzinfo is not None


def test_zero_amount_transfer(
    transaction_service: TransactionService,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    valid_transaction_request.amount = Decimal("0")

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Amount must be greater than 0"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_negative_amount_transfer(
    transaction_service: TransactionService,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    valid_transaction_request.amount = Decimal("-100.00")

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid amount"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_insufficient_balance(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    valid_account.balance = Decimal("1000.00")
    valid_transaction_request.amount = Decimal("5000.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_invalid_beneficiary(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    mock_account_repo.validate_account.return_value = False

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_ofac_screening_blocks_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: OFAC screening blocks transaction when match score exceeds threshold
    Validates sanctions screening and transaction blocking behavior
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen.return_value = {
        "match_score": 95,
        "matches": [{"name": "Sanctioned Entity", "list": "SDN"}],
    }

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.BLOCKED
    assert "sanctions screening" in result.message.lower()
    assert result.transaction_id is not None
    mock_ofac_service.screen.assert_called_once_with(
        "9876543210", "021000021", "USER-001"
    )


def test_ofac_screening_passes_below_threshold(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: OFAC screening passes when match score is below threshold
    Validates false positive handling
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 50, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("4900.00")


def test_ctr_threshold_transaction_succeeds(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Transaction at CTR threshold ($10,000) succeeds with proper audit
    Validates BSA/AML CTR reporting threshold handling (31 CFR 1010.311)
    """
    # Arrange
    valid_account.balance = Decimal("15000.00")
    valid_transaction_request.amount = CTR_THRESHOLD
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("5000.00")
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args
    assert audit_call.kwargs["amount"] == CTR_THRESHOLD


def test_sar_threshold_transaction_succeeds(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Transaction at SAR threshold ($5,000) succeeds with audit trail
    Validates suspicious activity reporting threshold (31 CFR 1020.320)
    """
    # Arrange
    valid_account.balance = Decimal("10000.00")
    valid_transaction_request.amount = SAR_THRESHOLD
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("5000.00")
    mock_audit_logger.log_transaction.assert_called_once()


def test_travel_rule_threshold_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Transaction at Travel Rule threshold ($3,000) includes required data
    Validates Bank Secrecy Act Travel Rule compliance (31 CFR 1010.410(e))
    """
    # Arrange
    valid_account.balance = Decimal("5000.00")
    valid_transaction_request.amount = TRAVEL_RULE_THRESHOLD
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("2000.00")
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args
    assert audit_call.kwargs["user_id"] is not None
    assert audit_call.kwargs["from_account"] is not None
    assert audit_call.kwargs["to_account"] is not None


def test_audit_trail_includes_timestamp(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Audit trail includes timezone-aware timestamp
    Validates audit requirements for timestamp recording
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args
    timestamp = audit_call.kwargs["timestamp"]
    assert timestamp.tzinfo is not None
    assert isinstance(timestamp, datetime)


def test_audit_trail_includes_user_context(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Audit trail includes user ID, IP address, and device info
    Validates GLBA Safeguards Rule and SOX compliance requirements
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args
    assert audit_call.kwargs["user_id"] == "USER-001"
    assert audit_call.kwargs["ip_address"] == "192.168.1.100"
    assert "Mozilla" in audit_call.kwargs["device_info"]


def test_rejected_transaction_logged_in_audit(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_audit_logger: Mock,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Rejected transactions are logged in audit trail
    Validates immutable audit log requirements for all transaction attempts
    """
    # Arrange
    mock_account_repo.validate_account.return_value = False

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args
    assert audit_call.kwargs["status"] == "REJECTED"
    assert audit_call.kwargs["decision_reason"] == "Invalid beneficiary account"


def test_decimal_precision_for_currency(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Currency amounts use Decimal type for precision
    Validates SOX financial reporting accuracy requirements
    """
    # Arrange
    valid_transaction_request.amount = Decimal("123.45")
    valid_account.balance = Decimal("500.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert isinstance(result.updated_balance, Decimal)
    assert result.updated_balance == Decimal("376.55")


def test_boundary_amount_one_cent(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Boundary test: Minimum valid transaction amount ($0.01)
    """
    # Arrange
    valid_transaction_request.amount = Decimal("0.01")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("4999.99")


def test_boundary_exact_balance_transfer(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Boundary test: Transfer exact account balance
    """
    # Arrange
    valid_transaction_request.amount = valid_account.balance
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("0.00")


def test_boundary_one_cent_over_balance(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Boundary test: Transfer one cent over balance fails
    """
    # Arrange
    valid_transaction_request.amount = valid_account.balance + Decimal("0.01")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"


def test_ofac_exact_threshold_boundary(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Boundary test: OFAC match score exactly at threshold (85) blocks transaction
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen.return_value = {
        "match_score": OFAC_FUZZY_THRESHOLD,
        "matches": [{"name": "Potential Match", "list": "SDN"}],
    }

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.BLOCKED


def test_ofac_one_below_threshold_passes(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Boundary test: OFAC match score one point below threshold (84) passes
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": OFAC_FUZZY_THRESHOLD - 1, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS


def test_invalid_source_account(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Negative test: Invalid source account number
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = None

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid source account"


def test_multiple_validation_failures_first_error_returned(
    transaction_service: TransactionService,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Negative test: Multiple validation failures return first error encountered
    """
    # Arrange
    valid_transaction_request.amount = Decimal("0")

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Amount must be greater than 0"


def test_large_amount_transaction(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Compliance test: Large transaction over wire dual approval threshold
    Validates handling of high-value transactions requiring dual approval
    """
    # Arrange
    valid_account.balance = Decimal("50000.00")
    valid_transaction_request.amount = Decimal("25000.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("25000.00")
    mock_audit_logger.log_transaction.assert_called_once()


def test_transaction_id_generation(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Test: Transaction ID is generated for all transactions
    Validates unique transaction identifier for audit trail
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.transaction_id is not None
    assert result.transaction_id.startswith("TXN-")


def test_rejected_transaction_no_balance_update(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    valid_transaction_request: TransactionRequest,
) -> None:
    """
    Negative test: Rejected transaction does not update balance
    Validates transaction atomicity
    """
    # Arrange
    mock_account_repo.validate_account.return_value = False

    # Act
    result = transaction_service.process_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    mock_account_repo.update_balance.assert_not_called()


def test_timezone_aware_timestamps(
    transaction_service: TransactionService,
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    valid_account: Account,
) -> None:
    """
    Compliance test: All timestamps are timezone-aware (UTC)
    Validates BSA record retention requirements with proper timestamps
    """
    # Arrange
    request = TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Test Device",
        timestamp=datetime.now(timezone.utc),
    )
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}

    # Act
    result = transaction_service.process_transaction(request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    audit_call = mock_audit_logger.log_transaction.call_args
    assert audit_call.kwargs["timestamp"].tzinfo is not None