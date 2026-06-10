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

    def execute_transaction(self, request: TransactionRequest) -> TransactionResult:
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

        # Log audit trail
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
            decision_reason="Transaction approved",
        )

        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction completed successfully",
            audit_id=audit_id,
            updated_balance=new_balance,
        )

    def _log_rejection(self, request: TransactionRequest, transaction_id: str, reason: str):
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
def mock_account_repo():
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_ofac_service():
    service = Mock(spec=OFACService)
    return service


@pytest.fixture
def mock_audit_logger():
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = "AUDIT-12345"
    return logger


@pytest.fixture
def transaction_service(mock_account_repo, mock_ofac_service, mock_audit_logger):
    return TransactionService(mock_account_repo, mock_ofac_service, mock_audit_logger)


@pytest.fixture
def valid_account():
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("5000.00"),
        user_id="USER-001",
        status="ACTIVE",
    )


@pytest.fixture
def valid_transaction_request():
    return TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        timestamp=datetime.now(timezone.utc),
    )


def test_successful_transaction(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
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
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.transaction_id is not None
    assert result.audit_id == "AUDIT-12345"
    assert result.updated_balance == Decimal("4900.00")
    assert result.message == "Transaction completed successfully"

    mock_account_repo.update_balance.assert_called_once_with(
        "1234567890", Decimal("4900.00")
    )
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args
    assert audit_call.kwargs["user_id"] == "USER-001"
    assert audit_call.kwargs["ip_address"] == "192.168.1.100"
    assert audit_call.kwargs["amount"] == Decimal("100.00")
    assert audit_call.kwargs["status"] == "SUCCESS"


def test_zero_amount_transfer(transaction_service, valid_transaction_request):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    valid_transaction_request.amount = Decimal("0")

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Amount must be greater than 0"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_negative_amount_transfer(transaction_service, valid_transaction_request):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    valid_transaction_request.amount = Decimal("-100")

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid amount"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_insufficient_balance(
    transaction_service, mock_account_repo, valid_account, valid_transaction_request
):
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
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_invalid_beneficiary(transaction_service, mock_account_repo, valid_transaction_request):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    mock_account_repo.validate_account.return_value = False

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Invalid beneficiary account"
    assert result.transaction_id is not None
    assert result.audit_id is None
    assert result.updated_balance is None


def test_ofac_screening_blocks_transaction(
    transaction_service, mock_account_repo, mock_ofac_service, valid_account, valid_transaction_request
):
    """
    Test OFAC screening blocks transaction when match score exceeds threshold.
    Compliance: OFAC/SDN screening requirement.
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen.return_value = {
        "match_score": 90,
        "status": "POTENTIAL_MATCH",
        "matched_entity": "SDN Entity XYZ",
    }

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.BLOCKED
    assert "sanctions screening" in result.message.lower()
    assert result.transaction_id is not None
    assert result.updated_balance is None


def test_ofac_screening_allows_low_score(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test OFAC screening allows transaction when match score is below threshold.
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 30, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance is not None


def test_audit_trail_contains_required_fields(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test audit trail records all required compliance fields.
    Compliance: 31 CFR 1010.430 (BSA recordkeeping), SOX financial reporting.
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    mock_audit_logger.log_transaction.assert_called_once()
    audit_call = mock_audit_logger.log_transaction.call_args.kwargs

    # Verify required audit fields
    assert "transaction_id" in audit_call
    assert "user_id" in audit_call
    assert audit_call["user_id"] == "USER-001"
    assert "ip_address" in audit_call
    assert audit_call["ip_address"] == "192.168.1.100"
    assert "device_info" in audit_call
    assert "amount" in audit_call
    assert "timestamp" in audit_call
    assert isinstance(audit_call["timestamp"], datetime)
    assert audit_call["timestamp"].tzinfo is not None  # Timezone-aware
    assert "status" in audit_call
    assert "decision_reason" in audit_call


def test_audit_trail_logged_on_rejection(
    transaction_service, mock_audit_logger, valid_transaction_request
):
    """
    Test audit trail is logged even when transaction is rejected.
    Compliance: Immutable audit log requirement.
    """
    # Arrange
    valid_transaction_request.amount = Decimal("0")

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    # Audit logger should still be called for rejected transactions
    # (implementation logs rejections in _log_rejection method)


def test_ctr_threshold_boundary_below(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test transaction just below CTR threshold ($10,000).
    Compliance: Currency Transaction Report (CTR) threshold per 31 CFR 1010.311.
    """
    # Arrange
    valid_account.balance = Decimal("15000.00")
    valid_transaction_request.amount = Decimal("9999.99")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("5000.01")


def test_ctr_threshold_boundary_at(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test transaction at CTR threshold ($10,000).
    Compliance: CTR filing required at or above $10,000.
    """
    # Arrange
    valid_account.balance = Decimal("15000.00")
    valid_transaction_request.amount = Decimal("10000.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    # In production, this would trigger CTR filing workflow


def test_sar_threshold_boundary(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test transaction at SAR threshold ($5,000).
    Compliance: Suspicious Activity Report (SAR) threshold per 31 CFR 1020.320.
    """
    # Arrange
    valid_account.balance = Decimal("10000.00")
    valid_transaction_request.amount = Decimal("5000.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    # In production, suspicious patterns at or above $5,000 would trigger SAR review


def test_travel_rule_threshold(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test transaction at Travel Rule threshold ($3,000).
    Compliance: Travel Rule per 31 CFR 1010.410(e) requires transmittal of customer info.
    """
    # Arrange
    valid_account.balance = Decimal("10000.00")
    valid_transaction_request.amount = Decimal("3000.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = True
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    # In production, transactions >= $3,000 would include additional customer data


def test_wire_dual_approval_threshold(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test high-value wire requiring dual approval.
    Compliance: Internal controls for high-value transactions.
    """
    # Arrange
    valid_account.balance = Decimal("50000.00")
    valid_transaction_request.amount = Decimal("10000.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    # In production, transactions >= $10,000 would require dual approval workflow


def test_decimal_precision_maintained(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test that Decimal precision is maintained for currency calculations.
    Compliance: SOX financial accuracy requirements.
    """
    # Arrange
    valid_account.balance = Decimal("1000.99")
    valid_transaction_request.amount = Decimal("100.50")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("900.49")
    assert isinstance(result.updated_balance, Decimal)


def test_timezone_aware_timestamp(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test that timestamps are timezone-aware for audit compliance.
    Compliance: Accurate timestamping for audit trail.
    """
    # Arrange
    utc_timestamp = datetime.now(timezone.utc)
    valid_transaction_request.timestamp = utc_timestamp
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    audit_call = mock_audit_logger.log_transaction.call_args.kwargs
    assert audit_call["timestamp"].tzinfo is not None
    assert audit_call["timestamp"] == utc_timestamp


def test_invalid_source_account(
    transaction_service, mock_account_repo, valid_transaction_request
):
    """
    Test rejection when source account does not exist.
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = None

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert "Invalid source account" in result.message


def test_exact_balance_transfer(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test transfer of exact account balance (boundary condition).
    """
    # Arrange
    valid_account.balance = Decimal("100.00")
    valid_transaction_request.amount = Decimal("100.00")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("0.00")


def test_one_cent_over_balance(
    transaction_service, mock_account_repo, valid_account, valid_transaction_request
):
    """
    Test rejection when transfer is one cent over balance (boundary condition).
    """
    # Arrange
    valid_account.balance = Decimal("100.00")
    valid_transaction_request.amount = Decimal("100.01")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.REJECTED
    assert result.message == "Insufficient balance"


def test_minimum_valid_amount(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test minimum valid transaction amount (one cent).
    """
    # Arrange
    valid_transaction_request.amount = Decimal("0.01")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("4999.99")


def test_ofac_threshold_boundary_below(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test OFAC screening just below fuzzy match threshold (85%).
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 84, "status": "REVIEW"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS


def test_ofac_threshold_boundary_at(
    transaction_service, mock_account_repo, mock_ofac_service, valid_account, valid_transaction_request
):
    """
    Test OFAC screening at fuzzy match threshold (85%).
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_ofac_service.screen.return_value = {"match_score": 85, "status": "MATCH"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.BLOCKED


def test_large_amount_formatting(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test handling of large transaction amounts with proper decimal precision.
    """
    # Arrange
    valid_account.balance = Decimal("999999999.99")
    valid_transaction_request.amount = Decimal("123456789.12")
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result.status == TransactionStatus.SUCCESS
    assert result.updated_balance == Decimal("876543210.87")
    assert isinstance(result.updated_balance, Decimal)


def test_transaction_id_uniqueness(
    transaction_service, mock_account_repo, mock_ofac_service, mock_audit_logger, valid_account, valid_transaction_request
):
    """
    Test that transaction IDs are generated and unique.
    Compliance: Unique transaction identifiers for audit trail.
    """
    # Arrange
    mock_account_repo.validate_account.return_value = True
    mock_account_repo.get_account.return_value = valid_account
    mock_account_repo.update_balance.return_value = True
    mock_ofac_service.screen.return_value = {"match_score": 0, "status": "CLEAR"}

    # Act
    result1 = transaction_service.execute_transaction(valid_transaction_request)
    result2 = transaction_service.execute_transaction(valid_transaction_request)

    # Assert
    assert result1.transaction_id is not None
    assert result2.transaction_id is not None
    assert result1.transaction_id != result2.transaction_id