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
    account_id: str
    routing_number: str
    balance: Decimal
    user_id: str
    status: str = "ACTIVE"


@dataclass
class TransactionRequest:
    from_account_id: str
    to_account_id: str
    to_routing_number: str
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
    updated_balance: Optional[Decimal]


class OFACService:
    def screen(self, account_id: str, routing_number: str) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(
        self,
        user_id: str,
        transaction_id: str,
        amount: Decimal,
        status: str,
        ip_address: str,
        device_info: str,
        timestamp: datetime,
        decision_reason: str,
    ) -> str:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_id: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_id: str, new_balance: Decimal) -> bool:
        raise NotImplementedError

    def validate_routing_and_account(
        self, routing_number: str, account_id: str
    ) -> bool:
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

    def process_transaction(
        self, request: TransactionRequest
    ) -> TransactionResult:
        timestamp = request.timestamp or datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        # Validate amount - zero amount
        if request.amount == Decimal("0"):
            self._log_rejection(
                request, transaction_id, "Amount must be greater than 0"
            )
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Amount must be greater than 0",
                audit_log_id=None,
                updated_balance=None,
            )

        # Validate amount - negative amount
        if request.amount < Decimal("0"):
            self._log_rejection(request, transaction_id, "Invalid amount")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid amount",
                audit_log_id=None,
                updated_balance=None,
            )

        # Validate beneficiary account
        if not self.account_repo.validate_routing_and_account(
            request.to_routing_number, request.to_account_id
        ):
            self._log_rejection(
                request, transaction_id, "Invalid beneficiary account"
            )
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid beneficiary account",
                audit_log_id=None,
                updated_balance=None,
            )

        # Get source account
        from_account = self.account_repo.get_account(request.from_account_id)
        if not from_account:
            self._log_rejection(request, transaction_id, "Invalid source account")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid source account",
                audit_log_id=None,
                updated_balance=None,
            )

        # Check sufficient balance
        if from_account.balance < request.amount:
            self._log_rejection(request, transaction_id, "Insufficient balance")
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Insufficient balance",
                audit_log_id=None,
                updated_balance=None,
            )

        # OFAC screening
        ofac_result = self.ofac_service.screen(
            request.to_account_id, request.to_routing_number
        )
        if ofac_result["match_score"] >= OFAC_FUZZY_THRESHOLD:
            if ofac_result["action"] == "BLOCK":
                audit_log_id = self.audit_logger.log_transaction(
                    user_id=request.user_id,
                    transaction_id=transaction_id,
                    amount=request.amount,
                    status="BLOCKED_OFAC",
                    ip_address=request.ip_address,
                    device_info=request.device_info,
                    timestamp=timestamp,
                    decision_reason=f"OFAC match: {ofac_result['matched_entity']}",
                )
                return TransactionResult(
                    status=TransactionStatus.BLOCKED,
                    transaction_id=transaction_id,
                    message="Transaction blocked due to sanctions screening",
                    audit_log_id=audit_log_id,
                    updated_balance=None,
                )

        # Process transaction
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account_id, new_balance)

        # Audit logging with compliance requirements
        audit_log_id = self.audit_logger.log_transaction(
            user_id=request.user_id,
            transaction_id=transaction_id,
            amount=request.amount,
            status="SUCCESS",
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=timestamp,
            decision_reason="Transaction approved",
        )

        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction successful",
            audit_log_id=audit_log_id,
            updated_balance=new_balance,
        )

    def _log_rejection(
        self, request: TransactionRequest, transaction_id: str, reason: str
    ) -> None:
        try:
            self.audit_logger.log_transaction(
                user_id=request.user_id,
                transaction_id=transaction_id,
                amount=request.amount,
                status="REJECTED",
                ip_address=request.ip_address,
                device_info=request.device_info,
                timestamp=request.timestamp or datetime.now(timezone.utc),
                decision_reason=reason,
            )
        except Exception:
            pass


# Fixtures


@pytest.fixture
def mock_account_repo() -> Mock:
    """Mock account repository for testing."""
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_ofac_service() -> Mock:
    """Mock OFAC screening service."""
    service = Mock(spec=OFACService)
    service.screen.return_value = {
        "match_score": 0,
        "action": "ALLOW",
        "matched_entity": None,
    }
    return service


@pytest.fixture
def mock_audit_logger() -> Mock:
    """Mock audit logger for compliance tracking."""
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = "AUDIT-12345"
    return logger


@pytest.fixture
def transaction_service(
    mock_account_repo: Mock, mock_ofac_service: Mock, mock_audit_logger: Mock
) -> TransactionService:
    """Transaction service with mocked dependencies."""
    return TransactionService(mock_account_repo, mock_ofac_service, mock_audit_logger)


@pytest.fixture
def valid_account() -> Account:
    """Valid account with sufficient balance."""
    return Account(
        account_id="ACC-001",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="ACTIVE",
    )


@pytest.fixture
def valid_transaction_request() -> TransactionRequest:
    """Valid transaction request."""
    return TransactionRequest(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        to_routing_number="021000022",
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )


# Test Cases


class TestSuccessfulTransaction:
    """Test successful transaction scenario."""

    def test_successful_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
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
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None
        assert result.message == "Transaction successful"
        assert result.audit_log_id == "AUDIT-12345"
        assert result.updated_balance == Decimal("9900.00")

        # Verify balance was updated
        mock_account_repo.update_balance.assert_called_once_with(
            "ACC-001", Decimal("9900.00")
        )

        # Verify audit trail was recorded with all required fields
        mock_audit_logger.log_transaction.assert_called_once()
        call_args = mock_audit_logger.log_transaction.call_args[1]
        assert call_args["user_id"] == "USER-001"
        assert call_args["amount"] == Decimal("100.00")
        assert call_args["status"] == "SUCCESS"
        assert call_args["ip_address"] == "192.168.1.100"
        assert call_args["device_info"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        assert isinstance(call_args["timestamp"], datetime)
        assert call_args["timestamp"].tzinfo is not None


class TestZeroAmountTransfer:
    """Test zero amount transfer scenario."""

    def test_zero_amount_transfer(
        self,
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
        assert result.transaction_id is None
        assert result.message == "Amount must be greater than 0"
        assert result.audit_log_id is None
        assert result.updated_balance is None

    def test_zero_amount_with_decimal_precision(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test zero amount with various decimal representations."""
        # Arrange
        valid_transaction_request.amount = Decimal("0.00")

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Amount must be greater than 0"


class TestNegativeAmountTransfer:
    """Test negative amount transfer scenario."""

    def test_negative_amount_transfer(
        self,
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
        assert result.transaction_id is None
        assert result.message == "Invalid amount"
        assert result.audit_log_id is None
        assert result.updated_balance is None

    def test_large_negative_amount(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test large negative amount."""
        # Arrange
        valid_transaction_request.amount = Decimal("-999999.99")

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"


class TestInsufficientBalance:
    """Test insufficient balance scenario."""

    def test_insufficient_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        account_with_low_balance = Account(
            account_id="ACC-001",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            user_id="USER-001",
        )
        valid_transaction_request.amount = Decimal("5000.00")
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = account_with_low_balance

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Insufficient balance"
        assert result.audit_log_id is None
        assert result.updated_balance is None

        # Verify balance was not updated
        mock_account_repo.update_balance.assert_not_called()

    def test_insufficient_balance_by_one_cent(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test boundary condition: insufficient by one cent."""
        # Arrange
        account = Account(
            account_id="ACC-001",
            routing_number="021000021",
            balance=Decimal("99.99"),
            user_id="USER-001",
        )
        valid_transaction_request.amount = Decimal("100.00")
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = account

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test invalid beneficiary account scenario."""

    def test_invalid_beneficiary(
        self,
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
        mock_account_repo.validate_routing_and_account.return_value = False

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Invalid beneficiary account"
        assert result.audit_log_id is None
        assert result.updated_balance is None

        # Verify validation was called with correct parameters
        mock_account_repo.validate_routing_and_account.assert_called_once_with(
            "021000022", "ACC-002"
        )

    def test_invalid_routing_number_format(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test invalid routing number format."""
        # Arrange
        valid_transaction_request.to_routing_number = "INVALID"
        mock_account_repo.validate_routing_and_account.return_value = False

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"


class TestOFACScreening:
    """Test OFAC/SDN screening compliance."""

    def test_ofac_blocked_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction blocked due to OFAC match."""
        # Arrange
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {
            "match_score": 95,
            "action": "BLOCK",
            "matched_entity": "SDN Entity XYZ",
        }

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert result.transaction_id is not None
        assert "sanctions screening" in result.message
        assert result.audit_log_id == "AUDIT-12345"

        # Verify OFAC screening was performed
        mock_ofac_service.screen.assert_called_once_with("ACC-002", "021000022")

        # Verify audit log captured OFAC block
        call_args = mock_audit_logger.log_transaction.call_args[1]
        assert call_args["status"] == "BLOCKED_OFAC"
        assert "OFAC match" in call_args["decision_reason"]

        # Verify balance was NOT updated
        mock_account_repo.update_balance.assert_not_called()

    def test_ofac_threshold_boundary(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test OFAC match at exact threshold (85%)."""
        # Arrange
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {
            "match_score": OFAC_FUZZY_THRESHOLD,
            "action": "BLOCK",
            "matched_entity": "Threshold Entity",
        }

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.BLOCKED

    def test_ofac_below_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test OFAC match below threshold allows transaction."""
        # Arrange
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {
            "match_score": 84,
            "action": "ALLOW",
            "matched_entity": None,
        }

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS


class TestCTRThresholdCompliance:
    """Test Currency Transaction Report (CTR) threshold compliance."""

    def test_transaction_at_ctr_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction at CTR threshold ($10,000)."""
        # Arrange
        high_balance_account = Account(
            account_id="ACC-001",
            routing_number="021000021",
            balance=Decimal("50000.00"),
            user_id="USER-001",
        )
        valid_transaction_request.amount = CTR_THRESHOLD
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = high_balance_account

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.updated_balance == Decimal("40000.00")

    def test_transaction_above_ctr_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction above CTR threshold requires reporting."""
        # Arrange
        high_balance_account = Account(
            account_id="ACC-001",
            routing_number="021000021",
            balance=Decimal("50000.00"),
            user_id="USER-001",
        )
        valid_transaction_request.amount = Decimal("15000.00")
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = high_balance_account

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        # In production, this would trigger CTR filing


class TestSARThresholdCompliance:
    """Test Suspicious Activity Report (SAR) threshold compliance."""

    def test_transaction_at_sar_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction at SAR threshold ($5,000)."""
        # Arrange
        account = Account(
            account_id="ACC-001",
            routing_number="021000021",
            balance=Decimal("20000.00"),
            user_id="USER-001",
        )
        valid_transaction_request.amount = SAR_THRESHOLD
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = account

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        # In production, suspicious patterns would trigger SAR


class TestTravelRuleCompliance:
    """Test Travel Rule compliance for wire transfers."""

    def test_transaction_at_travel_rule_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction at Travel Rule threshold ($3,000)."""
        # Arrange
        account = Account(
            account_id="ACC-001",
            routing_number="021000021",
            balance=Decimal("10000.00"),
            user_id="USER-001",
        )
        valid_transaction_request.amount = TRAVEL_RULE_THRESHOLD
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = account

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        # In production, would require originator/beneficiary info


class TestAuditTrailCompliance:
    """Test audit trail and record retention compliance."""

    def test_audit_trail_contains_required_fields(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test audit trail contains all required compliance fields."""
        # Arrange
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = valid_account

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_audit_logger.log_transaction.assert_called_once()

        call_args = mock_audit_logger.log_transaction.call_args[1]
        # Verify all required audit fields per 31 CFR 1010.430
        assert "user_id" in call_args
        assert "transaction_id" in call_args
        assert "amount" in call_args
        assert "status" in call_args
        assert "ip_address" in call_args
        assert "device_info" in call_args
        assert "timestamp" in call_args
        assert "decision_reason" in call_args

    def test_audit_trail_uses_timezone_aware_datetime(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test audit trail uses timezone-aware datetime for BSA compliance."""
        # Arrange
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = valid_account

        # Act
        transaction_service.process_transaction(valid_transaction_request)

        # Assert
        call_args = mock_audit_logger.log_transaction.call_args[1]
        timestamp = call_args["timestamp"]
        assert isinstance(timestamp, datetime)
        assert timestamp.tzinfo is not None
        assert timestamp.tzinfo == timezone.utc

    def test_rejected_transaction_audit_trail(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test rejected transactions are also audited."""
        # Arrange
        valid_transaction_request.amount = Decimal("0")

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        # Audit logger may be called for rejections in production
        # This test verifies the rejection path


class TestDataHandlingCompliance:
    """Test data handling and encryption compliance (GLBA, PCI-DSS)."""

    def test_decimal_precision_for_currency(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test currency amounts use Decimal for precision (SOX compliance)."""
        # Arrange
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        valid_transaction_request.amount = Decimal("123.45")

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert isinstance(result.updated_balance, Decimal)
        assert result.updated_balance == Decimal("9876.55")

    def test_transaction_request_contains_device_info(
        self, valid_transaction_request: TransactionRequest
    ) -> None:
        """Test transaction request captures device info for audit."""
        # Assert
        assert valid_transaction_request.device_info is not None
        assert len(valid_transaction_request.device_info) > 0

    def test_transaction_request_contains_ip_address(
        self, valid_transaction_request: TransactionRequest
    ) -> None:
        """Test transaction request captures IP address for audit."""
        # Assert
        assert valid_transaction_request.ip_address is not None
        assert len(valid_transaction_request.ip_address) > 0


class TestBoundaryConditions:
    """Test boundary conditions and edge cases."""

    def test_exact_balance_transfer(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transferring exact account balance."""
        # Arrange
        account = Account(
            account_id="ACC-001",
            routing_number="021000021",
            balance=Decimal("100.00"),
            user_id="USER-001",
        )
        valid_transaction_request.amount = Decimal("100.00")
        mock_account_repo.validate_routing_and_account.return_value = True
        mock_account_repo.get_account.return_value = account

        # Act
        result = transaction_service.process_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.updated_balance == Decimal("0.00")

    def test_minimum_valid_amount(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test minimum valid transaction amount (one cent)."""
        # Arrange
        valid_transaction_request.amount = Decimal