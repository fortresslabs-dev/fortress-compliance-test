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


class OFACMatchType(Enum):
    NO_MATCH = "NO_MATCH"
    EXACT_MATCH = "EXACT_MATCH"
    FUZZY_MATCH = "FUZZY_MATCH"


@dataclass
class Account:
    account_number: str
    routing_number: str
    balance: Decimal
    user_id: str
    is_active: bool = True


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
    new_balance: Optional[Decimal]


@dataclass
class AuditRecord:
    audit_id: str
    transaction_id: Optional[str]
    user_id: str
    ip_address: str
    device_info: str
    timestamp: datetime
    action: str
    status: str
    amount: Optional[Decimal]
    details: Dict[str, Any]
    encrypted: bool = True


class OFACService:
    def screen_account(self, account_number: str, routing_number: str) -> Dict[str, Any]:
        raise NotImplementedError

    def screen_user(self, user_id: str) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(self, record: AuditRecord) -> str:
        raise NotImplementedError

    def retrieve_audit_trail(self, transaction_id: str) -> AuditRecord:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_number: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_number: str, new_balance: Decimal) -> bool:
        raise NotImplementedError

    def validate_beneficiary(self, account_number: str, routing_number: str) -> bool:
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
        audit_record = AuditRecord(
            audit_id=f"AUD-{datetime.now(timezone.utc).timestamp()}",
            transaction_id=None,
            user_id=request.user_id,
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=request.timestamp,
            action="TRANSFER",
            status="INITIATED",
            amount=request.amount,
            details={},
        )

        # Validation: Zero amount
        if request.amount == Decimal("0"):
            audit_record.status = "REJECTED"
            audit_record.details = {"reason": "Amount must be greater than 0"}
            self.audit_logger.log_transaction(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Amount must be greater than 0",
                audit_id=audit_record.audit_id,
                new_balance=None,
            )

        # Validation: Negative amount
        if request.amount < Decimal("0"):
            audit_record.status = "REJECTED"
            audit_record.details = {"reason": "Invalid amount"}
            self.audit_logger.log_transaction(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid amount",
                audit_id=audit_record.audit_id,
                new_balance=None,
            )

        # Validate beneficiary account
        if not self.account_repo.validate_beneficiary(
            request.to_account, request.to_routing
        ):
            audit_record.status = "REJECTED"
            audit_record.details = {"reason": "Invalid beneficiary account"}
            self.audit_logger.log_transaction(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid beneficiary account",
                audit_id=audit_record.audit_id,
                new_balance=None,
            )

        # Get source account
        from_account = self.account_repo.get_account(request.from_account)
        if not from_account or not from_account.is_active:
            audit_record.status = "REJECTED"
            audit_record.details = {"reason": "Invalid source account"}
            self.audit_logger.log_transaction(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid source account",
                audit_id=audit_record.audit_id,
                new_balance=None,
            )

        # Check sufficient balance
        if from_account.balance < request.amount:
            audit_record.status = "REJECTED"
            audit_record.details = {"reason": "Insufficient balance"}
            self.audit_logger.log_transaction(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Insufficient balance",
                audit_id=audit_record.audit_id,
                new_balance=None,
            )

        # OFAC screening
        ofac_result = self.ofac_service.screen_account(
            request.to_account, request.to_routing
        )
        if ofac_result["match_type"] == OFACMatchType.EXACT_MATCH:
            audit_record.status = "BLOCKED"
            audit_record.details = {"reason": "OFAC exact match", "ofac_data": ofac_result}
            self.audit_logger.log_transaction(audit_record)
            return TransactionResult(
                status=TransactionStatus.BLOCKED,
                transaction_id=None,
                message="Transaction blocked due to OFAC match",
                audit_id=audit_record.audit_id,
                new_balance=None,
            )

        if ofac_result["match_type"] == OFACMatchType.FUZZY_MATCH:
            if ofac_result["score"] >= OFAC_FUZZY_THRESHOLD:
                audit_record.status = "PENDING_REVIEW"
                audit_record.details = {
                    "reason": "OFAC fuzzy match requires review",
                    "ofac_data": ofac_result,
                }
                self.audit_logger.log_transaction(audit_record)
                return TransactionResult(
                    status=TransactionStatus.PENDING_REVIEW,
                    transaction_id=None,
                    message="Transaction pending compliance review",
                    audit_id=audit_record.audit_id,
                    new_balance=None,
                )

        # Check for SAR threshold
        if request.amount >= SAR_THRESHOLD:
            audit_record.details["sar_review_required"] = True

        # Check for CTR threshold
        if request.amount >= CTR_THRESHOLD:
            audit_record.details["ctr_filing_required"] = True

        # Check for Travel Rule
        if request.amount >= TRAVEL_RULE_THRESHOLD:
            audit_record.details["travel_rule_data_required"] = True

        # Check for dual approval
        if request.amount >= WIRE_DUAL_APPROVAL_THRESHOLD:
            audit_record.details["dual_approval_required"] = True

        # Execute transaction
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account, new_balance)

        transaction_id = f"TXN-{datetime.now(timezone.utc).timestamp()}"
        audit_record.transaction_id = transaction_id
        audit_record.status = "SUCCESS"
        audit_record.details["new_balance"] = str(new_balance)
        audit_id = self.audit_logger.log_transaction(audit_record)

        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction completed successfully",
            audit_id=audit_id,
            new_balance=new_balance,
        )


# Fixtures


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
    logger.log_transaction.return_value = "AUD-12345"
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
        balance=Decimal("10000.00"),
        user_id="USER-001",
        is_active=True,
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
        timestamp=datetime.now(timezone.utc),
    )


# Test Cases


class TestSuccessfulTransaction:
    """Test successful transaction scenario from MDP-77"""

    def test_successful_transaction(
        self,
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
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None
        assert result.audit_id is not None
        assert result.new_balance == Decimal("9900.00")
        assert result.message == "Transaction completed successfully"

        # Verify balance was updated
        mock_account_repo.update_balance.assert_called_once_with(
            "1234567890", Decimal("9900.00")
        )

        # Verify audit trail was recorded
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.user_id == "USER-001"
        assert audit_call.ip_address == "192.168.1.100"
        assert audit_call.device_info == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        assert audit_call.amount == Decimal("100.00")
        assert audit_call.status == "SUCCESS"
        assert audit_call.encrypted is True


class TestZeroAmountTransfer:
    """Test zero amount transfer scenario from MDP-77"""

    def test_zero_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
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
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Amount must be greater than 0"
        assert result.audit_id is not None
        assert result.new_balance is None

        # Verify audit trail was recorded
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Amount must be greater than 0"


class TestNegativeAmountTransfer:
    """Test negative amount transfer scenario from MDP-77"""

    def test_negative_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
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
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Invalid amount"
        assert result.audit_id is not None
        assert result.new_balance is None

        # Verify audit trail was recorded
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Invalid amount"


class TestInsufficientBalance:
    """Test insufficient balance scenario from MDP-77"""

    def test_insufficient_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
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
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Insufficient balance"
        assert result.audit_id is not None
        assert result.new_balance is None

        # Verify balance was not updated
        mock_account_repo.update_balance.assert_not_called()

        # Verify audit trail was recorded
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test invalid beneficiary scenario from MDP-77"""

    def test_invalid_beneficiary(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = False

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Invalid beneficiary account"
        assert result.audit_id is not None
        assert result.new_balance is None

        # Verify validation was attempted
        mock_account_repo.validate_beneficiary.assert_called_once_with(
            "9876543210", "021000021"
        )

        # Verify audit trail was recorded
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Invalid beneficiary account"


class TestOFACScreening:
    """Test OFAC screening compliance requirements"""

    def test_ofac_exact_match_blocks_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that exact OFAC match blocks transaction
        Compliance: OFAC/SDN screening requirement
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.EXACT_MATCH,
            "score": 100,
            "matched_entity": "SDN Entity",
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert result.transaction_id is None
        assert "OFAC" in result.message

        # Verify balance was not updated
        mock_account_repo.update_balance.assert_not_called()

        # Verify audit trail includes OFAC data
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.status == "BLOCKED"
        assert "ofac_data" in audit_call.details

    def test_ofac_fuzzy_match_above_threshold_requires_review(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that fuzzy OFAC match above threshold requires manual review
        Compliance: OFAC screening with fuzzy matching
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.FUZZY_MATCH,
            "score": 90,
            "matched_entity": "Similar Name",
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.PENDING_REVIEW
        assert result.transaction_id is None
        assert "review" in result.message.lower()

        # Verify audit trail includes OFAC data
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.status == "PENDING_REVIEW"
        assert "ofac_data" in audit_call.details

    def test_ofac_fuzzy_match_below_threshold_allows_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that fuzzy OFAC match below threshold allows transaction
        Compliance: OFAC screening with acceptable false positive rate
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.FUZZY_MATCH,
            "score": 50,
            "matched_entity": "Vaguely Similar",
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None


class TestCTRAndSARThresholds:
    """Test CTR and SAR threshold compliance requirements"""

    def test_transaction_above_ctr_threshold_flags_for_filing(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that transactions >= $10,000 are flagged for CTR filing
        Compliance: 31 CFR 1010.311 - Currency Transaction Reports
        """
        # Arrange
        valid_account.balance = Decimal("50000.00")
        valid_transaction_request.amount = Decimal("10000.00")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("ctr_filing_required") is True

    def test_transaction_above_sar_threshold_flags_for_review(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that transactions >= $5,000 are flagged for SAR review
        Compliance: 31 CFR 1020.320 - Suspicious Activity Reports
        """
        # Arrange
        valid_account.balance = Decimal("20000.00")
        valid_transaction_request.amount = Decimal("5000.00")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("sar_review_required") is True

    def test_transaction_below_thresholds_no_special_flags(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that transactions below thresholds don't trigger CTR/SAR flags
        """
        # Arrange
        valid_transaction_request.amount = Decimal("100.00")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("ctr_filing_required") is not True
        assert audit_call.details.get("sar_review_required") is not True


class TestTravelRuleCompliance:
    """Test Travel Rule compliance requirements"""

    def test_transaction_above_travel_rule_threshold_requires_data(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that transactions >= $3,000 require Travel Rule data
        Compliance: 31 CFR 1010.410(e) - Recordkeeping for funds transfers
        """
        # Arrange
        valid_account.balance = Decimal("10000.00")
        valid_transaction_request.amount = Decimal("3000.00")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("travel_rule_data_required") is True


class TestDualApprovalRequirements:
    """Test dual approval requirements for high-value wires"""

    def test_high_value_wire_requires_dual_approval(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that wires >= $10,000 require dual approval
        Compliance: Internal control requirement for high-value transactions
        """
        # Arrange
        valid_account.balance = Decimal("50000.00")
        valid_transaction_request.amount = Decimal("10000.00")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("dual_approval_required") is True


class TestAuditTrailCompliance:
    """Test audit trail and record retention compliance"""

    def test_audit_record_contains_required_fields(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that audit records contain all required fields
        Compliance: 31 CFR 1010.430 - BSA record retention (5 years)
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]

        # Verify all required audit fields
        assert audit_call.user_id == "USER-001"
        assert audit_call.ip_address == "192.168.1.100"
        assert audit_call.device_info is not None
        assert audit_call.timestamp is not None
        assert audit_call.timestamp.tzinfo is not None  # Timezone-aware
        assert audit_call.action == "TRANSFER"
        assert audit_call.status == "SUCCESS"
        assert audit_call.amount == Decimal("100.00")
        assert audit_call.encrypted is True

    def test_rejected_transaction_creates_audit_record(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that rejected transactions also create audit records
        Compliance: Immutable audit log requirement
        """
        # Arrange
        valid_transaction_request.amount = Decimal("0")

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.transaction_id is None


class TestBoundaryConditions:
    """Test boundary conditions for regulatory thresholds"""

    def test_transaction_exactly_at_ctr_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction exactly at CTR threshold ($10,000)"""
        # Arrange
        valid_account.balance = Decimal("50000.00")
        valid_transaction_request.amount = CTR_THRESHOLD
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("ctr_filing_required") is True

    def test_transaction_one_cent_below_ctr_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction one cent below CTR threshold ($9,999.99)"""
        # Arrange
        valid_account.balance = Decimal("50000.00")
        valid_transaction_request.amount = CTR_THRESHOLD - Decimal("0.01")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("ctr_filing_required") is not True

    def test_transaction_exactly_at_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction exactly equal to account balance"""
        # Arrange
        valid_account.balance = Decimal("1000.00")
        valid_transaction_request.amount = Decimal("1000.00")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.new_balance == Decimal("0.00")

    def test_transaction_one_cent_above_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction one cent above account balance"""
        # Arrange
        valid_account.balance = Decimal("1000.00")
        valid_transaction_request.amount = Decimal("1000.01")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"


class TestDataHandlingCompliance:
    """Test data handling and encryption compliance"""

    def test_audit_records_marked_as_encrypted(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that audit records are marked for encryption
        Compliance: GLBA Safeguards Rule, AES-256 encryption at rest
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.encrypted is True

    def test_timestamp_is_timezone_aware(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """
        Test that timestamps are timezone-aware (UTC)
        Compliance: Accurate record keeping requirement
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.timestamp.tzinfo is not None
        assert audit_call.timestamp.tzinfo == timezone.utc


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_inactive_account_rejected(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test that transactions from inactive accounts are rejected"""
        # Arrange
        valid_account.is_active = False
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert "Invalid source account" in result.message

    def test_nonexistent_account_rejected(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test that transactions from non-existent accounts are rejected"""
        # Arrange
        mock_account_repo.get_account.return_value = None
        mock_account_repo.validate_beneficiary.return_value = True

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert "Invalid source account" in result.message

    def test_very_small_amount_above_zero(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction with very small amount (1 cent)"""
        # Arrange
        valid_transaction_request.amount = Decimal("0.01")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.new_balance == Decimal("9999.99")

    def test_very_large_amount_within_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest,
    ) -> None:
        """Test transaction with very large amount"""
        # Arrange
        valid_account.balance = Decimal("1000000.00")
        valid_transaction_request.amount = Decimal("999999.99")
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_account.return_value = {
            "match_type": OFACMatchType.NO_MATCH,
            "score": 0,
        }

        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.new_balance == Decimal("0.01")
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.details.get("ctr_filing_required") is True
        assert audit_call.details.get("dual_approval_required") is True