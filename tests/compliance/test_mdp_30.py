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
    ofac_check_passed: bool
    ctr_filed: bool
    sar_filed: bool
    dual_approval_required: bool


@dataclass
class AuditLogEntry:
    audit_id: str
    transaction_id: Optional[str]
    user_id: str
    ip_address: str
    device_info: str
    timestamp: datetime
    action: str
    result: str
    amount: Optional[Decimal]
    encrypted: bool
    retention_years: int = 5


class OFACService:
    def screen_account(self, account_number: str, routing_number: str, name: str) -> Dict[str, Any]:
        raise NotImplementedError

    def screen_user(self, user_id: str, name: str) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(self, entry: AuditLogEntry) -> str:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_number: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_number: str, new_balance: Decimal) -> bool:
        raise NotImplementedError

    def validate_beneficiary(self, account_number: str, routing_number: str) -> bool:
        raise NotImplementedError


class ComplianceEngine:
    def requires_ctr(self, amount: Decimal) -> bool:
        return amount >= CTR_THRESHOLD

    def requires_sar(self, amount: Decimal, suspicious: bool = False) -> bool:
        return amount >= SAR_THRESHOLD and suspicious

    def requires_dual_approval(self, amount: Decimal) -> bool:
        return amount >= WIRE_DUAL_APPROVAL_THRESHOLD

    def requires_travel_rule(self, amount: Decimal) -> bool:
        return amount >= TRAVEL_RULE_THRESHOLD


class TransactionService:
    def __init__(
        self,
        account_repo: AccountRepository,
        ofac_service: OFACService,
        audit_logger: AuditLogger,
        compliance_engine: ComplianceEngine,
    ):
        self.account_repo = account_repo
        self.ofac_service = ofac_service
        self.audit_logger = audit_logger
        self.compliance_engine = compliance_engine

    def process_transaction(self, request: TransactionRequest) -> TransactionResult:
        # Validate amount
        if request.amount == Decimal("0"):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Amount must be greater than 0",
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False,
            )
            self._log_transaction(request, result)
            return result

        if request.amount < Decimal("0"):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid amount",
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False,
            )
            self._log_transaction(request, result)
            return result

        # Validate beneficiary
        if not self.account_repo.validate_beneficiary(request.to_account, request.to_routing):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid beneficiary account",
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False,
            )
            self._log_transaction(request, result)
            return result

        # Get source account
        from_account = self.account_repo.get_account(request.from_account)
        if not from_account:
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid source account",
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False,
            )
            self._log_transaction(request, result)
            return result

        # Check balance
        if from_account.balance < request.amount:
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Insufficient balance",
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False,
            )
            self._log_transaction(request, result)
            return result

        # OFAC screening
        ofac_result = self.ofac_service.screen_user(request.user_id, "User Name")
        if ofac_result["match_type"] == OFACMatchType.EXACT_MATCH.value:
            result = TransactionResult(
                status=TransactionStatus.BLOCKED,
                transaction_id=None,
                message="Transaction blocked due to OFAC match",
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False,
            )
            self._log_transaction(request, result)
            return result

        # Check compliance requirements
        ctr_required = self.compliance_engine.requires_ctr(request.amount)
        dual_approval_required = self.compliance_engine.requires_dual_approval(request.amount)

        # Update balance
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account, new_balance)

        # Create successful result
        transaction_id = f"TXN-{request.timestamp.timestamp()}"
        result = TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction successful",
            audit_log_id=None,
            ofac_check_passed=True,
            ctr_filed=ctr_required,
            sar_filed=False,
            dual_approval_required=dual_approval_required,
        )

        # Log transaction
        audit_log_id = self._log_transaction(request, result)
        result.audit_log_id = audit_log_id

        return result

    def _log_transaction(self, request: TransactionRequest, result: TransactionResult) -> str:
        entry = AuditLogEntry(
            audit_id=f"AUDIT-{datetime.now(timezone.utc).timestamp()}",
            transaction_id=result.transaction_id,
            user_id=self._mask_pii(request.user_id),
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=request.timestamp,
            action="TRANSFER",
            result=result.status.value,
            amount=request.amount,
            encrypted=True,
            retention_years=5,
        )
        return self.audit_logger.log_transaction(entry)

    def _mask_pii(self, value: str) -> str:
        if len(value) > 4:
            return "*" * (len(value) - 4) + value[-4:]
        return value


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
    logger.log_transaction.return_value = "AUDIT-12345"
    return logger


@pytest.fixture
def mock_compliance_engine() -> ComplianceEngine:
    return ComplianceEngine()


@pytest.fixture
def transaction_service(
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock,
    mock_compliance_engine: ComplianceEngine,
) -> TransactionService:
    return TransactionService(
        mock_account_repo,
        mock_ofac_service,
        mock_audit_logger,
        mock_compliance_engine,
    )


@pytest.fixture
def valid_account() -> Account:
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="ACTIVE",
    )


@pytest.fixture
def transaction_timestamp() -> datetime:
    return datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)


# Test Cases


class TestSuccessfulTransaction:
    """Test successful transaction scenario with sufficient balance and valid account."""

    def test_successful_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        transaction_timestamp: datetime,
    ) -> None:
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_user.return_value = {
            "match_type": OFACMatchType.NO_MATCH.value,
            "score": 0,
        }

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None
        assert result.message == "Transaction successful"
        assert result.audit_log_id == "AUDIT-12345"
        assert result.ofac_check_passed is True

        # Verify balance updated
        mock_account_repo.update_balance.assert_called_once_with(
            "1234567890", Decimal("9500.00")
        )

        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call.user_id == "***R-001"  # Masked
        assert audit_call.ip_address == "192.168.1.100"
        assert audit_call.device_info == "Mozilla/5.0"
        assert audit_call.timestamp == transaction_timestamp
        assert audit_call.amount == Decimal("500.00")
        assert audit_call.encrypted is True
        assert audit_call.retention_years == 5

    def test_successful_transaction_with_ctr_filing(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        valid_account: Account,
        transaction_timestamp: datetime,
    ) -> None:
        """
        Test transaction at CTR threshold triggers CTR filing requirement.
        Validates 31 CFR 1010.430 compliance for transactions >= $10,000.
        """
        # Arrange
        valid_account.balance = Decimal("15000.00")
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("10000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_user.return_value = {
            "match_type": OFACMatchType.NO_MATCH.value,
            "score": 0,
        }

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.ctr_filed is True
        assert result.dual_approval_required is True

    def test_successful_transaction_below_ctr_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        valid_account: Account,
        transaction_timestamp: datetime,
    ) -> None:
        """
        Test transaction below CTR threshold does not trigger CTR filing.
        """
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("9999.99"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_user.return_value = {
            "match_type": OFACMatchType.NO_MATCH.value,
            "score": 0,
        }

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.ctr_filed is False
        assert result.dual_approval_required is False


class TestZeroAmountTransfer:
    """Test zero amount transfer rejection."""

    def test_zero_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
        transaction_timestamp: datetime,
    ) -> None:
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
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Amount must be greater than 0"
        assert result.ofac_check_passed is False

        # Verify audit log still recorded
        mock_audit_logger.log_transaction.assert_called_once()


class TestNegativeAmountTransfer:
    """Test negative amount transfer rejection."""

    def test_negative_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
        transaction_timestamp: datetime,
    ) -> None:
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
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Invalid amount"
        assert result.ofac_check_passed is False

        # Verify audit log recorded
        mock_audit_logger.log_transaction.assert_called_once()

    def test_negative_amount_boundary(
        self,
        transaction_service: TransactionService,
        transaction_timestamp: datetime,
    ) -> None:
        """Test negative amount at boundary (-0.01)."""
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("-0.01"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"


class TestInsufficientBalance:
    """Test insufficient balance rejection."""

    def test_insufficient_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        transaction_timestamp: datetime,
    ) -> None:
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
            user_id="USER-001",
        )

        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("5000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Insufficient balance"
        assert result.ofac_check_passed is False

        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()

        # Verify audit log recorded
        mock_audit_logger.log_transaction.assert_called_once()

    def test_insufficient_balance_by_one_cent(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        transaction_timestamp: datetime,
    ) -> None:
        """Test insufficient balance boundary case (off by $0.01)."""
        # Arrange
        account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            user_id="USER-001",
        )

        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("1000.01"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"

    def test_exact_balance_transfer_succeeds(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        transaction_timestamp: datetime,
    ) -> None:
        """Test transfer of exact account balance succeeds."""
        # Arrange
        account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            user_id="USER-001",
        )

        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_user.return_value = {
            "match_type": OFACMatchType.NO_MATCH.value,
            "score": 0,
        }

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_account_repo.update_balance.assert_called_once_with(
            "1234567890", Decimal("0.00")
        )


class TestInvalidBeneficiary:
    """Test invalid beneficiary account rejection."""

    def test_invalid_beneficiary(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        transaction_timestamp: datetime,
    ) -> None:
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="INVALID",
            to_routing="999999999",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = False

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Invalid beneficiary account"
        assert result.ofac_check_passed is False

        # Verify audit log recorded
        mock_audit_logger.log_transaction.assert_called_once()

    def test_invalid_routing_number(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        transaction_timestamp: datetime,
    ) -> None:
        """Test invalid routing number format."""
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="00000000",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = False

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"


class TestOFACScreening:
    """Test OFAC/SDN screening compliance."""

    def test_ofac_exact_match_blocks_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        valid_account: Account,
        transaction_timestamp: datetime,
    ) -> None:
        """
        Test OFAC exact match blocks transaction.
        Validates compliance with OFAC sanctions screening requirements.
        """
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("500.00"),
            user_id="USER-SDN",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen_user.return_value = {
            "match_type": OFACMatchType.EXACT_MATCH.value,
            "score": 100,
            "sdn_name": "Blocked Entity",
        }

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert result.transaction_id is None
        assert result.message == "Transaction blocked due to OFAC match"
        assert result.ofac_check_passed is False

        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()

    def test_ofac_fuzzy_match_allows_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        valid_account: Account,
        transaction_timestamp: datetime,
    ) -> None:
        """
        Test OFAC fuzzy match below threshold allows transaction.
        Fuzzy matches require manual review but don't auto-block.
        """
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_user.return_value = {
            "match_type": OFACMatchType.FUZZY_MATCH.value,
            "score": 75,
        }

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.ofac_check_passed is True

    def test_ofac_no_match_allows_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        valid_account: Account,
        transaction_timestamp: datetime,
    ) -> None:
        """Test OFAC no match allows transaction to proceed."""
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            to_routing="021000021",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp,
        )

        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen_user.return_value = {
            "match_type": OFACMatchType.NO_MATCH.value,
            "score": 0,
        }

        # Act
        result = transaction_service.process_transaction(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.ofac_check_passed is True


class TestComplianceThresholds:
    """Test U.S. regulatory threshold compliance."""

    def test_travel_rule_threshold(
        self,
        mock_compliance_engine: ComplianceEngine,
    ) -> None:
        """
        Test Travel Rule threshold ($3,000).
        Validates 31 CFR 1010.410(e) compliance.
        """
        # Arrange & Act & Assert
        assert mock_compliance_engine.requires_travel_rule(Decimal("2999.99")) is False
        assert mock_compliance_engine.requires_travel_rule(Decimal("3000.00")) is True
        assert mock_compliance_engine.requires_travel_rule(Decimal("3000.01")) is True

    def test_ctr_threshold(
        self,
        mock_compliance_engine: ComplianceEngine,
    ) -> None:
        """
        Test CTR threshold ($10,000).
        Validates 31 CFR 1010.430 compliance.
        """
        # Arrange & Act & Assert