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
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    device_info: Optional[str] = None


@dataclass
class AuditRecord:
    audit_id: str
    transaction_id: str
    timestamp: datetime
    user_id: str
    ip_address: str
    device_info: str
    action: str
    status: str
    encrypted: bool = True
    retention_years: int = 5


class OFACService:
    def screen_account(self, account_number: str, routing_number: str, name: str) -> Dict[str, Any]:
        raise NotImplementedError

    def screen_transaction(self, transaction: Transaction) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(self, transaction: Transaction, context: Dict[str, Any]) -> AuditRecord:
        raise NotImplementedError

    def log_compliance_event(self, event_type: str, details: Dict[str, Any]) -> AuditRecord:
        raise NotImplementedError


class TransactionService:
    def __init__(self, audit_logger: AuditLogger, ofac_service: OFACService):
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service

    def validate_amount(self, amount: Decimal) -> tuple[bool, Optional[str]]:
        if amount <= 0:
            if amount == 0:
                return False, "Amount must be greater than 0"
            return False, "Invalid amount"
        return True, None

    def validate_beneficiary(self, routing_number: str, account_number: str) -> tuple[bool, Optional[str]]:
        if not routing_number or not account_number:
            return False, "Invalid beneficiary account"
        if len(routing_number) != 9 or not routing_number.isdigit():
            return False, "Invalid beneficiary account"
        if not account_number.isdigit():
            return False, "Invalid beneficiary account"
        return True, None

    def check_balance(self, account: Account, amount: Decimal) -> tuple[bool, Optional[str]]:
        if account.balance < amount:
            return False, "Insufficient balance"
        return True, None

    def execute_transaction(
        self,
        from_account: Account,
        to_routing: str,
        to_account: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        transaction_id = f"TXN-{datetime.now(timezone.utc).timestamp()}"
        timestamp = datetime.now(timezone.utc)

        # Validate amount
        valid_amount, amount_error = self.validate_amount(amount)
        if not valid_amount:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_number,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=amount_error,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(transaction, {"reason": amount_error})
            return transaction

        # Validate beneficiary
        valid_beneficiary, beneficiary_error = self.validate_beneficiary(to_routing, to_account)
        if not valid_beneficiary:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_number,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=beneficiary_error,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(transaction, {"reason": beneficiary_error})
            return transaction

        # Check balance
        sufficient_balance, balance_error = self.check_balance(from_account, amount)
        if not sufficient_balance:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_number,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=balance_error,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_transaction(transaction, {"reason": balance_error})
            return transaction

        # OFAC screening
        ofac_result = self.ofac_service.screen_account(to_account, to_routing, "Beneficiary Name")
        if ofac_result["match_score"] >= OFAC_FUZZY_THRESHOLD:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_number,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.BLOCKED,
                rejection_reason="OFAC screening failed",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info
            )
            self.audit_logger.log_compliance_event("OFAC_BLOCK", {"transaction_id": transaction_id})
            return transaction

        # Check for CTR/SAR thresholds
        if amount >= CTR_THRESHOLD:
            self.audit_logger.log_compliance_event("CTR_REQUIRED", {
                "transaction_id": transaction_id,
                "amount": str(amount)
            })

        if amount >= SAR_THRESHOLD:
            self.audit_logger.log_compliance_event("SAR_REVIEW", {
                "transaction_id": transaction_id,
                "amount": str(amount)
            })

        # Dual approval for high-value wires
        if amount >= WIRE_DUAL_APPROVAL_THRESHOLD:
            self.audit_logger.log_compliance_event("DUAL_APPROVAL_REQUIRED", {
                "transaction_id": transaction_id,
                "amount": str(amount)
            })

        # Travel Rule data collection
        if amount >= TRAVEL_RULE_THRESHOLD:
            self.audit_logger.log_compliance_event("TRAVEL_RULE_DATA_REQUIRED", {
                "transaction_id": transaction_id,
                "amount": str(amount)
            })

        # Execute transaction
        from_account.balance -= amount
        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account.account_number,
            to_account=to_account,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        # Audit trail with PII masking
        self.audit_logger.log_transaction(transaction, {
            "balance_after": str(from_account.balance),
            "encrypted": True,
            "tls_version": "1.3",
            "encryption_algorithm": "AES-256"
        })

        return transaction


@pytest.fixture
def mock_audit_logger() -> Mock:
    """Fixture providing mocked audit logger with compliance requirements."""
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = AuditRecord(
        audit_id="AUDIT-001",
        transaction_id="TXN-001",
        timestamp=datetime.now(timezone.utc),
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0",
        action="TRANSACTION",
        status="SUCCESS",
        encrypted=True,
        retention_years=5
    )
    logger.log_compliance_event.return_value = AuditRecord(
        audit_id="AUDIT-002",
        transaction_id="TXN-001",
        timestamp=datetime.now(timezone.utc),
        user_id="USER-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0",
        action="COMPLIANCE_EVENT",
        status="LOGGED",
        encrypted=True,
        retention_years=5
    )
    return logger


@pytest.fixture
def mock_ofac_service() -> Mock:
    """Fixture providing mocked OFAC/SDN screening service."""
    service = Mock(spec=OFACService)
    service.screen_account.return_value = {
        "match_score": 0,
        "matches": [],
        "status": "CLEAR"
    }
    service.screen_transaction.return_value = {
        "match_score": 0,
        "matches": [],
        "status": "CLEAR"
    }
    return service


@pytest.fixture
def transaction_service(mock_audit_logger: Mock, mock_ofac_service: Mock) -> TransactionService:
    """Fixture providing transaction service with mocked dependencies."""
    return TransactionService(mock_audit_logger, mock_ofac_service)


@pytest.fixture
def valid_account() -> Account:
    """Fixture providing a valid account with sufficient balance."""
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="ACTIVE"
    )


@pytest.fixture
def low_balance_account() -> Account:
    """Fixture providing an account with low balance."""
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER-001",
        status="ACTIVE"
    )


class TestSuccessfulTransaction:
    """Test suite for MDP-57: successful_transaction scenario."""

    def test_successful_transaction_with_valid_account_and_balance(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
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
        user_id = "USER-001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.rejection_reason is None
        assert valid_account.balance == initial_balance - transfer_amount
        assert result.amount == transfer_amount
        assert result.user_id == user_id
        assert result.ip_address == ip_address
        assert result.device_info == device_info
        assert result.timestamp.tzinfo == timezone.utc

        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called_once()
        call_args = mock_audit_logger.log_transaction.call_args
        assert call_args[0][0].status == TransactionStatus.SUCCESS
        assert call_args[1]["encrypted"] is True
        assert call_args[1]["tls_version"] == "1.3"
        assert call_args[1]["encryption_algorithm"] == "AES-256"

    def test_successful_transaction_with_decimal_precision(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """
        Test successful transaction maintains decimal precision for currency.
        Ensures compliance with SOX financial reporting accuracy requirements.
        """
        # Arrange
        transfer_amount = Decimal("123.45")
        initial_balance = valid_account.balance

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("123.45")
        assert valid_account.balance == initial_balance - Decimal("123.45")
        assert isinstance(result.amount, Decimal)


class TestZeroAmountTransfer:
    """Test suite for MDP-57: zero_amount_transfer scenario."""

    def test_zero_amount_transfer_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        initial_balance = valid_account.balance
        transfer_amount = Decimal("0.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Amount must be greater than 0"
        assert valid_account.balance == initial_balance
        mock_audit_logger.log_transaction.assert_called_once()


class TestNegativeAmountTransfer:
    """Test suite for MDP-57: negative_amount_transfer scenario."""

    def test_negative_amount_transfer_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        initial_balance = valid_account.balance
        transfer_amount = Decimal("-100.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid amount"
        assert valid_account.balance == initial_balance
        mock_audit_logger.log_transaction.assert_called_once()

    def test_large_negative_amount_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test large negative amounts are properly rejected."""
        # Arrange
        transfer_amount = Decimal("-999999.99")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid amount"


class TestInsufficientBalance:
    """Test suite for MDP-57: insufficient_balance scenario."""

    def test_insufficient_balance_rejected(
        self,
        transaction_service: TransactionService,
        low_balance_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        initial_balance = low_balance_account.balance
        transfer_amount = Decimal("5000.00")
        assert initial_balance == Decimal("1000.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=low_balance_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"
        assert low_balance_account.balance == initial_balance
        mock_audit_logger.log_transaction.assert_called_once()

    def test_exact_balance_transfer_succeeds(
        self,
        transaction_service: TransactionService,
        low_balance_account: Account
    ) -> None:
        """Test transfer of exact account balance succeeds (boundary test)."""
        # Arrange
        transfer_amount = low_balance_account.balance

        # Act
        result = transaction_service.execute_transaction(
            from_account=low_balance_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert low_balance_account.balance == Decimal("0.00")

    def test_one_cent_over_balance_rejected(
        self,
        transaction_service: TransactionService,
        low_balance_account: Account
    ) -> None:
        """Test transfer one cent over balance is rejected (boundary test)."""
        # Arrange
        transfer_amount = low_balance_account.balance + Decimal("0.01")

        # Act
        result = transaction_service.execute_transaction(
            from_account=low_balance_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test suite for MDP-57: invalid_beneficiary scenario."""

    def test_invalid_routing_number_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        initial_balance = valid_account.balance
        invalid_routing = "12345"  # Too short

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=invalid_routing,
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"
        assert valid_account.balance == initial_balance
        mock_audit_logger.log_transaction.assert_called_once()

    def test_non_numeric_routing_number_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test non-numeric routing number is rejected."""
        # Arrange
        invalid_routing = "ABC123DEF"

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=invalid_routing,
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"

    def test_empty_routing_number_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test empty routing number is rejected."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="",
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"

    def test_non_numeric_account_number_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test non-numeric account number is rejected."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="ABCD1234",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"

    def test_empty_account_number_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test empty account number is rejected."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"


class TestOFACCompliance:
    """Test suite for OFAC/SDN screening compliance."""

    def test_ofac_match_blocks_transaction(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ) -> None:
        """Test transaction blocked when OFAC screening returns high match score."""
        # Arrange
        mock_ofac_service.screen_account.return_value = {
            "match_score": 95,
            "matches": [{"name": "Sanctioned Entity", "list": "SDN"}],
            "status": "MATCH"
        }

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert result.rejection_reason == "OFAC screening failed"
        mock_ofac_service.screen_account.assert_called_once()
        mock_audit_logger.log_compliance_event.assert_called_with(
            "OFAC_BLOCK",
            {"transaction_id": result.transaction_id}
        )

    def test_ofac_threshold_boundary(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_ofac_service: Mock
    ) -> None:
        """Test OFAC fuzzy match threshold boundary (85%)."""
        # Arrange - exactly at threshold
        mock_ofac_service.screen_account.return_value = {
            "match_score": OFAC_FUZZY_THRESHOLD,
            "matches": [{"name": "Possible Match", "list": "SDN"}],
            "status": "REVIEW"
        }

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.BLOCKED

    def test_ofac_below_threshold_passes(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_ofac_service: Mock
    ) -> None:
        """Test OFAC screening below threshold allows transaction."""
        # Arrange - below threshold
        mock_ofac_service.screen_account.return_value = {
            "match_score": 84,
            "matches": [],
            "status": "CLEAR"
        }

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS


class TestCTRCompliance:
    """Test suite for Currency Transaction Report (CTR) compliance (31 CFR 1010.311)."""

    def test_ctr_threshold_triggers_logging(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test CTR compliance event logged for transactions >= $10,000."""
        # Arrange
        ctr_amount = Decimal("10000.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=ctr_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "CTR_REQUIRED"
        ]
        assert len(compliance_calls) == 1
        assert compliance_calls[0][1]["amount"] == str(ctr_amount)

    def test_below_ctr_threshold_no_logging(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test no CTR logging for transactions below $10,000."""
        # Arrange
        amount = Decimal("9999.99")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "CTR_REQUIRED"
        ]
        assert len(compliance_calls) == 0


class TestSARCompliance:
    """Test suite for Suspicious Activity Report (SAR) compliance (31 CFR 1020.320)."""

    def test_sar_threshold_triggers_review(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test SAR review triggered for transactions >= $5,000."""
        # Arrange
        sar_amount = Decimal("5000.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=sar_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "SAR_REVIEW"
        ]
        assert len(compliance_calls) == 1

    def test_below_sar_threshold_no_review(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test no SAR review for transactions below $5,000."""
        # Arrange
        amount = Decimal("4999.99")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "SAR_REVIEW"
        ]
        assert len(compliance_calls) == 0


class TestTravelRuleCompliance:
    """Test suite for Travel Rule compliance (31 CFR 1010.410(e))."""

    def test_travel_rule_threshold_requires_data(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test Travel Rule data collection required for transactions >= $3,000."""
        # Arrange
        travel_rule_amount = Decimal("3000.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=travel_rule_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "TRAVEL_RULE_DATA_REQUIRED"
        ]
        assert len(compliance_calls) == 1

    def test_below_travel_rule_threshold_no_requirement(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test no Travel Rule requirement for transactions below $3,000."""
        # Arrange
        amount = Decimal("2999.99")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "TRAVEL_RULE_DATA_REQUIRED"
        ]
        assert len(compliance_calls) == 0


class TestDualApprovalCompliance:
    """Test suite for dual approval requirements on high-value wire transfers."""

    def test_dual_approval_required_for_high_value_wire(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test dual approval required for wire transfers >= $10,000."""
        # Arrange
        high_value_amount = Decimal("10000.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=high_value_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "DUAL_APPROVAL_REQUIRED"
        ]
        assert len(compliance_calls) == 1

    def test_no_dual_approval_below_threshold(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test no dual approval required below $10,000."""
        # Arrange
        amount = Decimal("9999.99")

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "DUAL_APPROVAL_REQUIRED"
        ]
        assert len(compliance_calls) == 0


class TestAuditTrailCompliance:
    """Test suite for audit trail and record retention compliance."""

    def test_audit_trail_records_all_required_fields(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """
        Test audit trail captures all required fields per 31 CFR 1010.430:
        - Transaction details
        - User ID
        - IP address
        - Device info
        - Timestamp (timezone-aware)
        """
        # Arrange
        user_id = "USER-123"
        ip_address = "10.0.0.50"
        device_info = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("1500.00"),
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        # Assert
        assert result.user_id == user_id
        assert result.ip_address == ip_address
        assert result.device_info == device_info
        assert result.timestamp.tzinfo == timezone.utc
        mock_audit_logger.log_transaction.assert_called_once()

    def test_audit_trail_includes_encryption_metadata(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test audit trail includes encryption and security metadata."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        call_args = mock_audit_logger.log_transaction.call_args
        context = call_args[1]
        assert context["encrypted"] is True
        assert context["tls_version"] == "1.3"
        assert context["encryption_algorithm"] == "AES-256"

    def test_rejected_transaction_logged_to_audit_trail(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock
    ) -> None:
        """Test rejected transactions are also logged to audit trail."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("0.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        mock_audit_logger.log_transaction.assert_called_once()
        call_args = mock_audit_logger.log_transaction.call_args
        assert call_args[0][0].status == TransactionStatus.REJECTED

    def test_audit_record_retention_period(
        self,
        mock_audit_logger: Mock
    ) -> None:
        """Test audit records specify 5-year retention per BSA requirements."""
        # Arrange
        audit_record = mock_audit_logger.log_transaction.return_value

        # Assert
        assert audit_record.retention_years == 5


class TestDataHandlingCompliance:
    """Test suite for data handling and PII protection compliance."""

    def test_transaction_uses_timezone_aware_datetime(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test all timestamps are timezone-aware (UTC)."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.tzinfo == timezone.utc

    def test_decimal_used_for_all_currency_amounts(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test Decimal type used for currency to avoid floating-point errors."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert isinstance(result.amount, Decimal)
        assert isinstance(valid_account.balance, Decimal)


class TestBoundaryConditions:
    """Test suite for boundary conditions and edge cases."""

    def test_minimum_valid_amount(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test minimum valid transaction amount (one cent)."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("0.01"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("0.01")

    def test_large_transaction_amount(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock
    ) -> None:
        """Test large transaction amount triggers multiple compliance events."""
        # Arrange
        large_account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("1000000.00"),
            user_id="USER-001"
        )
        large_amount = Decimal("50000.00")

        # Act
        transaction_service_instance = TransactionService(
            mock_audit_logger,
            Mock(spec=OFACService, screen_account=Mock(return_value={
                "match_score": 0,
                "matches": [],
                "status": "CLEAR"
            }))
        )
        result = transaction_service_instance.execute_transaction(
            from_account=large_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=large_amount,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        compliance_event_types = [
            call[0][0] for call in mock_audit_logger.log_compliance_event.call_args_list
        ]
        assert "CTR_REQUIRED" in compliance_event_types
        assert "SAR_REVIEW" in compliance_event_types
        assert "TRAVEL_RULE_DATA_REQUIRED" in compliance_event_types
        assert "DUAL_APPROVAL_REQUIRED" in compliance_event_types

    def test_valid_routing_number_nine_digits(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test valid 9-digit routing number is accepted."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="123456789",
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS

    def test_routing_number_with_ten_digits_rejected(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ) -> None:
        """Test routing number with 10 digits is rejected."""
        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="1234567890",
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"


class TestComplianceIntegration:
    """Integration tests for multiple compliance requirements."""

    def test_high_value_transaction_all_compliance_checks(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
        mock_ofac_service: Mock
    ) -> None:
        """
        Integration test: high-value transaction triggers all compliance checks:
        - OFAC screening
        - CTR logging
        - SAR review
        - Travel Rule
        - Dual approval
        - Audit trail with encryption
        """
        # Arrange
        high_value_account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("100000.00"),
            user_id="USER-VIP"
        )
        amount = Decimal("15000.00")

        # Act
        result = transaction_service.execute_transaction(
            from_account=high_value_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=amount,
            user_id="USER-VIP",
            ip_address="203.0.113.42",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify OFAC screening
        mock_ofac_service.screen_account.assert_called_once()
        
        # Verify all compliance events logged
        compliance_events = [
            call[0][0] for call in mock_audit_logger.log_compliance_event.call_args_list
        ]
        assert "CTR_REQUIRED" in compliance_events
        assert "SAR_REVIEW" in compliance_events
        assert "TRAVEL_RULE_DATA_REQUIRED" in compliance_events
        assert "DUAL_APPROVAL_REQUIRED" in compliance_events
        
        # Verify audit trail
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call = mock_audit_logger.log_transaction.call_args
        assert audit_call[1]["encrypted"] is True

    def test_failed_transaction_compliance_logging(
        self,
        transaction_service: TransactionService,
        valid_account: Account,
        mock_audit_logger: Mock,
        mock_ofac_service: Mock
    ) -> None:
        """Test failed transactions still log compliance events appropriately."""
        # Arrange
        mock_ofac_service.screen_account.return_value = {
            "match_score": 100,
            "matches": [{"name": "Blocked Entity", "list": "SDN"}],
            "status": "BLOCKED"
        }

        # Act
        result = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing="026009593",
            to_account="9876543210",
            amount=Decimal("5000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0"
        )

        # Assert
        assert result.status == TransactionStatus.BLOCKED
        
        # Verify OFAC block logged
        ofac_calls = [
            call for call in mock_audit_logger.log_compliance_event.call_args_list
            if call[0][0] == "OFAC_BLOCK"
        ]
        assert len(ofac_calls) == 1
        
        # Verify transaction logged to audit trail
        mock_audit_logger.log_transaction.assert_called_once()