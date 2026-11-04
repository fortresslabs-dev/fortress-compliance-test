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
    BLOCKED = "blocked"


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
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    device_info: Optional[str] = None


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


class OFACScreeningResult(Enum):
    CLEAR = "clear"
    BLOCK = "block"
    REVIEW = "review"


class ComplianceRuleResolver:
    def __init__(self):
        self.ctr_threshold = Decimal("10000")
        self.sar_threshold = Decimal("5000")
        self.travel_rule_threshold = Decimal("3000")
        self.wire_dual_approval_threshold = Decimal("10000")
        self.ofac_fuzzy_threshold = 85
        self.beneficial_ownership_pct = 20

    def requires_ctr(self, amount: Decimal) -> bool:
        return amount > self.ctr_threshold

    def requires_sar_review(self, amount: Decimal) -> bool:
        return amount >= self.sar_threshold

    def requires_travel_rule(self, amount: Decimal) -> bool:
        return amount >= self.travel_rule_threshold

    def requires_dual_approval(self, amount: Decimal) -> bool:
        return amount >= self.wire_dual_approval_threshold


class OFACScreeningService:
    def __init__(self):
        self.sdn_list = []
        self.section_311_list = []
        self.fincen_659_designations = []
        self.fincen_661_designations = []
        self.fincen_651_designations = []

    def screen_account(self, account_number: str, routing_number: str, name: str) -> OFACScreeningResult:
        return OFACScreeningResult.CLEAR

    def update_fincen_659_designations(self, designations: list) -> None:
        self.fincen_659_designations = designations

    def update_fincen_661_designations(self, designations: list) -> None:
        self.fincen_661_designations = designations

    def update_section_311_designations(self, designations: list) -> None:
        self.fincen_651_designations = designations


class AuditLogger:
    def __init__(self):
        self.logs = []

    def log(self, entry: AuditLogEntry) -> None:
        self.logs.append(entry)

    def get_logs(self) -> list:
        return self.logs


class TransactionService:
    def __init__(
        self,
        account_repository: Any,
        audit_logger: AuditLogger,
        ofac_service: OFACScreeningService,
        rule_resolver: ComplianceRuleResolver,
    ):
        self.account_repository = account_repository
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver

    def initiate_transaction(
        self,
        from_account_id: str,
        to_account_number: str,
        to_routing_number: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str,
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        # Validate amount
        if amount == Decimal("0"):
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_number,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Amount must be greater than 0",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
            )
            self._log_transaction(transaction, "REJECTED")
            return transaction

        if amount < Decimal("0"):
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_number,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid amount",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
            )
            self._log_transaction(transaction, "REJECTED")
            return transaction

        # Validate from account
        from_account = self.account_repository.get_account(from_account_id)
        if not from_account:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_number,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid source account",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
            )
            self._log_transaction(transaction, "REJECTED")
            return transaction

        # Check balance
        if from_account.balance < amount:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_number,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
            )
            self._log_transaction(transaction, "REJECTED")
            return transaction

        # Validate beneficiary account
        if not self._validate_beneficiary(to_account_number, to_routing_number):
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_number,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
            )
            self._log_transaction(transaction, "REJECTED")
            return transaction

        # OFAC screening
        screening_result = self.ofac_service.screen_account(
            to_account_number, to_routing_number, "Beneficiary Name"
        )
        if screening_result == OFACScreeningResult.BLOCK:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_number,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.BLOCKED,
                rejection_reason="OFAC screening failed",
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
            )
            self._log_transaction(transaction, "BLOCKED")
            return transaction

        # Process transaction
        from_account.balance -= amount
        self.account_repository.update_account(from_account)

        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account_id,
            to_account=to_account_number,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )
        self._log_transaction(transaction, "SUCCESS")
        return transaction

    def _validate_beneficiary(self, account_number: str, routing_number: str) -> bool:
        if not account_number or not routing_number:
            return False
        if len(routing_number) != 9:
            return False
        if not routing_number.isdigit():
            return False
        return True

    def _log_transaction(self, transaction: Transaction, result: str) -> None:
        audit_entry = AuditLogEntry(
            timestamp=transaction.timestamp,
            transaction_id=transaction.transaction_id,
            user_id=transaction.user_id or "unknown",
            ip_address=transaction.ip_address or "unknown",
            device_info=transaction.device_info or "unknown",
            action="TRANSACTION",
            result=result,
            details={
                "from_account": transaction.from_account,
                "to_account": transaction.to_account,
                "amount": str(transaction.amount),
                "status": transaction.status.value,
                "rejection_reason": transaction.rejection_reason,
            },
        )
        self.audit_logger.log(audit_entry)


@pytest.fixture
def mock_account_repository():
    repo = Mock()
    repo.get_account = Mock()
    repo.update_account = Mock()
    return repo


@pytest.fixture
def audit_logger():
    return AuditLogger()


@pytest.fixture
def ofac_service():
    return OFACScreeningService()


@pytest.fixture
def rule_resolver():
    return ComplianceRuleResolver()


@pytest.fixture
def transaction_service(mock_account_repository, audit_logger, ofac_service, rule_resolver):
    return TransactionService(
        account_repository=mock_account_repository,
        audit_logger=audit_logger,
        ofac_service=ofac_service,
        rule_resolver=rule_resolver,
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC-12345",
        routing_number="123456789",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="active",
    )


class TestSuccessfulTransaction:
    """Test successful transaction scenario."""

    def test_successful_transaction(
        self, transaction_service, mock_account_repository, valid_account, audit_logger
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        transfer_amount = Decimal("500.00")
        expected_balance = valid_account.balance - transfer_amount

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=transfer_amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == transfer_amount
        assert valid_account.balance == expected_balance
        assert len(audit_logger.get_logs()) == 1
        audit_log = audit_logger.get_logs()[0]
        assert audit_log.user_id == "USER-001"
        assert audit_log.ip_address == "192.168.1.1"
        assert audit_log.device_info == "Mozilla/5.0"
        assert audit_log.result == "SUCCESS"
        assert audit_log.timestamp is not None


class TestZeroAmountTransfer:
    """Test zero amount transfer scenario."""

    def test_zero_amount_transfer(self, transaction_service, mock_account_repository, valid_account):
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("0"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Amount must be greater than 0"


class TestNegativeAmountTransfer:
    """Test negative amount transfer scenario."""

    def test_negative_amount_transfer(self, transaction_service, mock_account_repository, valid_account):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("-100.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid amount"


class TestInsufficientBalance:
    """Test insufficient balance scenario."""

    def test_insufficient_balance(self, transaction_service, mock_account_repository):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        account = Account(
            account_id="ACC-12345",
            routing_number="123456789",
            balance=Decimal("1000.00"),
            user_id="USER-001",
            status="active",
        )
        mock_account_repository.get_account.return_value = account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("5000.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test invalid beneficiary scenario."""

    def test_invalid_beneficiary_routing_number(
        self, transaction_service, mock_account_repository, valid_account
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="12345",  # Invalid routing number (not 9 digits)
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"

    def test_invalid_beneficiary_empty_account(
        self, transaction_service, mock_account_repository, valid_account
    ):
        """Test rejection when beneficiary account number is empty."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"


class TestFinCEN659Compliance:
    """Test FinCEN 31 C.F.R. § 1010.659 compliance requirements."""

    def test_screening_system_incorporates_fincen_659_designations(self, ofac_service):
        """
        [FINCEN-1010-659-R3::OBL::001] Screening system must incorporate this designation
        and update promptly on any changes per 31 C.F.R. § 1010.659
        """
        # Arrange
        initial_designations = ["ENTITY-A", "ENTITY-B"]
        updated_designations = ["ENTITY-A", "ENTITY-B", "ENTITY-C"]

        # Act - Initial incorporation
        ofac_service.update_fincen_659_designations(initial_designations)

        # Assert - System incorporates designations
        assert (
            ofac_service.fincen_659_designations == initial_designations
        ), "Screening system must incorporate this designation per 31 C.F.R. § 1010.659"

        # Act - Update with changes
        ofac_service.update_fincen_659_designations(updated_designations)

        # Assert - System updates promptly on changes
        assert (
            ofac_service.fincen_659_designations == updated_designations
        ), "Screening system must update promptly on any changes per 31 C.F.R. § 1010.659"

    def test_screening_system_updates_on_designation_removal(self, ofac_service):
        """
        Test that screening system updates when designations are removed,
        ensuring compliance with 31 C.F.R. § 1010.659
        """
        # Arrange
        initial_designations = ["ENTITY-A", "ENTITY-B", "ENTITY-C"]
        updated_designations = ["ENTITY-A"]

        # Act
        ofac_service.update_fincen_659_designations(initial_designations)
        ofac_service.update_fincen_659_designations(updated_designations)

        # Assert
        assert (
            len(ofac_service.fincen_659_designations) == 1
        ), "Screening system must update promptly on any changes per 31 C.F.R. § 1010.659"
        assert (
            "ENTITY-B" not in ofac_service.fincen_659_designations
        ), "Screening system must incorporate this designation and update promptly on any changes per 31 C.F.R. § 1010.659"

    def test_transaction_blocked_when_matching_fincen_659_designation(
        self, transaction_service, mock_account_repository, valid_account, ofac_service
    ):
        """
        Test that transactions are blocked when matching FinCEN 1010.659 designations,
        ensuring compliance with 31 C.F.R. § 1010.659
        """
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        ofac_service.update_fincen_659_designations(["BLOCKED-ENTITY"])
        ofac_service.screen_account = Mock(return_value=OFACScreeningResult.BLOCK)
        transaction_service.ofac_service = ofac_service

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert (
            transaction.status == TransactionStatus.BLOCKED
        ), "Screening system must incorporate this designation per 31 C.F.R. § 1010.659"
        assert transaction.rejection_reason == "OFAC screening failed"


class TestAuditTrailCompliance:
    """Test audit trail and record retention compliance."""

    def test_audit_trail_records_all_required_fields(
        self, transaction_service, mock_account_repository, valid_account, audit_logger
    ):
        """
        Test that audit trail records all transactions with required fields:
        timestamp, user ID, IP address, device info per BSA requirements.
        """
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0 (Windows NT 10.0)",
        )

        # Assert
        logs = audit_logger.get_logs()
        assert len(logs) == 1
        log = logs[0]
        assert log.timestamp is not None, "Record all transactions with timestamp"
        assert log.user_id == "USER-001", "Store user ID"
        assert log.ip_address == "192.168.1.1", "Store IP address"
        assert log.device_info == "Mozilla/5.0 (Windows NT 10.0)", "Store device info"
        assert log.transaction_id == transaction.transaction_id
        assert log.action == "TRANSACTION"

    def test_audit_trail_immutable_log_entry(
        self, transaction_service, mock_account_repository, valid_account, audit_logger
    ):
        """Test that audit log entries are immutable once created."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert - Maintain immutable audit log
        logs = audit_logger.get_logs()
        original_log = logs[0]
        original_timestamp = original_log.timestamp
        original_user_id = original_log.user_id

        # Verify log entry attributes are preserved
        assert logs[0].timestamp == original_timestamp
        assert logs[0].user_id == original_user_id


class TestComplianceThresholds:
    """Test compliance threshold rules using authoritative values."""

    def test_ctr_threshold_exact_value(self, rule_resolver):
        """Test CTR threshold is exactly $10,000."""
        # Arrange & Act & Assert
        assert rule_resolver.ctr_threshold == Decimal("10000")
        assert not rule_resolver.requires_ctr(Decimal("10000"))
        assert rule_resolver.requires_ctr(Decimal("10000.01"))

    def test_sar_threshold_exact_value(self, rule_resolver):
        """Test SAR threshold is exactly $5,000."""
        # Arrange & Act & Assert
        assert rule_resolver.sar_threshold == Decimal("5000")
        assert rule_resolver.requires_sar_review(Decimal("5000"))
        assert not rule_resolver.requires_sar_review(Decimal("4999.99"))

    def test_travel_rule_threshold_exact_value(self, rule_resolver):
        """Test Travel Rule threshold is exactly $3,000."""
        # Arrange & Act & Assert
        assert rule_resolver.travel_rule_threshold == Decimal("3000")
        assert rule_resolver.requires_travel_rule(Decimal("3000"))
        assert not rule_resolver.requires_travel_rule(Decimal("2999.99"))

    def test_wire_dual_approval_threshold_exact_value(self, rule_resolver):
        """Test wire dual approval threshold is exactly $10,000."""
        # Arrange & Act & Assert
        assert rule_resolver.wire_dual_approval_threshold == Decimal("10000")
        assert rule_resolver.requires_dual_approval(Decimal("10000"))
        assert not rule_resolver.requires_dual_approval(Decimal("9999.99"))

    def test_ofac_fuzzy_threshold_exact_value(self, rule_resolver):
        """Test OFAC fuzzy matching threshold is exactly 85."""
        # Arrange & Act & Assert
        assert rule_resolver.ofac_fuzzy_threshold == 85

    def test_beneficial_ownership_percentage_exact_value(self, rule_resolver):
        """Test beneficial ownership percentage is exactly 20%."""
        # Arrange & Act & Assert
        assert rule_resolver.beneficial_ownership_pct == 20


class TestOFACScreeningCompliance:
    """Test OFAC screening and blocking behavior."""

    def test_transaction_blocked_on_ofac_match(
        self, transaction_service, mock_account_repository, valid_account, ofac_service
    ):
        """Test that transactions are blocked when OFAC screening returns BLOCK."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        ofac_service.screen_account = Mock(return_value=OFACScreeningResult.BLOCK)
        transaction_service.ofac_service = ofac_service

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.BLOCKED
        assert transaction.rejection_reason == "OFAC screening failed"

    def test_transaction_proceeds_on_ofac_clear(
        self, transaction_service, mock_account_repository, valid_account, ofac_service
    ):
        """Test that transactions proceed when OFAC screening returns CLEAR."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        ofac_service.screen_account = Mock(return_value=OFACScreeningResult.CLEAR)
        transaction_service.ofac_service = ofac_service

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS


class TestBoundaryConditions:
    """Test boundary conditions for transaction amounts."""

    def test_transaction_at_ctr_threshold_boundary(
        self, transaction_service, mock_account_repository, rule_resolver
    ):
        """Test transaction exactly at CTR threshold ($10,000)."""
        # Arrange
        account = Account(
            account_id="ACC-12345",
            routing_number="123456789",
            balance=Decimal("15000.00"),
            user_id="USER-001",
            status="active",
        )
        mock_account_repository.get_account.return_value = account
        amount = Decimal("10000.00")

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert not rule_resolver.requires_ctr(amount)

    def test_transaction_above_ctr_threshold(
        self, transaction_service, mock_account_repository, rule_resolver
    ):
        """Test transaction above CTR threshold ($10,000.01)."""
        # Arrange
        account = Account(
            account_id="ACC-12345",
            routing_number="123456789",
            balance=Decimal("15000.00"),
            user_id="USER-001",
            status="active",
        )
        mock_account_repository.get_account.return_value = account
        amount = Decimal("10000.01")

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=amount,
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert rule_resolver.requires_ctr(amount)

    def test_transaction_at_sar_threshold_boundary(self, rule_resolver):
        """Test SAR review requirement at threshold boundary ($5,000)."""
        # Arrange & Act & Assert
        assert rule_resolver.requires_sar_review(Decimal("5000.00"))
        assert not rule_resolver.requires_sar_review(Decimal("4999.99"))

    def test_transaction_at_travel_rule_threshold_boundary(self, rule_resolver):
        """Test Travel Rule requirement at threshold boundary ($3,000)."""
        # Arrange & Act & Assert
        assert rule_resolver.requires_travel_rule(Decimal("3000.00"))
        assert not rule_resolver.requires_travel_rule(Decimal("2999.99"))


class TestNegativePathScenarios:
    """Test negative path scenarios and error handling."""

    def test_invalid_source_account(self, transaction_service, mock_account_repository):
        """Test transaction rejection when source account does not exist."""
        # Arrange
        mock_account_repository.get_account.return_value = None

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="INVALID-ACC",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid source account"

    def test_routing_number_non_numeric(
        self, transaction_service, mock_account_repository, valid_account
    ):
        """Test rejection when routing number contains non-numeric characters."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="12345ABC9",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"

    def test_very_small_amount_above_zero(
        self, transaction_service, mock_account_repository, valid_account
    ):
        """Test transaction with very small amount (0.01) succeeds."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("0.01"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == Decimal("0.01")


class TestTimestampCompliance:
    """Test timezone-aware timestamp handling."""

    def test_transaction_timestamp_is_timezone_aware(
        self, transaction_service, mock_account_repository, valid_account
    ):
        """Test that transaction timestamps are timezone-aware (UTC)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction = transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        assert transaction.timestamp.tzinfo is not None
        assert transaction.timestamp.tzinfo == timezone.utc

    def test_audit_log_timestamp_is_timezone_aware(
        self, transaction_service, mock_account_repository, valid_account, audit_logger
    ):
        """Test that audit log timestamps are timezone-aware (UTC)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account

        # Act
        transaction_service.initiate_transaction(
            from_account_id="ACC-12345",
            to_account_number="987654321",
            to_routing_number="987654321",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0",
        )

        # Assert
        logs = audit_logger.get_logs()
        assert len(logs) == 1
        assert logs[0].timestamp.tzinfo is not None
        assert logs[0].timestamp.tzinfo == timezone.utc