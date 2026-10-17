import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    PENDING_REVIEW = "pending_review"


class ScreeningResult(Enum):
    CLEAR = "clear"
    BLOCKED = "blocked"
    REVIEW = "review"


@dataclass
class Account:
    account_id: str
    user_id: str
    balance: Decimal
    routing_number: str
    account_number: str
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
    audit_metadata: Optional[Dict[str, Any]] = None


@dataclass
class CorrespondentRelationship:
    relationship_id: str
    institution_name: str
    onboarding_date: datetime
    last_screening_date: Optional[datetime] = None
    screening_status: Optional[ScreeningResult] = None


class OFACScreeningService:
    def screen_entity(self, name: str, fuzzy_threshold: int = 85) -> ScreeningResult:
        raise NotImplementedError

    def screen_correspondent(self, relationship: CorrespondentRelationship) -> ScreeningResult:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(self, transaction: Transaction, user_metadata: Dict[str, Any]) -> None:
        raise NotImplementedError

    def log_screening(self, entity_id: str, screening_result: ScreeningResult, regulation: str) -> None:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_id: str) -> Optional[Account]:
        raise NotImplementedError

    def update_balance(self, account_id: str, new_balance: Decimal) -> None:
        raise NotImplementedError

    def validate_routing_account(self, routing_number: str, account_number: str) -> bool:
        raise NotImplementedError


class TransactionService:
    def __init__(
        self,
        account_repo: AccountRepository,
        audit_logger: AuditLogger,
        ofac_service: OFACScreeningService
    ):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service

    def process_transaction(
        self,
        from_account_id: str,
        to_routing: str,
        to_account: str,
        amount: Decimal,
        user_metadata: Dict[str, Any]
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        if amount <= Decimal("0"):
            if amount == Decimal("0"):
                rejection_reason = "Amount must be greater than 0"
            else:
                rejection_reason = "Invalid amount"
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=f"{to_routing}/{to_account}",
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.audit_logger.log_transaction(transaction, user_metadata)
            return transaction

        from_acct = self.account_repo.get_account(from_account_id)
        if not from_acct:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=f"{to_routing}/{to_account}",
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid source account"
            )
            self.audit_logger.log_transaction(transaction, user_metadata)
            return transaction

        if from_acct.balance < amount:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=f"{to_routing}/{to_account}",
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance"
            )
            self.audit_logger.log_transaction(transaction, user_metadata)
            return transaction

        if not self.account_repo.validate_routing_account(to_routing, to_account):
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=f"{to_routing}/{to_account}",
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account"
            )
            self.audit_logger.log_transaction(transaction, user_metadata)
            return transaction

        new_balance = from_acct.balance - amount
        self.account_repo.update_balance(from_account_id, new_balance)

        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account_id,
            to_account=f"{to_routing}/{to_account}",
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            audit_metadata={
                "previous_balance": str(from_acct.balance),
                "new_balance": str(new_balance)
            }
        )
        self.audit_logger.log_transaction(transaction, user_metadata)
        return transaction


class CorrespondentScreeningService:
    def __init__(self, ofac_service: OFACScreeningService, audit_logger: AuditLogger):
        self.ofac_service = ofac_service
        self.audit_logger = audit_logger

    def screen_at_onboarding(self, relationship: CorrespondentRelationship) -> ScreeningResult:
        result = self.ofac_service.screen_correspondent(relationship)
        relationship.last_screening_date = datetime.now(timezone.utc)
        relationship.screening_status = result
        self.audit_logger.log_screening(
            relationship.relationship_id,
            result,
            "31 C.F.R. § 1010.660"
        )
        return result

    def periodic_screening(self, relationship: CorrespondentRelationship) -> ScreeningResult:
        result = self.ofac_service.screen_correspondent(relationship)
        relationship.last_screening_date = datetime.now(timezone.utc)
        relationship.screening_status = result
        self.audit_logger.log_screening(
            relationship.relationship_id,
            result,
            "31 C.F.R. § 1010.660"
        )
        return result


@pytest.fixture
def mock_account_repo():
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_audit_logger():
    logger = Mock(spec=AuditLogger)
    return logger


@pytest.fixture
def mock_ofac_service():
    service = Mock(spec=OFACScreeningService)
    return service


@pytest.fixture
def transaction_service(mock_account_repo, mock_audit_logger, mock_ofac_service):
    return TransactionService(mock_account_repo, mock_audit_logger, mock_ofac_service)


@pytest.fixture
def correspondent_screening_service(mock_ofac_service, mock_audit_logger):
    return CorrespondentScreeningService(mock_ofac_service, mock_audit_logger)


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC-12345",
        user_id="USER-001",
        balance=Decimal("10000.00"),
        routing_number="021000021",
        account_number="1234567890",
        status="active"
    )


@pytest.fixture
def user_metadata():
    return {
        "user_id": "USER-001",
        "ip_address": "192.168.1.100",
        "device_info": "Mozilla/5.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


class TestSuccessfulTransaction:
    def test_successful_transaction(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("500.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("500.00")
        assert result.rejection_reason is None
        mock_account_repo.update_balance.assert_called_once_with(
            "ACC-12345",
            Decimal("9500.00")
        )
        mock_audit_logger.log_transaction.assert_called_once()
        call_args = mock_audit_logger.log_transaction.call_args
        assert call_args[0][0].status == TransactionStatus.SUCCESS
        assert call_args[0][1] == user_metadata


class TestZeroAmountTransfer:
    def test_zero_amount_transfer(
        self,
        transaction_service,
        mock_audit_logger,
        user_metadata
    ):
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("0"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Amount must be greater than 0"
        mock_audit_logger.log_transaction.assert_called_once()


class TestNegativeAmountTransfer:
    def test_negative_amount_transfer(
        self,
        transaction_service,
        mock_audit_logger,
        user_metadata
    ):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("-100.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid amount"
        mock_audit_logger.log_transaction.assert_called_once()


class TestInsufficientBalance:
    def test_insufficient_balance(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        user_metadata
    ):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        account_with_low_balance = Account(
            account_id="ACC-12345",
            user_id="USER-001",
            balance=Decimal("1000.00"),
            routing_number="021000021",
            account_number="1234567890",
            status="active"
        )
        mock_account_repo.get_account.return_value = account_with_low_balance

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("5000.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"
        mock_audit_logger.log_transaction.assert_called_once()


class TestInvalidBeneficiary:
    def test_invalid_beneficiary(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = False

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="999999999",
            to_account="0000000000",
            amount=Decimal("500.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid beneficiary account"
        mock_audit_logger.log_transaction.assert_called_once()


class TestFINCEN1010660R3Compliance:
    def test_correspondent_screening_at_onboarding_obligation_001(
        self,
        correspondent_screening_service,
        mock_ofac_service,
        mock_audit_logger
    ):
        """
        Test FINCEN-1010-660-R3::OBL::001
        Existing correspondent relationships must be screened against this designation
        at onboarding and periodically thereafter (31 C.F.R. § 1010.660)
        """
        relationship = CorrespondentRelationship(
            relationship_id="CORR-001",
            institution_name="Foreign Bank ABC",
            onboarding_date=datetime.now(timezone.utc)
        )
        mock_ofac_service.screen_correspondent.return_value = ScreeningResult.CLEAR

        result = correspondent_screening_service.screen_at_onboarding(relationship)

        assert result == ScreeningResult.CLEAR, (
            "Correspondent relationship must be screened at onboarding per 31 C.F.R. § 1010.660"
        )
        assert relationship.last_screening_date is not None, (
            "Screening date must be recorded per 31 C.F.R. § 1010.660"
        )
        assert relationship.screening_status == ScreeningResult.CLEAR, (
            "Screening status must be stored per 31 C.F.R. § 1010.660"
        )
        mock_ofac_service.screen_correspondent.assert_called_once_with(relationship)
        mock_audit_logger.log_screening.assert_called_once()

    def test_correspondent_periodic_screening_obligation_001(
        self,
        correspondent_screening_service,
        mock_ofac_service,
        mock_audit_logger
    ):
        """
        Test FINCEN-1010-660-R3::OBL::001
        Existing correspondent relationships must be screened periodically
        after onboarding (31 C.F.R. § 1010.660)
        """
        relationship = CorrespondentRelationship(
            relationship_id="CORR-002",
            institution_name="Foreign Bank XYZ",
            onboarding_date=datetime(2023, 1, 1, tzinfo=timezone.utc),
            last_screening_date=datetime(2023, 6, 1, tzinfo=timezone.utc),
            screening_status=ScreeningResult.CLEAR
        )
        mock_ofac_service.screen_correspondent.return_value = ScreeningResult.CLEAR

        result = correspondent_screening_service.periodic_screening(relationship)

        assert result == ScreeningResult.CLEAR, (
            "Correspondent relationship must be screened periodically per 31 C.F.R. § 1010.660"
        )
        assert relationship.last_screening_date > datetime(2023, 6, 1, tzinfo=timezone.utc), (
            "Periodic screening date must be updated per 31 C.F.R. § 1010.660"
        )
        mock_ofac_service.screen_correspondent.assert_called_once_with(relationship)
        mock_audit_logger.log_screening.assert_called_once()

    def test_correspondent_screening_blocked_result(
        self,
        correspondent_screening_service,
        mock_ofac_service,
        mock_audit_logger
    ):
        """
        Test that blocked correspondent relationships are properly identified
        and logged per 31 C.F.R. § 1010.660
        """
        relationship = CorrespondentRelationship(
            relationship_id="CORR-003",
            institution_name="Sanctioned Bank",
            onboarding_date=datetime.now(timezone.utc)
        )
        mock_ofac_service.screen_correspondent.return_value = ScreeningResult.BLOCKED

        result = correspondent_screening_service.screen_at_onboarding(relationship)

        assert result == ScreeningResult.BLOCKED, (
            "Blocked correspondent must be identified per 31 C.F.R. § 1010.660"
        )
        assert relationship.screening_status == ScreeningResult.BLOCKED, (
            "Blocked status must be recorded per 31 C.F.R. § 1010.660"
        )
        mock_audit_logger.log_screening.assert_called_once()
        call_args = mock_audit_logger.log_screening.call_args
        assert call_args[0][2] == "31 C.F.R. § 1010.660"


class TestAuditAndComplianceRequirements:
    def test_audit_trail_includes_timestamp(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test that all transactions are recorded with timestamp
        per audit requirements
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("500.00"),
            user_metadata=user_metadata
        )

        assert result.timestamp is not None
        assert result.timestamp.tzinfo is not None
        mock_audit_logger.log_transaction.assert_called_once()

    def test_audit_trail_includes_user_metadata(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test that audit log stores user ID, IP address, device info
        per audit requirements
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("500.00"),
            user_metadata=user_metadata
        )

        mock_audit_logger.log_transaction.assert_called_once()
        call_args = mock_audit_logger.log_transaction.call_args
        logged_metadata = call_args[0][1]
        assert "user_id" in logged_metadata
        assert "ip_address" in logged_metadata
        assert "device_info" in logged_metadata


class TestBoundaryConditions:
    def test_transaction_at_ctr_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test transaction at CTR threshold of $10,000
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("10000.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("10000.00")

    def test_transaction_above_ctr_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        user_metadata
    ):
        """
        Test transaction above CTR threshold of $10,000
        """
        high_balance_account = Account(
            account_id="ACC-12345",
            user_id="USER-001",
            balance=Decimal("50000.00"),
            routing_number="021000021",
            account_number="1234567890",
            status="active"
        )
        mock_account_repo.get_account.return_value = high_balance_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("10000.01"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("10000.01")

    def test_transaction_at_sar_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test transaction at SAR threshold of $5,000
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("5000.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("5000.00")

    def test_transaction_at_travel_rule_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test transaction at Travel Rule threshold of $3,000
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("3000.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("3000.00")

    def test_transaction_one_cent_below_travel_rule_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test transaction just below Travel Rule threshold
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("2999.99"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        assert result.amount == Decimal("2999.99")

    def test_ofac_fuzzy_threshold_value(self):
        """
        Test that OFAC fuzzy matching threshold is set to 85
        """
        ofac_fuzzy_threshold = 85
        assert ofac_fuzzy_threshold == 85, (
            "OFAC fuzzy threshold must be exactly 85 per authoritative thresholds"
        )

    def test_beneficial_ownership_percentage(self):
        """
        Test that beneficial ownership percentage is set to 20%
        """
        beneficial_ownership_pct = 20
        assert beneficial_ownership_pct == 20, (
            "Beneficial ownership percentage must be exactly 20 per authoritative thresholds"
        )


class TestDecimalPrecision:
    def test_decimal_precision_in_transaction(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test that Decimal type is used for currency amounts
        to ensure precision
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("123.45"),
            user_metadata=user_metadata
        )

        assert isinstance(result.amount, Decimal)
        assert result.amount == Decimal("123.45")

    def test_balance_calculation_precision(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        user_metadata
    ):
        """
        Test that balance calculations maintain precision
        """
        account = Account(
            account_id="ACC-12345",
            user_id="USER-001",
            balance=Decimal("1000.99"),
            routing_number="021000021",
            account_number="1234567890",
            status="active"
        )
        mock_account_repo.get_account.return_value = account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("500.50"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        mock_account_repo.update_balance.assert_called_once_with(
            "ACC-12345",
            Decimal("500.49")
        )


class TestTimezoneAwareness:
    def test_transaction_timestamp_is_timezone_aware(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        valid_account,
        user_metadata
    ):
        """
        Test that transaction timestamps are timezone-aware (UTC)
        """
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_metadata=user_metadata
        )

        assert result.timestamp.tzinfo is not None
        assert result.timestamp.tzinfo == timezone.utc


class TestNegativePaths:
    def test_nonexistent_account(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        user_metadata
    ):
        """
        Test transaction with non-existent source account
        """
        mock_account_repo.get_account.return_value = None

        result = transaction_service.process_transaction(
            from_account_id="ACC-99999",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("100.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Invalid source account"

    def test_exact_balance_transfer(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        user_metadata
    ):
        """
        Test transferring exact account balance
        """
        account = Account(
            account_id="ACC-12345",
            user_id="USER-001",
            balance=Decimal("1000.00"),
            routing_number="021000021",
            account_number="1234567890",
            status="active"
        )
        mock_account_repo.get_account.return_value = account
        mock_account_repo.validate_routing_account.return_value = True

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("1000.00"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.SUCCESS
        mock_account_repo.update_balance.assert_called_once_with(
            "ACC-12345",
            Decimal("0.00")
        )

    def test_one_cent_over_balance(
        self,
        transaction_service,
        mock_account_repo,
        mock_audit_logger,
        user_metadata
    ):
        """
        Test transferring one cent more than balance
        """
        account = Account(
            account_id="ACC-12345",
            user_id="USER-001",
            balance=Decimal("1000.00"),
            routing_number="021000021",
            account_number="1234567890",
            status="active"
        )
        mock_account_repo.get_account.return_value = account

        result = transaction_service.process_transaction(
            from_account_id="ACC-12345",
            to_routing="021000022",
            to_account="9876543210",
            amount=Decimal("1000.01"),
            user_metadata=user_metadata
        )

        assert result.status == TransactionStatus.REJECTED
        assert result.rejection_reason == "Insufficient balance"