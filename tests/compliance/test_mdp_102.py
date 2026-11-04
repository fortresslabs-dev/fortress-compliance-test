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
    PENDING = "pending"


class ScreeningResult(Enum):
    CLEAR = "clear"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    user_id: str


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None


@dataclass
class AuditLogEntry:
    timestamp: datetime
    user_id: str
    ip_address: str
    device_info: str
    transaction_id: str
    action: str
    result: str
    details: Dict[str, Any]


@dataclass
class CapitalRatios:
    cet1_ratio: Decimal
    tier1_ratio: Decimal
    total_capital_ratio: Decimal
    leverage_ratio: Decimal
    risk_weighted_assets: Decimal
    average_total_assets: Decimal


class OFACService:
    def screen(self, name: str, account: str) -> ScreeningResult:
        raise NotImplementedError


class AuditLogger:
    def log(self, entry: AuditLogEntry) -> None:
        raise NotImplementedError


class TransactionService:
    def __init__(self, ofac_service: OFACService, audit_logger: AuditLogger):
        self.ofac_service = ofac_service
        self.audit_logger = audit_logger
        self.ctr_threshold = Decimal("10000")
        self.sar_threshold = Decimal("5000")
        self.travel_rule_threshold = Decimal("3000")
        self.wire_dual_approval_threshold = Decimal("10000")
        self.ofac_fuzzy_threshold = 85
        self.beneficial_ownership_pct = Decimal("20")

    def validate_amount(self, amount: Decimal) -> tuple[bool, Optional[str]]:
        if amount <= 0:
            if amount == 0:
                return False, "Amount must be greater than 0"
            else:
                return False, "Invalid amount"
        return True, None

    def validate_beneficiary(self, routing_number: str, account_number: str) -> tuple[bool, Optional[str]]:
        if not routing_number or not account_number:
            return False, "Invalid beneficiary account"
        if len(routing_number) != 9 or not routing_number.isdigit():
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
        device_info: str,
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        valid_amount, amount_error = self.validate_amount(amount)
        if not valid_amount:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_id,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=amount_error,
            )
            self._log_transaction(transaction, user_id, ip_address, device_info)
            return transaction

        valid_beneficiary, beneficiary_error = self.validate_beneficiary(to_routing, to_account)
        if not valid_beneficiary:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_id,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=beneficiary_error,
            )
            self._log_transaction(transaction, user_id, ip_address, device_info)
            return transaction

        has_balance, balance_error = self.check_balance(from_account, amount)
        if not has_balance:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_id,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason=balance_error,
            )
            self._log_transaction(transaction, user_id, ip_address, device_info)
            return transaction

        screening_result = self.ofac_service.screen(user_id, to_account)
        if screening_result == ScreeningResult.BLOCK:
            transaction = Transaction(
                transaction_id=transaction_id,
                from_account=from_account.account_id,
                to_account=to_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                rejection_reason="OFAC screening failed",
            )
            self._log_transaction(transaction, user_id, ip_address, device_info)
            return transaction

        from_account.balance -= amount
        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account.account_id,
            to_account=to_account,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
        )
        self._log_transaction(transaction, user_id, ip_address, device_info)
        return transaction

    def _log_transaction(
        self, transaction: Transaction, user_id: str, ip_address: str, device_info: str
    ) -> None:
        entry = AuditLogEntry(
            timestamp=transaction.timestamp,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
            transaction_id=transaction.transaction_id,
            action="transaction",
            result=transaction.status.value,
            details={
                "from_account": transaction.from_account,
                "to_account": transaction.to_account,
                "amount": str(transaction.amount),
                "rejection_reason": transaction.rejection_reason,
            },
        )
        self.audit_logger.log(entry)


class CapitalRatioValidator:
    def __init__(self):
        self.min_cet1_ratio = Decimal("4.5")
        self.min_tier1_ratio = Decimal("6.0")
        self.min_total_capital_ratio = Decimal("8.0")
        self.min_leverage_ratio = Decimal("4.0")

    def validate_capital_ratios(self, ratios: CapitalRatios) -> tuple[bool, list[str]]:
        violations = []

        if ratios.cet1_ratio < self.min_cet1_ratio:
            violations.append(
                f"CET1 ratio {ratios.cet1_ratio}% below minimum 4.5% required by 12 C.F.R. § 324.10"
            )

        if ratios.tier1_ratio < self.min_tier1_ratio:
            violations.append(
                f"Tier 1 capital ratio {ratios.tier1_ratio}% below minimum 6% required by 12 C.F.R. § 324.10"
            )

        if ratios.total_capital_ratio < self.min_total_capital_ratio:
            violations.append(
                f"Total capital ratio {ratios.total_capital_ratio}% below minimum 8% required by 12 C.F.R. § 324.10"
            )

        if ratios.leverage_ratio < self.min_leverage_ratio:
            violations.append(
                f"Leverage ratio {ratios.leverage_ratio}% below minimum 4% required by 12 C.F.R. § 324.10"
            )

        return len(violations) == 0, violations


@pytest.fixture
def mock_ofac_service():
    service = Mock(spec=OFACService)
    service.screen.return_value = ScreeningResult.CLEAR
    return service


@pytest.fixture
def mock_audit_logger():
    logger = Mock(spec=AuditLogger)
    return logger


@pytest.fixture
def transaction_service(mock_ofac_service, mock_audit_logger):
    return TransactionService(mock_ofac_service, mock_audit_logger)


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER001",
    )


@pytest.fixture
def low_balance_account():
    return Account(
        account_id="ACC123456",
        routing_number="021000021",
        balance=Decimal("1000.00"),
        user_id="USER001",
    )


@pytest.fixture
def capital_ratio_validator():
    return CapitalRatioValidator()


class TestSuccessfulTransaction:
    """Test successful transaction scenario from MDP-102."""

    def test_successful_transaction_with_sufficient_balance_and_valid_account(
        self, transaction_service, valid_account, mock_audit_logger
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        initial_balance = valid_account.balance
        transfer_amount = Decimal("500.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == transfer_amount
        assert valid_account.balance == initial_balance - transfer_amount
        assert transaction.rejection_reason is None
        mock_audit_logger.log.assert_called_once()

        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.user_id == user_id
        assert audit_entry.ip_address == ip_address
        assert audit_entry.device_info == device_info
        assert audit_entry.transaction_id == transaction.transaction_id
        assert audit_entry.result == "success"


class TestZeroAmountTransfer:
    """Test zero amount transfer scenario from MDP-102."""

    def test_zero_amount_transfer_rejected(self, transaction_service, valid_account, mock_audit_logger):
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        transfer_amount = Decimal("0.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Amount must be greater than 0"
        mock_audit_logger.log.assert_called_once()


class TestNegativeAmountTransfer:
    """Test negative amount transfer scenario from MDP-102."""

    def test_negative_amount_transfer_rejected(
        self, transaction_service, valid_account, mock_audit_logger
    ):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        transfer_amount = Decimal("-100.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid amount"
        mock_audit_logger.log.assert_called_once()


class TestInsufficientBalance:
    """Test insufficient balance scenario from MDP-102."""

    def test_insufficient_balance_transfer_rejected(
        self, transaction_service, low_balance_account, mock_audit_logger
    ):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        assert low_balance_account.balance == Decimal("1000.00")
        transfer_amount = Decimal("5000.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=low_balance_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Insufficient balance"
        mock_audit_logger.log.assert_called_once()


class TestInvalidBeneficiary:
    """Test invalid beneficiary scenario from MDP-102."""

    def test_invalid_routing_number_rejected(
        self, transaction_service, valid_account, mock_audit_logger
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        transfer_amount = Decimal("500.00")
        invalid_routing = "12345"  # Invalid: not 9 digits
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=invalid_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"
        mock_audit_logger.log.assert_called_once()

    def test_empty_account_number_rejected(
        self, transaction_service, valid_account, mock_audit_logger
    ):
        """Test rejection when beneficiary account number is empty."""
        # Arrange
        transfer_amount = Decimal("500.00")
        to_routing = "021000022"
        invalid_account = ""
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=invalid_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "Invalid beneficiary account"


class TestFDICCapitalRequirements:
    """
    Test FDIC capital ratio requirements per 12 C.F.R. § 324.10.
    MUST-TEST OBLIGATIONS: [FDIC-CAPITAL-001::OBL::001]
    """

    def test_cet1_ratio_minimum_requirement_met(self, capital_ratio_validator):
        """
        Test that CET1 ratio of 4.5% minimum is enforced per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Common Equity Tier 1 requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert is_valid, f"CET1 ratio of 4.5% should meet minimum requirement per 12 C.F.R. § 324.10"
        assert len(violations) == 0

    def test_cet1_ratio_below_minimum_rejected(self, capital_ratio_validator):
        """
        Test that CET1 ratio below 4.5% is rejected per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Common Equity Tier 1 requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.4"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert not is_valid, f"CET1 ratio below 4.5% must be rejected per 12 C.F.R. § 324.10"
        assert any("CET1" in v and "12 C.F.R. § 324.10" in v for v in violations), (
            f"Violation must reference CET1 and 12 C.F.R. § 324.10"
        )

    def test_tier1_capital_ratio_minimum_requirement_met(self, capital_ratio_validator):
        """
        Test that Tier 1 capital ratio of 6% minimum is enforced per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Tier 1 capital requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert is_valid, f"Tier 1 ratio of 6% should meet minimum requirement per 12 C.F.R. § 324.10"
        assert len(violations) == 0

    def test_tier1_capital_ratio_below_minimum_rejected(self, capital_ratio_validator):
        """
        Test that Tier 1 capital ratio below 6% is rejected per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Tier 1 capital requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("5.9"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert not is_valid, f"Tier 1 ratio below 6% must be rejected per 12 C.F.R. § 324.10"
        assert any("Tier 1" in v and "12 C.F.R. § 324.10" in v for v in violations), (
            f"Violation must reference Tier 1 and 12 C.F.R. § 324.10"
        )

    def test_total_capital_ratio_minimum_requirement_met(self, capital_ratio_validator):
        """
        Test that Total capital ratio of 8% minimum is enforced per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Total capital requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert is_valid, f"Total capital ratio of 8% should meet minimum requirement per 12 C.F.R. § 324.10"
        assert len(violations) == 0

    def test_total_capital_ratio_below_minimum_rejected(self, capital_ratio_validator):
        """
        Test that Total capital ratio below 8% is rejected per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Total capital requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("7.9"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert not is_valid, f"Total capital ratio below 8% must be rejected per 12 C.F.R. § 324.10"
        assert any("Total capital" in v and "12 C.F.R. § 324.10" in v for v in violations), (
            f"Violation must reference Total capital and 12 C.F.R. § 324.10"
        )

    def test_leverage_ratio_minimum_requirement_met(self, capital_ratio_validator):
        """
        Test that Leverage ratio of 4% minimum is enforced per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Leverage ratio requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert is_valid, f"Leverage ratio of 4% should meet minimum requirement per 12 C.F.R. § 324.10"
        assert len(violations) == 0

    def test_leverage_ratio_below_minimum_rejected(self, capital_ratio_validator):
        """
        Test that Leverage ratio below 4% is rejected per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - Leverage ratio requirement.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("3.9"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert not is_valid, f"Leverage ratio below 4% must be rejected per 12 C.F.R. § 324.10"
        assert any("Leverage" in v and "12 C.F.R. § 324.10" in v for v in violations), (
            f"Violation must reference Leverage and 12 C.F.R. § 324.10"
        )

    def test_all_capital_ratios_minimum_requirements_enforced(self, capital_ratio_validator):
        """
        Test that all four capital ratios are enforced simultaneously per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - All capital requirements must be met.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.5"),
            tier1_ratio=Decimal("6.0"),
            total_capital_ratio=Decimal("8.0"),
            leverage_ratio=Decimal("4.0"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert is_valid, (
            f"All capital ratios meeting minimums should pass validation per 12 C.F.R. § 324.10"
        )
        assert len(violations) == 0, (
            f"No violations expected when all ratios meet requirements per 12 C.F.R. § 324.10"
        )

    def test_multiple_capital_ratio_violations_reported(self, capital_ratio_validator):
        """
        Test that multiple capital ratio violations are all reported per 12 C.F.R. § 324.10.
        FDIC-CAPITAL-001::OBL::001 - All violations must be identified.
        """
        # Arrange
        ratios = CapitalRatios(
            cet1_ratio=Decimal("4.0"),
            tier1_ratio=Decimal("5.5"),
            total_capital_ratio=Decimal("7.5"),
            leverage_ratio=Decimal("3.5"),
            risk_weighted_assets=Decimal("1000000"),
            average_total_assets=Decimal("1200000"),
        )

        # Act
        is_valid, violations = capital_ratio_validator.validate_capital_ratios(ratios)

        # Assert
        assert not is_valid, f"Multiple violations should fail validation per 12 C.F.R. § 324.10"
        assert len(violations) == 4, (
            f"All four ratio violations should be reported per 12 C.F.R. § 324.10"
        )
        assert all("12 C.F.R. § 324.10" in v for v in violations), (
            f"All violations must cite 12 C.F.R. § 324.10"
        )


class TestOFACScreening:
    """Test OFAC/SDN screening compliance."""

    def test_ofac_blocked_transaction_rejected(
        self, transaction_service, valid_account, mock_ofac_service, mock_audit_logger
    ):
        """Test that OFAC blocked transactions are rejected."""
        # Arrange
        mock_ofac_service.screen.return_value = ScreeningResult.BLOCK
        transfer_amount = Decimal("500.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.REJECTED
        assert transaction.rejection_reason == "OFAC screening failed"
        mock_ofac_service.screen.assert_called_once_with(user_id, to_account)
        mock_audit_logger.log.assert_called_once()


class TestBSAThresholds:
    """Test BSA/AML threshold compliance using authoritative thresholds."""

    def test_ctr_threshold_value_is_10000(self, transaction_service):
        """Test that CTR threshold is exactly $10,000."""
        # Assert
        assert transaction_service.ctr_threshold == Decimal("10000"), (
            "CTR threshold must be exactly $10,000"
        )

    def test_sar_threshold_value_is_5000(self, transaction_service):
        """Test that SAR threshold is exactly $5,000."""
        # Assert
        assert transaction_service.sar_threshold == Decimal("5000"), (
            "SAR threshold must be exactly $5,000"
        )

    def test_travel_rule_threshold_value_is_3000(self, transaction_service):
        """Test that Travel Rule threshold is exactly $3,000."""
        # Assert
        assert transaction_service.travel_rule_threshold == Decimal("3000"), (
            "Travel Rule threshold must be exactly $3,000"
        )

    def test_wire_dual_approval_threshold_value_is_10000(self, transaction_service):
        """Test that wire dual approval threshold is exactly $10,000."""
        # Assert
        assert transaction_service.wire_dual_approval_threshold == Decimal("10000"), (
            "Wire dual approval threshold must be exactly $10,000"
        )

    def test_ofac_fuzzy_threshold_value_is_85(self, transaction_service):
        """Test that OFAC fuzzy matching threshold is exactly 85."""
        # Assert
        assert transaction_service.ofac_fuzzy_threshold == 85, (
            "OFAC fuzzy threshold must be exactly 85"
        )

    def test_beneficial_ownership_percentage_is_20(self, transaction_service):
        """Test that beneficial ownership percentage is exactly 20%."""
        # Assert
        assert transaction_service.beneficial_ownership_pct == Decimal("20"), (
            "Beneficial ownership percentage must be exactly 20%"
        )


class TestAuditTrailCompliance:
    """Test audit trail and record retention compliance."""

    def test_audit_log_contains_required_fields(
        self, transaction_service, valid_account, mock_audit_logger
    ):
        """Test that audit log contains all required fields per compliance requirements."""
        # Arrange
        transfer_amount = Decimal("500.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        mock_audit_logger.log.assert_called_once()
        audit_entry = mock_audit_logger.log.call_args[0][0]

        assert audit_entry.timestamp is not None
        assert audit_entry.timestamp.tzinfo is not None, "Timestamp must be timezone-aware"
        assert audit_entry.user_id == user_id
        assert audit_entry.ip_address == ip_address
        assert audit_entry.device_info == device_info
        assert audit_entry.transaction_id is not None
        assert audit_entry.action == "transaction"
        assert audit_entry.result in ["success", "rejected"]

    def test_rejected_transaction_logged_with_reason(
        self, transaction_service, valid_account, mock_audit_logger
    ):
        """Test that rejected transactions are logged with rejection reason."""
        # Arrange
        transfer_amount = Decimal("0.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.result == "rejected"
        assert audit_entry.details["rejection_reason"] == "Amount must be greater than 0"


class TestBoundaryConditions:
    """Test boundary conditions for transaction amounts and thresholds."""

    def test_transaction_at_ctr_threshold(self, transaction_service, valid_account):
        """Test transaction exactly at CTR threshold of $10,000."""
        # Arrange
        transfer_amount = Decimal("10000.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == Decimal("10000.00")

    def test_transaction_at_sar_threshold(self, transaction_service, valid_account):
        """Test transaction exactly at SAR threshold of $5,000."""
        # Arrange
        transfer_amount = Decimal("5000.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == Decimal("5000.00")

    def test_transaction_at_travel_rule_threshold(self, transaction_service, valid_account):
        """Test transaction exactly at Travel Rule threshold of $3,000."""
        # Arrange
        transfer_amount = Decimal("3000.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == Decimal("3000.00")

    def test_minimum_valid_transaction_amount(self, transaction_service, valid_account):
        """Test minimum valid transaction amount (0.01)."""
        # Arrange
        transfer_amount = Decimal("0.01")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.amount == Decimal("0.01")


class TestDataHandlingCompliance:
    """Test data handling and security compliance requirements."""

    def test_transaction_uses_decimal_for_currency(self, transaction_service, valid_account):
        """Test that currency amounts use Decimal type for precision."""
        # Arrange
        transfer_amount = Decimal("123.45")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert isinstance(transaction.amount, Decimal)
        assert isinstance(valid_account.balance, Decimal)

    def test_transaction_timestamp_is_timezone_aware(
        self, transaction_service, valid_account
    ):
        """Test that transaction timestamps are timezone-aware."""
        # Arrange
        transfer_amount = Decimal("100.00")
        to_routing = "021000022"
        to_account = "ACC789012"
        user_id = "USER001"
        ip_address = "192.168.1.100"
        device_info = "Mozilla/5.0"

        # Act
        transaction = transaction_service.execute_transaction(
            from_account=valid_account,
            to_routing=to_routing,
            to_account=to_account,
            amount=transfer_amount,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
        )

        # Assert
        assert transaction.timestamp.tzinfo is not None, (
            "Transaction timestamp must be timezone-aware"
        )
        assert transaction.timestamp.tzinfo == timezone.utc, (
            "Transaction timestamp should use UTC"
        )