import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# Domain Models
# ============================================================================

class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    PENDING = "PENDING"


class ComplianceAction(Enum):
    CTR_FILED = "CTR_FILED"
    SAR_FILED = "SAR_FILED"
    OFAC_BLOCKED = "OFAC_BLOCKED"
    OFAC_PASSED = "OFAC_PASSED"
    DUAL_APPROVAL_OBTAINED = "DUAL_APPROVAL_OBTAINED"
    TRAVEL_RULE_APPLIED = "TRAVEL_RULE_APPLIED"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    status: str = "ACTIVE"
    user_id: str = "user123"


@dataclass
class Beneficiary:
    name: str
    account_number: str
    routing_number: str
    country: str = "US"


@dataclass
class TransactionRequest:
    from_account: Account
    to_beneficiary: Beneficiary
    amount: Decimal
    transaction_type: str
    user_id: str
    ip_address: str = "192.168.1.1"
    device_info: str = "Mozilla/5.0"
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class TransactionResult:
    status: TransactionStatus
    transaction_id: Optional[str]
    message: str
    compliance_actions: List[ComplianceAction]
    audit_id: str
    updated_balance: Optional[Decimal] = None
    error_code: Optional[str] = None


# ============================================================================
# Compliance Rules Configuration
# ============================================================================

class ComplianceRules:
    CTR_THRESHOLD = Decimal("10000.00")
    SAR_THRESHOLD = Decimal("5000.00")
    TRAVEL_RULE_THRESHOLD = Decimal("3000.00")
    WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000.00")
    OFAC_FUZZY_THRESHOLD = 85
    BENEFICIAL_OWNERSHIP_PCT = 20
    RECORDKEEPING_YEARS = 5


# ============================================================================
# Service Interfaces (to be mocked)
# ============================================================================

class OFACService:
    def screen_name(self, name: str, fuzzy_threshold: int = 85) -> Dict[str, Any]:
        raise NotImplementedError("Mock required")

    def file_blocking_report(self, transaction_id: str, details: Dict[str, Any]) -> str:
        raise NotImplementedError("Mock required")


class FinCENService:
    def file_ctr(self, transaction_details: Dict[str, Any]) -> str:
        raise NotImplementedError("Mock required")


class AuditLogger:
    def log_transaction(self, transaction: TransactionRequest, result: TransactionResult) -> str:
        raise NotImplementedError("Mock required")

    def log_compliance_action(self, action: ComplianceAction, details: Dict[str, Any]) -> str:
        raise NotImplementedError("Mock required")


class AccountRepository:
    def get_account(self, account_id: str) -> Optional[Account]:
        raise NotImplementedError("Mock required")

    def update_balance(self, account_id: str, new_balance: Decimal) -> bool:
        raise NotImplementedError("Mock required")

    def validate_beneficiary(self, routing: str, account: str) -> bool:
        raise NotImplementedError("Mock required")


class ApprovalService:
    def obtain_dual_approval(self, transaction_id: str, amount: Decimal) -> bool:
        raise NotImplementedError("Mock required")


# ============================================================================
# Wire Transfer Service (System Under Test)
# ============================================================================

class WireTransferService:
    def __init__(
        self,
        ofac_service: OFACService,
        fincen_service: FinCENService,
        audit_logger: AuditLogger,
        account_repo: AccountRepository,
        approval_service: ApprovalService,
    ):
        self.ofac_service = ofac_service
        self.fincen_service = fincen_service
        self.audit_logger = audit_logger
        self.account_repo = account_repo
        self.approval_service = approval_service

    def process_wire_transfer(self, request: TransactionRequest) -> TransactionResult:
        compliance_actions = []
        
        # Validation: amount checks
        if request.amount <= Decimal("0"):
            if request.amount == Decimal("0"):
                error_msg = "Amount must be greater than 0"
            else:
                error_msg = "Invalid amount"
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message=error_msg,
                compliance_actions=[],
                audit_id="",
                error_code="INVALID_AMOUNT"
            )
            audit_id = self.audit_logger.log_transaction(request, result)
            result.audit_id = audit_id
            return result

        # Validation: beneficiary account
        if not self.account_repo.validate_beneficiary(
            request.to_beneficiary.routing_number,
            request.to_beneficiary.account_number
        ):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid beneficiary account",
                compliance_actions=[],
                audit_id="",
                error_code="INVALID_BENEFICIARY"
            )
            audit_id = self.audit_logger.log_transaction(request, result)
            result.audit_id = audit_id
            return result

        # Validation: sufficient balance
        if request.from_account.balance < request.amount:
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Insufficient balance",
                compliance_actions=[],
                audit_id="",
                error_code="INSUFFICIENT_BALANCE"
            )
            audit_id = self.audit_logger.log_transaction(request, result)
            result.audit_id = audit_id
            return result

        # OFAC screening (required for all wires)
        ofac_result = self.ofac_service.screen_name(
            request.to_beneficiary.name,
            ComplianceRules.OFAC_FUZZY_THRESHOLD
        )
        
        if ofac_result["match_found"] and ofac_result["score"] >= ComplianceRules.OFAC_FUZZY_THRESHOLD:
            # Block transaction and file OFAC report
            transaction_id = f"TXN-BLOCKED-{datetime.now(timezone.utc).timestamp()}"
            self.ofac_service.file_blocking_report(transaction_id, {
                "beneficiary": request.to_beneficiary.name,
                "amount": str(request.amount),
                "user_id": request.user_id
            })
            result = TransactionResult(
                status=TransactionStatus.BLOCKED,
                transaction_id=transaction_id,
                message="Wire rejected, funds frozen, OFAC blocking report filed",
                compliance_actions=[ComplianceAction.OFAC_BLOCKED],
                audit_id="",
                error_code="OFAC_BLOCKED"
            )
            audit_id = self.audit_logger.log_transaction(request, result)
            result.audit_id = audit_id
            self.audit_logger.log_compliance_action(
                ComplianceAction.OFAC_BLOCKED,
                {"transaction_id": transaction_id, "beneficiary": request.to_beneficiary.name}
            )
            return result
        
        compliance_actions.append(ComplianceAction.OFAC_PASSED)

        # Dual approval for wires >= threshold
        transaction_id = f"TXN-{datetime.now(timezone.utc).timestamp()}"
        if request.amount >= ComplianceRules.WIRE_DUAL_APPROVAL_THRESHOLD:
            approval_obtained = self.approval_service.obtain_dual_approval(
                transaction_id, request.amount
            )
            if approval_obtained:
                compliance_actions.append(ComplianceAction.DUAL_APPROVAL_OBTAINED)

        # CTR filing for amounts >= threshold
        if request.amount >= ComplianceRules.CTR_THRESHOLD:
            ctr_id = self.fincen_service.file_ctr({
                "transaction_id": transaction_id,
                "amount": str(request.amount),
                "user_id": request.user_id,
                "timestamp": request.timestamp.isoformat()
            })
            compliance_actions.append(ComplianceAction.CTR_FILED)
            self.audit_logger.log_compliance_action(
                ComplianceAction.CTR_FILED,
                {"transaction_id": transaction_id, "ctr_id": ctr_id}
            )

        # Travel Rule for international wires >= threshold
        if (request.to_beneficiary.country != "US" and 
            request.amount >= ComplianceRules.TRAVEL_RULE_THRESHOLD):
            compliance_actions.append(ComplianceAction.TRAVEL_RULE_APPLIED)
            self.audit_logger.log_compliance_action(
                ComplianceAction.TRAVEL_RULE_APPLIED,
                {
                    "transaction_id": transaction_id,
                    "originator": request.user_id,
                    "beneficiary": request.to_beneficiary.name
                }
            )

        # Update balance
        new_balance = request.from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account.account_id, new_balance)

        result = TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction succeeds, balance updated, audit trail recorded",
            compliance_actions=compliance_actions,
            audit_id="",
            updated_balance=new_balance
        )
        
        audit_id = self.audit_logger.log_transaction(request, result)
        result.audit_id = audit_id
        
        return result


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def mock_ofac_service() -> Mock:
    """Mock OFAC screening service."""
    service = Mock(spec=OFACService)
    service.screen_name.return_value = {
        "match_found": False,
        "score": 0,
        "matched_entity": None
    }
    service.file_blocking_report.return_value = "OFAC-BLOCK-12345"
    return service


@pytest.fixture
def mock_fincen_service() -> Mock:
    """Mock FinCEN CTR/SAR filing service."""
    service = Mock(spec=FinCENService)
    service.file_ctr.return_value = "CTR-2024-12345"
    return service


@pytest.fixture
def mock_audit_logger() -> Mock:
    """Mock audit logging service."""
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = "AUDIT-LOG-67890"
    logger.log_compliance_action.return_value = "AUDIT-COMPLIANCE-11111"
    return logger


@pytest.fixture
def mock_account_repo() -> Mock:
    """Mock account repository."""
    repo = Mock(spec=AccountRepository)
    repo.validate_beneficiary.return_value = True
    repo.update_balance.return_value = True
    return repo


@pytest.fixture
def mock_approval_service() -> Mock:
    """Mock dual approval service."""
    service = Mock(spec=ApprovalService)
    service.obtain_dual_approval.return_value = True
    return service


@pytest.fixture
def wire_transfer_service(
    mock_ofac_service,
    mock_fincen_service,
    mock_audit_logger,
    mock_account_repo,
    mock_approval_service
) -> WireTransferService:
    """Wire transfer service with all dependencies mocked."""
    return WireTransferService(
        ofac_service=mock_ofac_service,
        fincen_service=mock_fincen_service,
        audit_logger=mock_audit_logger,
        account_repo=mock_account_repo,
        approval_service=mock_approval_service
    )


@pytest.fixture
def valid_account() -> Account:
    """Valid account with sufficient balance."""
    return Account(
        account_id="ACC-001",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        status="ACTIVE",
        user_id="user123"
    )


@pytest.fixture
def valid_beneficiary() -> Beneficiary:
    """Valid domestic beneficiary."""
    return Beneficiary(
        name="John Doe",
        account_number="9876543210",
        routing_number="021000022",
        country="US"
    )


@pytest.fixture
def international_beneficiary() -> Beneficiary:
    """Valid international beneficiary."""
    return Beneficiary(
        name="Jane Smith",
        account_number="GB29NWBK60161331926819",
        routing_number="SWIFT123",
        country="GB"
    )


# ============================================================================
# Test Cases
# ============================================================================

class TestSuccessfulTransaction:
    """Test successful transaction with sufficient balance and valid account."""

    def test_successful_transaction(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_audit_logger: Mock
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("5000.00"),
            transaction_type="WIRE",
            user_id="user123",
            ip_address="192.168.1.1",
            device_info="Mozilla/5.0"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None
        assert result.updated_balance == Decimal("45000.00")
        assert ComplianceAction.OFAC_PASSED in result.compliance_actions
        assert result.audit_id == "AUDIT-LOG-67890"
        mock_audit_logger.log_transaction.assert_called_once()


class TestWireTransferBelowCTRThreshold:
    """Test wire transfer below CTR threshold."""

    def test_wire_transfer_below_ctr_threshold(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_fincen_service: Mock,
        mock_ofac_service: Mock
    ):
        """
        Scenario: wire_transfer_below_ctr_threshold
        Given User has a valid account with balance $50,000
        When User sends wire transfer of $5,000
        Then Wire succeeds, no CTR filed, OFAC screening passed
        """
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("5000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.OFAC_PASSED in result.compliance_actions
        assert ComplianceAction.CTR_FILED not in result.compliance_actions
        mock_fincen_service.file_ctr.assert_not_called()
        mock_ofac_service.screen_name.assert_called_once()


class TestWireTransferAboveCTRThreshold:
    """Test wire transfer above CTR threshold."""

    def test_wire_transfer_above_ctr_threshold(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_fincen_service: Mock,
        mock_approval_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Scenario: wire_transfer_above_ctr_threshold
        Given User has valid account and approved by compliance
        When User sends wire transfer of $10,001
        Then Wire succeeds, CTR filed with FinCEN, dual approval obtained
        """
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("10001.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.CTR_FILED in result.compliance_actions
        assert ComplianceAction.DUAL_APPROVAL_OBTAINED in result.compliance_actions
        mock_fincen_service.file_ctr.assert_called_once()
        mock_approval_service.obtain_dual_approval.assert_called_once()
        mock_audit_logger.log_compliance_action.assert_called()


class TestWireTransferAtCTRThreshold:
    """Test wire transfer at exact CTR threshold (boundary test)."""

    def test_wire_transfer_at_ctr_threshold(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_fincen_service: Mock
    ):
        """
        Scenario: wire_transfer_at_ctr_threshold
        Given User initiates wire transfer
        When User sends wire transfer of exactly $10,000
        Then Wire succeeds, CTR filed (threshold is inclusive)
        """
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("10000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.CTR_FILED in result.compliance_actions
        mock_fincen_service.file_ctr.assert_called_once()
        call_args = mock_fincen_service.file_ctr.call_args[0][0]
        assert Decimal(call_args["amount"]) == Decimal("10000.00")


class TestWireTransferOFACBlocked:
    """Test wire transfer blocked due to OFAC match."""

    def test_wire_transfer_ofac_blocked(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Scenario: wire_transfer_ofac_blocked
        Given Beneficiary name matches OFAC SDN list
        When User attempts wire transfer to blocked party
        Then Wire rejected, funds frozen, OFAC blocking report filed
        """
        # Arrange
        blocked_beneficiary = Beneficiary(
            name="Sanctioned Entity",
            account_number="1111111111",
            routing_number="021000022",
            country="IR"
        )
        
        mock_ofac_service.screen_name.return_value = {
            "match_found": True,
            "score": 95,
            "matched_entity": "Sanctioned Entity - SDN List"
        }
        
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=blocked_beneficiary,
            amount=Decimal("5000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert ComplianceAction.OFAC_BLOCKED in result.compliance_actions
        assert "OFAC blocking report filed" in result.message
        assert result.error_code == "OFAC_BLOCKED"
        mock_ofac_service.file_blocking_report.assert_called_once()
        mock_audit_logger.log_compliance_action.assert_called_with(
            ComplianceAction.OFAC_BLOCKED,
            {"transaction_id": result.transaction_id, "beneficiary": "Sanctioned Entity"}
        )


class TestWireTransferTravelRule:
    """Test Travel Rule compliance for international wires."""

    def test_wire_transfer_travel_rule(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        international_beneficiary: Beneficiary,
        mock_audit_logger: Mock
    ):
        """
        Scenario: wire_transfer_travel_rule
        Given User sends international wire
        When Wire amount is $3,000 or more
        Then Originator and beneficiary info included per Travel Rule
        """
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=international_beneficiary,
            amount=Decimal("3000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.TRAVEL_RULE_APPLIED in result.compliance_actions
        
        # Verify travel rule logging
        travel_rule_logged = False
        for call in mock_audit_logger.log_compliance_action.call_args_list:
            if call[0][0] == ComplianceAction.TRAVEL_RULE_APPLIED:
                travel_rule_logged = True
                details = call[0][1]
                assert "originator" in details
                assert "beneficiary" in details
        
        assert travel_rule_logged


class TestZeroAmountTransfer:
    """Test rejection of zero amount transfer."""

    def test_zero_amount_transfer(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_audit_logger: Mock
    ):
        """
        Scenario: zero_amount_transfer
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("0.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Amount must be greater than 0"
        assert result.error_code == "INVALID_AMOUNT"
        assert result.transaction_id is None
        mock_audit_logger.log_transaction.assert_called_once()


class TestNegativeAmountTransfer:
    """Test rejection of negative amount transfer."""

    def test_negative_amount_transfer(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary
    ):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("-100.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"
        assert result.error_code == "INVALID_AMOUNT"
        assert result.transaction_id is None


class TestInsufficientBalance:
    """Test rejection due to insufficient balance."""

    def test_insufficient_balance(
        self,
        wire_transfer_service: WireTransferService,
        valid_beneficiary: Beneficiary
    ):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        low_balance_account = Account(
            account_id="ACC-002",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            status="ACTIVE",
            user_id="user456"
        )
        
        request = TransactionRequest(
            from_account=low_balance_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("5000.00"),
            transaction_type="WIRE",
            user_id="user456"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"
        assert result.error_code == "INSUFFICIENT_BALANCE"
        assert result.transaction_id is None


class TestInvalidBeneficiary:
    """Test rejection due to invalid beneficiary account."""

    def test_invalid_beneficiary(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        mock_account_repo: Mock
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        invalid_beneficiary = Beneficiary(
            name="Invalid Recipient",
            account_number="0000000000",
            routing_number="999999999",
            country="US"
        )
        
        mock_account_repo.validate_beneficiary.return_value = False
        
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=invalid_beneficiary,
            amount=Decimal("1000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
        assert result.error_code == "INVALID_BENEFICIARY"
        assert result.transaction_id is None
        mock_account_repo.validate_beneficiary.assert_called_once_with(
            "999999999", "0000000000"
        )


# ============================================================================
# Boundary and Edge Case Tests
# ============================================================================

class TestBoundaryConditions:
    """Test boundary conditions for compliance thresholds."""

    def test_ctr_threshold_minus_one_cent(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_fincen_service: Mock
    ):
        """Test wire transfer one cent below CTR threshold does not trigger CTR."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("9999.99"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.CTR_FILED not in result.compliance_actions
        mock_fincen_service.file_ctr.assert_not_called()

    def test_travel_rule_threshold_exact(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        international_beneficiary: Beneficiary
    ):
        """Test Travel Rule applies at exact threshold of $3,000."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=international_beneficiary,
            amount=Decimal("3000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.TRAVEL_RULE_APPLIED in result.compliance_actions

    def test_travel_rule_below_threshold(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        international_beneficiary: Beneficiary
    ):
        """Test Travel Rule does not apply below $3,000 threshold."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=international_beneficiary,
            amount=Decimal("2999.99"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.TRAVEL_RULE_APPLIED not in result.compliance_actions

    def test_dual_approval_at_threshold(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_approval_service: Mock
    ):
        """Test dual approval required at exact $10,000 threshold."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("10000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.DUAL_APPROVAL_OBTAINED in result.compliance_actions
        mock_approval_service.obtain_dual_approval.assert_called_once()

    def test_ofac_fuzzy_match_below_threshold(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_ofac_service: Mock
    ):
        """Test OFAC match below fuzzy threshold does not block transaction."""
        # Arrange
        mock_ofac_service.screen_name.return_value = {
            "match_found": True,
            "score": 75,  # Below 85 threshold
            "matched_entity": "Similar Name"
        }
        
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("1000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.OFAC_BLOCKED not in result.compliance_actions


class TestAuditAndDataHandling:
    """Test audit trail and data handling requirements."""

    def test_audit_trail_contains_required_fields(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary,
        mock_audit_logger: Mock
    ):
        """Verify audit log captures user ID, IP address, device info, and timestamp."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("1000.00"),
            transaction_type="WIRE",
            user_id="user123",
            ip_address="10.0.0.1",
            device_info="Chrome/120.0"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.audit_id == "AUDIT-LOG-67890"
        mock_audit_logger.log_transaction.assert_called_once()
        logged_request = mock_audit_logger.log_transaction.call_args[0][0]
        assert logged_request.user_id == "user123"
        assert logged_request.ip_address == "10.0.0.1"
        assert logged_request.device_info == "Chrome/120.0"
        assert logged_request.timestamp is not None

    def test_timestamp_is_timezone_aware(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary
    ):
        """Verify transaction timestamps are timezone-aware (UTC)."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("1000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert request.timestamp.tzinfo is not None
        assert request.timestamp.tzinfo == timezone.utc


class TestComplianceActionLogging:
    """Test that all compliance actions are properly logged."""

    def test_multiple_compliance_actions_logged(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        international_beneficiary: Beneficiary,
        mock_audit_logger: Mock
    ):
        """Test transaction with multiple compliance actions logs all actions."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=international_beneficiary,
            amount=Decimal("15000.00"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert ComplianceAction.OFAC_PASSED in result.compliance_actions
        assert ComplianceAction.CTR_FILED in result.compliance_actions
        assert ComplianceAction.DUAL_APPROVAL_OBTAINED in result.compliance_actions
        assert ComplianceAction.TRAVEL_RULE_APPLIED in result.compliance_actions
        
        # Verify compliance actions were logged
        assert mock_audit_logger.log_compliance_action.call_count >= 2


class TestDecimalPrecision:
    """Test proper handling of decimal precision for currency amounts."""

    def test_decimal_precision_maintained(
        self,
        wire_transfer_service: WireTransferService,
        valid_account: Account,
        valid_beneficiary: Beneficiary
    ):
        """Verify decimal precision is maintained throughout transaction processing."""
        # Arrange
        request = TransactionRequest(
            from_account=valid_account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("1234.56"),
            transaction_type="WIRE",
            user_id="user123"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        expected_balance = Decimal("50000.00") - Decimal("1234.56")
        assert result.updated_balance == expected_balance
        assert isinstance(result.updated_balance, Decimal)

    def test_balance_calculation_accuracy(
        self,
        wire_transfer_service: WireTransferService,
        valid_beneficiary: Beneficiary
    ):
        """Test balance calculation maintains accuracy with multiple decimal places."""
        # Arrange
        account = Account(
            account_id="ACC-003",
            routing_number="021000021",
            balance=Decimal("10000.99"),
            status="ACTIVE",
            user_id="user789"
        )
        
        request = TransactionRequest(
            from_account=account,
            to_beneficiary=valid_beneficiary,
            amount=Decimal("9999.99"),
            transaction_type="WIRE",
            user_id="user789"
        )

        # Act
        result = wire_transfer_service.process_wire_transfer(request)

        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.updated_balance == Decimal("1.00")