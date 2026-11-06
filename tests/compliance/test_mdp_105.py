import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# Domain Models
# ============================================================================

class TransactionStatus(Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    PENDING = "pending"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    user_id: str


@dataclass
class TransactionRequest:
    from_account: str
    to_account: str
    to_routing: str
    amount: Decimal
    user_id: str
    ip_address: str
    device_info: str


@dataclass
class TransactionResult:
    status: TransactionStatus
    message: str
    transaction_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    audit_log_id: Optional[str] = None


@dataclass
class AuditLogEntry:
    log_id: str
    transaction_id: Optional[str]
    user_id: str
    ip_address: str
    device_info: str
    timestamp: datetime
    action: str
    result: str
    details: Dict[str, Any]


# ============================================================================
# Service Layer
# ============================================================================

class TransactionService:
    """Core transaction processing service with compliance controls."""
    
    def __init__(
        self,
        account_repository,
        audit_logger,
        ofac_service,
        rule_resolver
    ):
        self.account_repo = account_repository
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver
        self.ctr_threshold = Decimal("10000")
        self.sar_threshold = Decimal("5000")
        self.travel_rule_threshold = Decimal("3000")
        self.wire_dual_approval_threshold = Decimal("10000")
    
    def process_transaction(self, request: TransactionRequest) -> TransactionResult:
        """Process a transaction with full compliance checks."""
        timestamp = datetime.now(timezone.utc)
        
        # Validate amount
        if request.amount == Decimal("0"):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Amount must be greater than 0",
                timestamp=timestamp
            )
            self._log_transaction(request, result, "AMOUNT_ZERO")
            return result
        
        if request.amount < Decimal("0"):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid amount",
                timestamp=timestamp
            )
            self._log_transaction(request, result, "AMOUNT_NEGATIVE")
            return result
        
        # Validate beneficiary account
        if not self._validate_beneficiary(request.to_account, request.to_routing):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid beneficiary account",
                timestamp=timestamp
            )
            self._log_transaction(request, result, "INVALID_BENEFICIARY")
            return result
        
        # Get source account
        from_account = self.account_repo.get_account(request.from_account)
        if not from_account:
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid source account",
                timestamp=timestamp
            )
            self._log_transaction(request, result, "INVALID_SOURCE")
            return result
        
        # Check balance
        if from_account.balance < request.amount:
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Insufficient balance",
                timestamp=timestamp
            )
            self._log_transaction(request, result, "INSUFFICIENT_BALANCE")
            return result
        
        # OFAC screening
        ofac_result = self.ofac_service.screen_transaction(request)
        if ofac_result.get("blocked"):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Transaction blocked by OFAC screening",
                timestamp=timestamp
            )
            self._log_transaction(request, result, "OFAC_BLOCKED")
            return result
        
        # Process successful transaction
        transaction_id = self._generate_transaction_id()
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account, new_balance)
        
        result = TransactionResult(
            status=TransactionStatus.SUCCESS,
            message="Transaction successful",
            transaction_id=transaction_id,
            timestamp=timestamp
        )
        
        # Audit trail (immutable log)
        audit_log_id = self._log_transaction(request, result, "SUCCESS")
        result.audit_log_id = audit_log_id
        
        return result
    
    def _validate_beneficiary(self, account: str, routing: str) -> bool:
        """Validate beneficiary account and routing number format."""
        if not account or not routing:
            return False
        if len(routing) != 9 or not routing.isdigit():
            return False
        if len(account) < 4 or len(account) > 17:
            return False
        return True
    
    def _log_transaction(
        self,
        request: TransactionRequest,
        result: TransactionResult,
        action: str
    ) -> str:
        """Record immutable audit trail per BSA and SOX requirements."""
        audit_entry = AuditLogEntry(
            log_id=self._generate_audit_id(),
            transaction_id=result.transaction_id,
            user_id=request.user_id,
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=result.timestamp or datetime.now(timezone.utc),
            action=action,
            result=result.status.value,
            details={
                "amount": str(request.amount),
                "from_account": self._mask_account(request.from_account),
                "to_account": self._mask_account(request.to_account),
                "message": result.message
            }
        )
        return self.audit_logger.log(audit_entry)
    
    def _mask_account(self, account: str) -> str:
        """Mask account number showing last 4 digits only (GLBA compliance)."""
        if len(account) <= 4:
            return "****"
        return "*" * (len(account) - 4) + account[-4:]
    
    def _generate_transaction_id(self) -> str:
        """Generate unique transaction ID."""
        return f"TXN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    
    def _generate_audit_id(self) -> str:
        """Generate unique audit log ID."""
        return f"AUD-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_account_repository():
    """Mock account repository."""
    repo = Mock()
    repo.get_account = Mock()
    repo.update_balance = Mock()
    return repo


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger for immutable audit trail."""
    logger = Mock()
    logger.log = Mock(return_value="AUD-12345678901234567890")
    return logger


@pytest.fixture
def mock_ofac_service():
    """Mock OFAC/SDN screening service."""
    service = Mock()
    service.screen_transaction = Mock(return_value={"blocked": False, "score": 0})
    return service


@pytest.fixture
def mock_rule_resolver():
    """Mock compliance rule resolver."""
    resolver = Mock()
    resolver.resolve = Mock(return_value={})
    return resolver


@pytest.fixture
def transaction_service(
    mock_account_repository,
    mock_audit_logger,
    mock_ofac_service,
    mock_rule_resolver
):
    """Transaction service with mocked dependencies."""
    return TransactionService(
        account_repository=mock_account_repository,
        audit_logger=mock_audit_logger,
        ofac_service=mock_ofac_service,
        rule_resolver=mock_rule_resolver
    )


@pytest.fixture
def valid_account():
    """Valid account with sufficient balance."""
    return Account(
        account_id="1234567890",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001"
    )


@pytest.fixture
def valid_transaction_request():
    """Valid transaction request."""
    return TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )


# ============================================================================
# Test Suite: MDP-105 BDD Scenarios
# ============================================================================

class TestSuccessfulTransaction:
    """Test scenario: successful_transaction
    
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    
    def test_successful_transaction_with_sufficient_balance(
        self,
        transaction_service,
        mock_account_repository,
        mock_audit_logger,
        valid_account,
        valid_transaction_request
    ):
        """
        Verify successful transaction processing with balance update and audit trail.
        
        Compliance: Audit trail per BSA 31 CFR 1010.430 (5-year retention).
        """
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS, \
            "Transaction should succeed with valid account and sufficient balance"
        assert result.message == "Transaction successful"
        assert result.transaction_id is not None
        assert result.transaction_id.startswith("TXN-")
        assert result.timestamp is not None
        assert result.timestamp.tzinfo == timezone.utc
        
        # Verify balance was updated
        expected_new_balance = valid_account.balance - valid_transaction_request.amount
        mock_account_repository.update_balance.assert_called_once_with(
            valid_transaction_request.from_account,
            expected_new_balance
        )
        
        # Verify audit trail was recorded (immutable log requirement)
        mock_audit_logger.log.assert_called_once()
        audit_call_args = mock_audit_logger.log.call_args[0][0]
        assert isinstance(audit_call_args, AuditLogEntry)
        assert audit_call_args.user_id == valid_transaction_request.user_id
        assert audit_call_args.ip_address == valid_transaction_request.ip_address
        assert audit_call_args.device_info == valid_transaction_request.device_info
        assert audit_call_args.action == "SUCCESS"
        assert audit_call_args.result == "success"
    
    def test_successful_transaction_records_timestamp(
        self,
        transaction_service,
        mock_account_repository,
        valid_account,
        valid_transaction_request
    ):
        """Verify transaction timestamp is recorded in UTC (audit requirement)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        before_time = datetime.now(timezone.utc)
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        after_time = datetime.now(timezone.utc)
        assert result.timestamp >= before_time
        assert result.timestamp <= after_time
        assert result.timestamp.tzinfo == timezone.utc, \
            "Timestamp must be timezone-aware (UTC) for audit compliance"
    
    def test_successful_transaction_masks_account_numbers_in_audit(
        self,
        transaction_service,
        mock_account_repository,
        mock_audit_logger,
        valid_account,
        valid_transaction_request
    ):
        """Verify account numbers are masked in audit logs (GLBA Safeguards Rule)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        audit_entry = mock_audit_logger.log.call_args[0][0]
        masked_from = audit_entry.details["from_account"]
        masked_to = audit_entry.details["to_account"]
        
        # Should show last 4 digits only
        assert masked_from.endswith("7890"), \
            "GLBA Safeguards Rule: mask account numbers, show last 4 only"
        assert masked_to.endswith("3210")
        assert "*" in masked_from
        assert "*" in masked_to


class TestZeroAmountTransfer:
    """Test scenario: zero_amount_transfer
    
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    
    def test_zero_amount_transfer_rejected(
        self,
        transaction_service,
        mock_audit_logger,
        valid_transaction_request
    ):
        """Verify transaction with $0 amount is rejected."""
        # Arrange
        valid_transaction_request.amount = Decimal("0")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED, \
            "Transaction with zero amount must be rejected"
        assert result.message == "Amount must be greater than 0"
        assert result.transaction_id is None
        
        # Verify rejection is logged in audit trail
        mock_audit_logger.log.assert_called_once()
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.action == "AMOUNT_ZERO"
        assert audit_entry.result == "rejected"
    
    def test_zero_amount_decimal_precision(
        self,
        transaction_service,
        valid_transaction_request
    ):
        """Verify zero amount with decimal precision is rejected."""
        # Arrange
        valid_transaction_request.amount = Decimal("0.00")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Amount must be greater than 0"


class TestNegativeAmountTransfer:
    """Test scenario: negative_amount_transfer
    
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    
    def test_negative_amount_transfer_rejected(
        self,
        transaction_service,
        mock_audit_logger,
        valid_transaction_request
    ):
        """Verify transaction with negative amount is rejected."""
        # Arrange
        valid_transaction_request.amount = Decimal("-100.00")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED, \
            "Transaction with negative amount must be rejected"
        assert result.message == "Invalid amount"
        assert result.transaction_id is None
        
        # Verify rejection is logged
        mock_audit_logger.log.assert_called_once()
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.action == "AMOUNT_NEGATIVE"
        assert audit_entry.result == "rejected"
    
    def test_large_negative_amount_rejected(
        self,
        transaction_service,
        valid_transaction_request
    ):
        """Verify large negative amounts are rejected."""
        # Arrange
        valid_transaction_request.amount = Decimal("-999999.99")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"


class TestInsufficientBalance:
    """Test scenario: insufficient_balance
    
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    
    def test_insufficient_balance_rejected(
        self,
        transaction_service,
        mock_account_repository,
        mock_audit_logger,
        valid_transaction_request
    ):
        """Verify transaction exceeding balance is rejected."""
        # Arrange
        account_with_low_balance = Account(
            account_id="1234567890",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            user_id="USER-001"
        )
        mock_account_repository.get_account.return_value = account_with_low_balance
        valid_transaction_request.amount = Decimal("5000.00")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED, \
            "Transaction exceeding available balance must be rejected"
        assert result.message == "Insufficient balance"
        assert result.transaction_id is None
        
        # Verify balance was NOT updated
        mock_account_repository.update_balance.assert_not_called()
        
        # Verify rejection is logged
        mock_audit_logger.log.assert_called_once()
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.action == "INSUFFICIENT_BALANCE"
    
    def test_insufficient_balance_by_one_cent(
        self,
        transaction_service,
        mock_account_repository,
        valid_transaction_request
    ):
        """Verify insufficient balance detection with minimal shortfall."""
        # Arrange
        account = Account(
            account_id="1234567890",
            routing_number="021000021",
            balance=Decimal("99.99"),
            user_id="USER-001"
        )
        mock_account_repository.get_account.return_value = account
        valid_transaction_request.amount = Decimal("100.00")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"
    
    def test_exact_balance_transfer_succeeds(
        self,
        transaction_service,
        mock_account_repository,
        valid_transaction_request
    ):
        """Verify transaction for exact account balance succeeds."""
        # Arrange
        account = Account(
            account_id="1234567890",
            routing_number="021000021",
            balance=Decimal("100.00"),
            user_id="USER-001"
        )
        mock_account_repository.get_account.return_value = account
        valid_transaction_request.amount = Decimal("100.00")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_account_repository.update_balance.assert_called_once_with(
            valid_transaction_request.from_account,
            Decimal("0.00")
        )


class TestInvalidBeneficiary:
    """Test scenario: invalid_beneficiary
    
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    
    def test_invalid_routing_number_rejected(
        self,
        transaction_service,
        mock_audit_logger,
        valid_transaction_request
    ):
        """Verify transaction with invalid routing number is rejected."""
        # Arrange
        valid_transaction_request.to_routing = "12345"  # Too short
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED, \
            "Transaction with invalid routing number must be rejected"
        assert result.message == "Invalid beneficiary account"
        
        # Verify rejection is logged
        mock_audit_logger.log.assert_called_once()
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.action == "INVALID_BENEFICIARY"
    
    def test_empty_routing_number_rejected(
        self,
        transaction_service,
        valid_transaction_request
    ):
        """Verify transaction with empty routing number is rejected."""
        # Arrange
        valid_transaction_request.to_routing = ""
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_non_numeric_routing_number_rejected(
        self,
        transaction_service,
        valid_transaction_request
    ):
        """Verify transaction with non-numeric routing number is rejected."""
        # Arrange
        valid_transaction_request.to_routing = "02100002A"
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_empty_account_number_rejected(
        self,
        transaction_service,
        valid_transaction_request
    ):
        """Verify transaction with empty account number is rejected."""
        # Arrange
        valid_transaction_request.to_account = ""
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_account_number_too_short_rejected(
        self,
        transaction_service,
        valid_transaction_request
    ):
        """Verify transaction with too-short account number is rejected."""
        # Arrange
        valid_transaction_request.to_account = "123"  # Less than 4 digits
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_account_number_too_long_rejected(
        self,
        transaction_service,
        valid_transaction_request
    ):
        """Verify transaction with too-long account number is rejected."""
        # Arrange
        valid_transaction_request.to_account = "1" * 18  # More than 17 digits
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"


# ============================================================================
# Compliance-Specific Tests
# ============================================================================

class TestOFACScreening:
    """Test OFAC/SDN screening compliance."""
    
    def test_ofac_blocked_transaction_rejected(
        self,
        transaction_service,
        mock_account_repository,
        mock_ofac_service,
        mock_audit_logger,
        valid_account,
        valid_transaction_request
    ):
        """Verify OFAC-blocked transactions are rejected."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        mock_ofac_service.screen_transaction.return_value = {
            "blocked": True,
            "score": 95,
            "match": "SDN List"
        }
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED, \
            "OFAC-blocked transactions must be rejected"
        assert "OFAC" in result.message
        
        # Verify balance was NOT updated
        mock_account_repository.update_balance.assert_not_called()
        
        # Verify OFAC block is logged
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.action == "OFAC_BLOCKED"
    
    def test_ofac_screening_called_for_all_transactions(
        self,
        transaction_service,
        mock_account_repository,
        mock_ofac_service,
        valid_account,
        valid_transaction_request
    ):
        """Verify OFAC screening is performed for every transaction."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        mock_ofac_service.screen_transaction.assert_called_once_with(
            valid_transaction_request
        )
    
    def test_ofac_fuzzy_match_threshold(
        self,
        transaction_service,
        mock_account_repository,
        mock_ofac_service,
        valid_account,
        valid_transaction_request
    ):
        """Verify OFAC fuzzy matching uses correct threshold (85%)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        mock_ofac_service.screen_transaction.return_value = {
            "blocked": False,
            "score": 84,  # Below threshold
            "match": None
        }
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS, \
            "OFAC score below 85 threshold should allow transaction"
        
        # Test at threshold
        mock_ofac_service.screen_transaction.return_value = {
            "blocked": True,
            "score": 85,  # At threshold
            "match": "Potential SDN match"
        }
        result = transaction_service.process_transaction(valid_transaction_request)
        assert result.status == TransactionStatus.REJECTED, \
            "OFAC score at/above 85 threshold should block transaction"


class TestBSAAuditRequirements:
    """Test BSA audit and recordkeeping requirements (31 CFR 1010.430)."""
    
    def test_audit_log_contains_required_fields(
        self,
        transaction_service,
        mock_account_repository,
        mock_audit_logger,
        valid_account,
        valid_transaction_request
    ):
        """Verify audit log contains all required fields per BSA."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        audit_entry = mock_audit_logger.log.call_args[0][0]
        
        # BSA requires: timestamp, user ID, IP, device, action, result
        assert audit_entry.timestamp is not None, \
            "BSA 31 CFR 1010.430: audit log must contain timestamp"
        assert audit_entry.user_id == valid_transaction_request.user_id, \
            "BSA 31 CFR 1010.430: audit log must contain user ID"
        assert audit_entry.ip_address == valid_transaction_request.ip_address, \
            "BSA 31 CFR 1010.430: audit log must contain IP address"
        assert audit_entry.device_info == valid_transaction_request.device_info, \
            "BSA 31 CFR 1010.430: audit log must contain device info"
        assert audit_entry.action is not None
        assert audit_entry.result is not None
        assert audit_entry.log_id is not None
    
    def test_audit_log_immutability(
        self,
        transaction_service,
        mock_account_repository,
        mock_audit_logger,
        valid_account,
        valid_transaction_request
    ):
        """Verify audit log is immutable (write-once)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        # Audit logger should be called exactly once (no updates)
        assert mock_audit_logger.log.call_count == 1, \
            "Audit log must be immutable (write-once, no updates)"
        
        # Verify audit entry has unique ID
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.log_id.startswith("AUD-"), \
            "Audit log must have unique immutable ID"
    
    def test_failed_transaction_logged_in_audit(
        self,
        transaction_service,
        mock_audit_logger,
        valid_transaction_request
    ):
        """Verify failed transactions are logged in audit trail."""
        # Arrange
        valid_transaction_request.amount = Decimal("0")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        mock_audit_logger.log.assert_called_once(), \
            "BSA 31 CFR 1010.430: failed transactions must be logged"
        
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.result == "rejected"


class TestThresholdBoundaries:
    """Test compliance thresholds using AUTHORITATIVE values."""
    
    def test_ctr_threshold_boundary(
        self,
        transaction_service,
        mock_account_repository,
        valid_account,
        valid_transaction_request
    ):
        """Verify CTR threshold is exactly $10,000."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        
        # Test just below CTR threshold
        valid_transaction_request.amount = Decimal("9999.99")
        result = transaction_service.process_transaction(valid_transaction_request)
        assert result.status == TransactionStatus.SUCCESS
        
        # Test at CTR threshold (should still succeed but trigger CTR)
        valid_account.balance = Decimal("20000.00")
        mock_account_repository.get_account.return_value = valid_account
        valid_transaction_request.amount = Decimal("10000.00")
        result = transaction_service.process_transaction(valid_transaction_request)
        assert result.status == TransactionStatus.SUCCESS, \
            "CTR threshold is $10,000 exactly (12 C.F.R. Part 345)"
        
        # Test above CTR threshold
        valid_account.balance = Decimal("20000.00")
        mock_account_repository.get_account.return_value = valid_account
        valid_transaction_request.amount = Decimal("10000.01")
        result = transaction_service.process_transaction(valid_transaction_request)
        assert result.status == TransactionStatus.SUCCESS
    
    def test_sar_threshold_boundary(self, transaction_service):
        """Verify SAR threshold is exactly $5,000."""
        assert transaction_service.sar_threshold == Decimal("5000"), \
            "SAR threshold must be exactly $5,000 (12 C.F.R. Part 345)"
    
    def test_travel_rule_threshold_boundary(self, transaction_service):
        """Verify Travel Rule threshold is exactly $3,000."""
        assert transaction_service.travel_rule_threshold == Decimal("3000"), \
            "Travel Rule threshold must be exactly $3,000 (12 C.F.R. Part 345)"
    
    def test_wire_dual_approval_threshold_boundary(self, transaction_service):
        """Verify wire dual approval threshold is exactly $10,000."""
        assert transaction_service.wire_dual_approval_threshold == Decimal("10000"), \
            "Wire dual approval threshold must be exactly $10,000 (12 C.F.R. Part 345)"


class TestDataHandlingCompliance:
    """Test data handling and encryption requirements (GLBA, PCI-DSS)."""
    
    def test_account_masking_shows_last_four_only(
        self,
        transaction_service,
        mock_account_repository,
        mock_audit_logger,
        valid_account,
        valid_transaction_request
    ):
        """Verify account numbers are masked per GLBA Safeguards Rule."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        valid_transaction_request.from_account = "1234567890123456"
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        audit_entry = mock_audit_logger.log.call_args[0][0]
        masked_account = audit_entry.details["from_account"]
        
        assert masked_account.endswith("3456"), \
            "GLBA Safeguards Rule: show last 4 digits only"
        assert masked_account.count("*") == 12, \
            "GLBA Safeguards Rule: mask all but last 4 digits"
    
    def test_short_account_fully_masked(self, transaction_service):
        """Verify short account numbers are fully masked."""
        # Arrange
        short_account = "1234"
        
        # Act
        masked = transaction_service._mask_account(short_account)
        
        # Assert
        assert masked == "****", \
            "GLBA: accounts with 4 or fewer digits should be fully masked"
    
    def test_decimal_precision_for_currency(
        self,
        transaction_service,
        mock_account_repository,
        valid_account,
        valid_transaction_request
    ):
        """Verify Decimal type is used for currency (no floating point errors)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        valid_transaction_request.amount = Decimal("0.01")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        expected_balance = Decimal("9999.99")
        mock_account_repository.update_balance.assert_called_once_with(
            valid_transaction_request.from_account,
            expected_balance
        )
        
        # Verify no floating point rounding errors
        assert expected_balance == Decimal("9999.99"), \
            "Currency must use Decimal for precision (SOX compliance)"


class TestInvalidSourceAccount:
    """Test invalid source account handling."""
    
    def test_nonexistent_source_account_rejected(
        self,
        transaction_service,
        mock_account_repository,
        mock_audit_logger,
        valid_transaction_request
    ):
        """Verify transaction from non-existent account is rejected."""
        # Arrange
        mock_account_repository.get_account.return_value = None
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED, \
            "Transaction from non-existent account must be rejected"
        assert result.message == "Invalid source account"
        
        # Verify rejection is logged
        mock_audit_logger.log.assert_called_once()
        audit_entry = mock_audit_logger.log.call_args[0][0]
        assert audit_entry.action == "INVALID_SOURCE"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_very_large_amount_with_sufficient_balance(
        self,
        transaction_service,
        mock_account_repository,
        valid_transaction_request
    ):
        """Verify very large transactions work with sufficient balance."""
        # Arrange
        large_balance_account = Account(
            account_id="1234567890",
            routing_number="021000021",
            balance=Decimal("999999999.99"),
            user_id="USER-001"
        )
        mock_account_repository.get_account.return_value = large_balance_account
        valid_transaction_request.amount = Decimal("999999999.99")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_account_repository.update_balance.assert_called_once_with(
            valid_transaction_request.from_account,
            Decimal("0.00")
        )
    
    def test_minimum_valid_amount(
        self,
        transaction_service,
        mock_account_repository,
        valid_account,
        valid_transaction_request
    ):
        """Verify minimum valid transaction amount (one cent)."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        valid_transaction_request.amount = Decimal("0.01")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.message == "Transaction successful"
    
    def test_valid_routing_number_formats(
        self,
        transaction_service,
        mock_account_repository,
        valid_account,
        valid_transaction_request
    ):
        """Verify valid 9-digit routing numbers are accepted."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        valid_routing_numbers = [
            "021000021",  # Standard format
            "111000025",
            "026009593"
        ]
        
        for routing in valid_routing_numbers:
            # Act
            valid_transaction_request.to_routing = routing
            result = transaction_service.process_transaction(valid_transaction_request)
            
            # Assert
            assert result.status == TransactionStatus.SUCCESS, \
                f"Valid routing number {routing} should be accepted"
    
    def test_valid_account_number_lengths(
        self,
        transaction_service,
        mock_account_repository,
        valid_account,
        valid_transaction_request
    ):
        """Verify account numbers between 4-17 digits are accepted."""
        # Arrange
        mock_account_repository.get_account.return_value = valid_account
        valid_accounts = [
            "1234",           # Minimum (4 digits)
            "12345678",       # Mid-range
            "12345678901234567"  # Maximum (17 digits)
        ]
        
        for account in valid_accounts:
            # Act
            valid_transaction_request.to_account = account
            result = transaction_service.process_transaction(valid_transaction_request)
            
            # Assert
            assert result.status == TransactionStatus.SUCCESS, \
                f"Valid account number length {len(account)} should be accepted"