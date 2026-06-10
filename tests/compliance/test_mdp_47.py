import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# Constants based on U.S. banking regulations
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
    routing_number: str
    amount: Decimal
    user_id: str
    ip_address: str
    device_info: str
    timestamp: datetime


@dataclass
class TransactionResult:
    status: TransactionStatus
    message: str
    transaction_id: Optional[str]
    audit_log_id: Optional[str]
    ofac_check_passed: bool
    ctr_filed: bool
    sar_filed: bool
    dual_approval_required: bool


class OFACService:
    def screen(self, account_number: str, routing_number: str, user_id: str) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(self, transaction: Dict[str, Any]) -> str:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_number: str) -> Optional[Account]:
        raise NotImplementedError
    
    def update_balance(self, account_number: str, new_balance: Decimal) -> bool:
        raise NotImplementedError


class TransactionService:
    def __init__(
        self,
        account_repo: AccountRepository,
        ofac_service: OFACService,
        audit_logger: AuditLogger
    ):
        self.account_repo = account_repo
        self.ofac_service = ofac_service
        self.audit_logger = audit_logger
    
    def execute_transaction(self, request: TransactionRequest) -> TransactionResult:
        # Validate amount
        if request.amount == Decimal("0"):
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Amount must be greater than 0",
                transaction_id=None,
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False
            )
        
        if request.amount < Decimal("0"):
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid amount",
                transaction_id=None,
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False
            )
        
        # Get source account
        from_account = self.account_repo.get_account(request.from_account)
        if not from_account:
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid source account",
                transaction_id=None,
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False
            )
        
        # Check sufficient balance
        if from_account.balance < request.amount:
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Insufficient balance",
                transaction_id=None,
                audit_log_id=None,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False
            )
        
        # OFAC screening
        ofac_result = self.ofac_service.screen(
            request.to_account,
            request.routing_number,
            request.user_id
        )
        
        if ofac_result["status"] == "BLOCKED":
            audit_log_id = self.audit_logger.log_transaction({
                "transaction_type": "TRANSFER",
                "from_account": self._mask_account(request.from_account),
                "to_account": self._mask_account(request.to_account),
                "amount": str(request.amount),
                "status": "BLOCKED_OFAC",
                "user_id": request.user_id,
                "ip_address": request.ip_address,
                "device_info": request.device_info,
                "timestamp": request.timestamp.isoformat(),
                "ofac_match_score": ofac_result.get("match_score"),
                "encryption": "AES-256",
                "transport": "TLS-1.3"
            })
            return TransactionResult(
                status=TransactionStatus.BLOCKED,
                message="Transaction blocked due to OFAC screening",
                transaction_id=None,
                audit_log_id=audit_log_id,
                ofac_check_passed=False,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False
            )
        
        # Validate beneficiary account
        if not self._validate_routing_account(request.routing_number, request.to_account):
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid beneficiary account",
                transaction_id=None,
                audit_log_id=None,
                ofac_check_passed=True,
                ctr_filed=False,
                sar_filed=False,
                dual_approval_required=False
            )
        
        # Check compliance thresholds
        ctr_filed = request.amount >= CTR_THRESHOLD
        sar_filed = request.amount >= SAR_THRESHOLD and ofac_result.get("suspicious", False)
        dual_approval_required = request.amount >= WIRE_DUAL_APPROVAL_THRESHOLD
        
        # Update balance
        new_balance = from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account, new_balance)
        
        # Create audit log
        transaction_id = f"TXN-{request.timestamp.timestamp()}"
        audit_log_id = self.audit_logger.log_transaction({
            "transaction_id": transaction_id,
            "transaction_type": "TRANSFER",
            "from_account": self._mask_account(request.from_account),
            "to_account": self._mask_account(request.to_account),
            "routing_number": request.routing_number,
            "amount": str(request.amount),
            "status": "SUCCESS",
            "user_id": request.user_id,
            "ip_address": request.ip_address,
            "device_info": request.device_info,
            "timestamp": request.timestamp.isoformat(),
            "previous_balance": str(from_account.balance),
            "new_balance": str(new_balance),
            "ctr_filed": ctr_filed,
            "sar_filed": sar_filed,
            "dual_approval_required": dual_approval_required,
            "ofac_check_passed": True,
            "encryption": "AES-256",
            "transport": "TLS-1.3",
            "retention_period": "5_years_31_CFR_1010.430"
        })
        
        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            message="Transaction completed successfully",
            transaction_id=transaction_id,
            audit_log_id=audit_log_id,
            ofac_check_passed=True,
            ctr_filed=ctr_filed,
            sar_filed=sar_filed,
            dual_approval_required=dual_approval_required
        )
    
    def _validate_routing_account(self, routing_number: str, account_number: str) -> bool:
        if not routing_number or len(routing_number) != 9:
            return False
        if not account_number or len(account_number) < 4:
            return False
        return True
    
    def _mask_account(self, account_number: str) -> str:
        """Mask account number showing only last 4 digits per GLBA requirements."""
        if len(account_number) <= 4:
            return "****"
        return "*" * (len(account_number) - 4) + account_number[-4:]


@pytest.fixture
def mock_account_repo():
    """Mock account repository for testing."""
    repo = Mock(spec=AccountRepository)
    return repo


@pytest.fixture
def mock_ofac_service():
    """Mock OFAC service for testing."""
    service = Mock(spec=OFACService)
    return service


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger for testing."""
    logger = Mock(spec=AuditLogger)
    logger.log_transaction.return_value = "AUDIT-12345"
    return logger


@pytest.fixture
def transaction_service(mock_account_repo, mock_ofac_service, mock_audit_logger):
    """Create transaction service with mocked dependencies."""
    return TransactionService(
        account_repo=mock_account_repo,
        ofac_service=mock_ofac_service,
        audit_logger=mock_audit_logger
    )


@pytest.fixture
def valid_account():
    """Create a valid account with sufficient balance."""
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        user_id="USER-001",
        status="ACTIVE"
    )


@pytest.fixture
def transaction_timestamp():
    """Create a timezone-aware timestamp for transactions."""
    return datetime.now(timezone.utc)


class TestSuccessfulTransaction:
    """Test suite for successful transaction scenario."""
    
    def test_successful_transaction(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {
            "status": "CLEAR",
            "match_score": 0,
            "suspicious": False
        }
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.message == "Transaction completed successfully"
        assert result.transaction_id is not None
        assert result.audit_log_id == "AUDIT-12345"
        assert result.ofac_check_passed is True
        
        # Verify balance was updated
        mock_account_repo.update_balance.assert_called_once_with(
            "1234567890",
            Decimal("49000.00")
        )
        
        # Verify audit log was created
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["status"] == "SUCCESS"
        assert audit_call_args["user_id"] == "USER-001"
        assert audit_call_args["ip_address"] == "192.168.1.100"
        assert audit_call_args["device_info"] == "Mozilla/5.0"
        assert audit_call_args["encryption"] == "AES-256"
        assert audit_call_args["transport"] == "TLS-1.3"
        assert "retention_period" in audit_call_args
        assert "5_years" in audit_call_args["retention_period"]
    
    def test_successful_transaction_with_account_masking(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """
        Test that account numbers are masked in audit logs per GLBA requirements.
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"status": "CLEAR", "suspicious": False}
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["from_account"] == "******7890"
        assert audit_call_args["to_account"] == "******3210"


class TestZeroAmountTransfer:
    """Test suite for zero amount transfer scenario."""
    
    def test_zero_amount_transfer(
        self,
        transaction_service,
        transaction_timestamp
    ):
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
            routing_number="021000021",
            amount=Decimal("0"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Amount must be greater than 0"
        assert result.transaction_id is None
        assert result.audit_log_id is None


class TestNegativeAmountTransfer:
    """Test suite for negative amount transfer scenario."""
    
    def test_negative_amount_transfer(
        self,
        transaction_service,
        transaction_timestamp
    ):
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
            routing_number="021000021",
            amount=Decimal("-100.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"
        assert result.transaction_id is None
        assert result.audit_log_id is None
    
    def test_negative_amount_boundary(
        self,
        transaction_service,
        transaction_timestamp
    ):
        """Test negative amount at boundary value."""
        # Arrange
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("-0.01"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"


class TestInsufficientBalance:
    """Test suite for insufficient balance scenario."""
    
    def test_insufficient_balance(
        self,
        transaction_service,
        mock_account_repo,
        transaction_timestamp
    ):
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
            user_id="USER-001"
        )
        mock_account_repo.get_account.return_value = account
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("5000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"
        assert result.transaction_id is None
        assert result.audit_log_id is None
    
    def test_insufficient_balance_boundary(
        self,
        transaction_service,
        mock_account_repo,
        transaction_timestamp
    ):
        """Test insufficient balance at exact boundary."""
        # Arrange
        account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            user_id="USER-001"
        )
        mock_account_repo.get_account.return_value = account
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("1000.01"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test suite for invalid beneficiary scenario."""
    
    def test_invalid_beneficiary_routing_number(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {"status": "CLEAR", "suspicious": False}
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="12345",  # Invalid routing number (not 9 digits)
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
        assert result.transaction_id is None
    
    def test_invalid_beneficiary_account_number(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test invalid beneficiary with short account number."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {"status": "CLEAR", "suspicious": False}
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="123",  # Invalid account number (too short)
            routing_number="021000021",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_empty_routing_number(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test invalid beneficiary with empty routing number."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {"status": "CLEAR", "suspicious": False}
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"


class TestOFACScreening:
    """Test suite for OFAC/SDN screening compliance."""
    
    def test_ofac_blocked_transaction(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        mock_audit_logger,
        valid_account,
        transaction_timestamp
    ):
        """Test transaction blocked due to OFAC match."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {
            "status": "BLOCKED",
            "match_score": 95,
            "suspicious": True
        }
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("1000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert "OFAC" in result.message
        assert result.transaction_id is None
        assert result.ofac_check_passed is False
        
        # Verify audit log was created for blocked transaction
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["status"] == "BLOCKED_OFAC"
        assert audit_call_args["ofac_match_score"] == 95
    
    def test_ofac_high_match_score_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test OFAC screening at fuzzy match threshold."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {
            "status": "BLOCKED",
            "match_score": OFAC_FUZZY_THRESHOLD,
            "suspicious": True
        }
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("500.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert result.ofac_check_passed is False


class TestCTRFiling:
    """Test suite for Currency Transaction Report (CTR) filing requirements."""
    
    def test_ctr_threshold_exceeded(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test CTR filing when transaction exceeds $10,000 threshold."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"status": "CLEAR", "suspicious": False}
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("15000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.ctr_filed is True
        
        # Verify audit log includes CTR flag
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["ctr_filed"] is True
    
    def test_ctr_threshold_boundary(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test CTR filing at exact $10,000 threshold."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"status": "CLEAR", "suspicious": False}
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=CTR_THRESHOLD,
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.ctr_filed is True
    
    def test_ctr_not_filed_below_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test CTR not filed when below $10,000 threshold."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"status": "CLEAR", "suspicious": False}
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("9999.99"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.ctr_filed is False


class TestSARFiling:
    """Test suite for Suspicious Activity Report (SAR) filing requirements."""
    
    def test_sar_filed_for_suspicious_activity(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test SAR filing when transaction exceeds $5,000 and flagged as suspicious."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {
            "status": "CLEAR",
            "suspicious": True,
            "match_score": 75
        }
        
        request = TransactionRequest(
            from_account="1234567890",
            to_account="9876543210",
            routing_number="021000021",
            amount=Decimal("6000.00"),
            user_id="USER-001",
            ip_address="192.168.1.100",
            device_info="Mozilla/5.0",
            timestamp=transaction_timestamp
        )
        
        # Act
        result = transaction_service.execute_transaction(request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.sar_filed is True
        
        # Verify audit log includes SAR flag
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["sar_filed"] is True
    
    def test_sar_not_filed_below_threshold(
        self,
        transaction_service,
        mock_account_repo,
        mock_ofac_service,
        valid_account,
        transaction_timestamp
    ):
        """Test SAR not filed when below $5,000 threshold even if suspicious."""
        # Arrange
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance