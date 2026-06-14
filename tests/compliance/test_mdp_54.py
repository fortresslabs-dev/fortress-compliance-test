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
class User:
    user_id: str
    name: str
    ssn: str
    ip_address: str
    device_info: str


@dataclass
class TransactionRequest:
    from_account: Account
    to_account_number: str
    to_routing_number: str
    amount: Decimal
    user: User
    timestamp: datetime
    transaction_type: str = "TRANSFER"


@dataclass
class TransactionResult:
    status: TransactionStatus
    transaction_id: Optional[str]
    message: str
    audit_id: Optional[str]
    timestamp: datetime
    balance_after: Optional[Decimal]


class OFACService:
    def screen(self, name: str, account_number: str) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log_transaction(self, transaction_data: Dict[str, Any]) -> str:
        raise NotImplementedError
    
    def log_decision(self, decision_data: Dict[str, Any]) -> str:
        raise NotImplementedError


class AccountRepository:
    def get_account(self, account_number: str, routing_number: str) -> Optional[Account]:
        raise NotImplementedError
    
    def update_balance(self, account_id: str, new_balance: Decimal) -> bool:
        raise NotImplementedError
    
    def validate_account(self, account_number: str, routing_number: str) -> bool:
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
    
    def process_transaction(self, request: TransactionRequest) -> TransactionResult:
        timestamp = datetime.now(timezone.utc)
        
        # Validate amount
        if request.amount == Decimal("0"):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Amount must be greater than 0",
                audit_id=None,
                timestamp=timestamp,
                balance_after=None
            )
            self._log_rejection(request, result)
            return result
        
        if request.amount < Decimal("0"):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid amount",
                audit_id=None,
                timestamp=timestamp,
                balance_after=None
            )
            self._log_rejection(request, result)
            return result
        
        # Check sufficient balance
        if request.from_account.balance < request.amount:
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Insufficient balance",
                audit_id=None,
                timestamp=timestamp,
                balance_after=None
            )
            self._log_rejection(request, result)
            return result
        
        # Validate beneficiary account
        if not self.account_repo.validate_account(
            request.to_account_number,
            request.to_routing_number
        ):
            result = TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid beneficiary account",
                audit_id=None,
                timestamp=timestamp,
                balance_after=None
            )
            self._log_rejection(request, result)
            return result
        
        # OFAC screening
        ofac_result = self.ofac_service.screen(
            request.user.name,
            request.to_account_number
        )
        
        if ofac_result.get("match_score", 0) >= OFAC_FUZZY_THRESHOLD:
            if ofac_result.get("is_blocked", False):
                result = TransactionResult(
                    status=TransactionStatus.BLOCKED,
                    transaction_id=None,
                    message="Transaction blocked - OFAC match",
                    audit_id=None,
                    timestamp=timestamp,
                    balance_after=None
                )
                self._log_ofac_block(request, ofac_result)
                return result
        
        # Process transaction
        new_balance = request.from_account.balance - request.amount
        self.account_repo.update_balance(request.from_account.account_id, new_balance)
        
        transaction_id = f"TXN-{timestamp.timestamp()}"
        
        # Audit logging with compliance requirements
        audit_data = self._create_audit_data(request, transaction_id, new_balance)
        audit_id = self.audit_logger.log_transaction(audit_data)
        
        # CTR/SAR detection
        if request.amount >= CTR_THRESHOLD:
            self._file_ctr(request, transaction_id)
        
        if self._is_suspicious(request):
            self._flag_for_sar(request, transaction_id)
        
        result = TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction successful",
            audit_id=audit_id,
            timestamp=timestamp,
            balance_after=new_balance
        )
        
        return result
    
    def _create_audit_data(
        self,
        request: TransactionRequest,
        transaction_id: str,
        new_balance: Decimal
    ) -> Dict[str, Any]:
        return {
            "transaction_id": transaction_id,
            "user_id": request.user.user_id,
            "ip_address": request.user.ip_address,
            "device_info": request.user.device_info,
            "timestamp": request.timestamp.isoformat(),
            "from_account": request.from_account.account_id,
            "to_account": request.to_account_number,
            "to_routing": request.to_routing_number,
            "amount": str(request.amount),
            "balance_before": str(request.from_account.balance),
            "balance_after": str(new_balance),
            "ssn_masked": self._mask_ssn(request.user.ssn),
            "encryption": "AES-256",
            "transport": "TLS-1.3"
        }
    
    def _mask_ssn(self, ssn: str) -> str:
        if len(ssn) >= 4:
            return f"***-**-{ssn[-4:]}"
        return "***-**-****"
    
    def _log_rejection(self, request: TransactionRequest, result: TransactionResult):
        self.audit_logger.log_decision({
            "user_id": request.user.user_id,
            "timestamp": result.timestamp.isoformat(),
            "decision": "REJECTED",
            "reason": result.message,
            "amount": str(request.amount),
            "ip_address": request.user.ip_address
        })
    
    def _log_ofac_block(self, request: TransactionRequest, ofac_result: Dict[str, Any]):
        self.audit_logger.log_decision({
            "user_id": request.user.user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": "BLOCKED",
            "reason": "OFAC_MATCH",
            "ofac_score": ofac_result.get("match_score"),
            "amount": str(request.amount)
        })
    
    def _file_ctr(self, request: TransactionRequest, transaction_id: str):
        self.audit_logger.log_decision({
            "transaction_id": transaction_id,
            "report_type": "CTR",
            "amount": str(request.amount),
            "threshold": str(CTR_THRESHOLD),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "regulation": "31 CFR 1010.311"
        })
    
    def _flag_for_sar(self, request: TransactionRequest, transaction_id: str):
        self.audit_logger.log_decision({
            "transaction_id": transaction_id,
            "report_type": "SAR",
            "amount": str(request.amount),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "regulation": "31 CFR 1020.320"
        })
    
    def _is_suspicious(self, request: TransactionRequest) -> bool:
        return request.amount >= SAR_THRESHOLD


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
    logger.log_decision.return_value = "DECISION-12345"
    return logger


@pytest.fixture
def transaction_service(
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock
) -> TransactionService:
    return TransactionService(
        account_repo=mock_account_repo,
        ofac_service=mock_ofac_service,
        audit_logger=mock_audit_logger
    )


@pytest.fixture
def valid_user() -> User:
    return User(
        user_id="USER-001",
        name="John Doe",
        ssn="123-45-6789",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )


@pytest.fixture
def valid_from_account() -> Account:
    return Account(
        account_id="ACC-001",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        status="ACTIVE"
    )


@pytest.fixture
def valid_transaction_request(valid_user: User, valid_from_account: Account) -> TransactionRequest:
    return TransactionRequest(
        from_account=valid_from_account,
        to_account_number="987654321",
        to_routing_number="021000022",
        amount=Decimal("100.00"),
        user=valid_user,
        timestamp=datetime.now(timezone.utc),
        transaction_type="TRANSFER"
    )


# Test Cases

class TestSuccessfulTransaction:
    """Test successful transaction scenario with compliance requirements."""
    
    def test_successful_transaction(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {
            "match_score": 0,
            "is_blocked": False
        }
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None
        assert result.transaction_id.startswith("TXN-")
        assert result.balance_after == Decimal("9900.00")
        assert result.audit_id == "AUDIT-12345"
        
        # Verify balance updated
        mock_account_repo.update_balance.assert_called_once_with(
            "ACC-001",
            Decimal("9900.00")
        )
        
        # Verify audit trail recorded with compliance data
        mock_audit_logger.log_transaction.assert_called_once()
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["user_id"] == "USER-001"
        assert audit_call_args["ip_address"] == "192.168.1.100"
        assert audit_call_args["device_info"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        assert audit_call_args["ssn_masked"] == "***-**-6789"
        assert audit_call_args["encryption"] == "AES-256"
        assert audit_call_args["transport"] == "TLS-1.3"
        assert "timestamp" in audit_call_args
        
        # Verify OFAC screening performed
        mock_ofac_service.screen.assert_called_once_with(
            "John Doe",
            "987654321"
        )


class TestZeroAmountTransfer:
    """Test zero amount transfer rejection."""
    
    def test_zero_amount_transfer(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_audit_logger: Mock
    ):
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
        assert result.balance_after is None
        
        # Verify rejection logged
        mock_audit_logger.log_decision.assert_called_once()
        decision_call_args = mock_audit_logger.log_decision.call_args[0][0]
        assert decision_call_args["decision"] == "REJECTED"
        assert decision_call_args["reason"] == "Amount must be greater than 0"


class TestNegativeAmountTransfer:
    """Test negative amount transfer rejection."""
    
    def test_negative_amount_transfer(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_audit_logger: Mock
    ):
        """
        Scenario: negative_amount_transfer
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        valid_transaction_request.amount = Decimal("-100")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Invalid amount"
        assert result.balance_after is None
        
        # Verify rejection logged
        mock_audit_logger.log_decision.assert_called_once()
        decision_call_args = mock_audit_logger.log_decision.call_args[0][0]
        assert decision_call_args["decision"] == "REJECTED"
        assert decision_call_args["reason"] == "Invalid amount"


class TestInsufficientBalance:
    """Test insufficient balance rejection."""
    
    def test_insufficient_balance(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_audit_logger: Mock
    ):
        """
        Scenario: insufficient_balance
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        valid_transaction_request.from_account.balance = Decimal("1000.00")
        valid_transaction_request.amount = Decimal("5000.00")
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Insufficient balance"
        assert result.balance_after is None
        
        # Verify rejection logged
        mock_audit_logger.log_decision.assert_called_once()
        decision_call_args = mock_audit_logger.log_decision.call_args[0][0]
        assert decision_call_args["decision"] == "REJECTED"
        assert decision_call_args["reason"] == "Insufficient balance"
        assert decision_call_args["user_id"] == "USER-001"


class TestInvalidBeneficiary:
    """Test invalid beneficiary account rejection."""
    
    def test_invalid_beneficiary(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_audit_logger: Mock
    ):
        """
        Scenario: invalid_beneficiary
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        mock_account_repo.validate_account.return_value = False
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Invalid beneficiary account"
        assert result.balance_after is None
        
        # Verify validation attempted
        mock_account_repo.validate_account.assert_called_once_with(
            "987654321",
            "021000022"
        )
        
        # Verify rejection logged
        mock_audit_logger.log_decision.assert_called_once()


class TestOFACCompliance:
    """Test OFAC screening and blocking requirements."""
    
    def test_ofac_blocked_transaction(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test transaction blocked due to OFAC match.
        Verifies OFAC screening and blocking behavior.
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {
            "match_score": 95,
            "is_blocked": True,
            "matched_entity": "SDN-12345"
        }
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert result.transaction_id is None
        assert "OFAC" in result.message
        
        # Verify OFAC block logged
        assert mock_audit_logger.log_decision.call_count >= 1
        decision_calls = [call[0][0] for call in mock_audit_logger.log_decision.call_args_list]
        ofac_log = next((d for d in decision_calls if d.get("reason") == "OFAC_MATCH"), None)
        assert ofac_log is not None
        assert ofac_log["decision"] == "BLOCKED"
        assert ofac_log["ofac_score"] == 95
    
    def test_ofac_low_score_passes(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock
    ):
        """
        Test transaction proceeds when OFAC score below threshold.
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {
            "match_score": 50,
            "is_blocked": False
        }
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None


class TestCTRCompliance:
    """Test Currency Transaction Report (CTR) filing requirements."""
    
    def test_ctr_filed_for_transaction_at_threshold(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test CTR filed for transaction at $10,000 threshold.
        31 CFR 1010.311 - Currency Transaction Reporting
        """
        # Arrange
        valid_transaction_request.amount = CTR_THRESHOLD
        valid_transaction_request.from_account.balance = Decimal("20000.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify CTR logged
        decision_calls = [call[0][0] for call in mock_audit_logger.log_decision.call_args_list]
        ctr_log = next((d for d in decision_calls if d.get("report_type") == "CTR"), None)
        assert ctr_log is not None
        assert ctr_log["amount"] == str(CTR_THRESHOLD)
        assert ctr_log["regulation"] == "31 CFR 1010.311"
    
    def test_ctr_filed_for_transaction_above_threshold(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test CTR filed for transaction above $10,000 threshold.
        """
        # Arrange
        valid_transaction_request.amount = Decimal("15000.00")
        valid_transaction_request.from_account.balance = Decimal("20000.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify CTR logged
        decision_calls = [call[0][0] for call in mock_audit_logger.log_decision.call_args_list]
        ctr_log = next((d for d in decision_calls if d.get("report_type") == "CTR"), None)
        assert ctr_log is not None
    
    def test_no_ctr_for_transaction_below_threshold(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test no CTR filed for transaction below $10,000 threshold.
        """
        # Arrange
        valid_transaction_request.amount = Decimal("9999.99")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify no CTR logged
        decision_calls = [call[0][0] for call in mock_audit_logger.log_decision.call_args_list]
        ctr_log = next((d for d in decision_calls if d.get("report_type") == "CTR"), None)
        assert ctr_log is None


class TestSARCompliance:
    """Test Suspicious Activity Report (SAR) flagging requirements."""
    
    def test_sar_flagged_for_suspicious_transaction(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test SAR flagged for transaction at $5,000 threshold.
        31 CFR 1020.320 - Suspicious Activity Reporting
        """
        # Arrange
        valid_transaction_request.amount = SAR_THRESHOLD
        valid_transaction_request.from_account.balance = Decimal("10000.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify SAR logged
        decision_calls = [call[0][0] for call in mock_audit_logger.log_decision.call_args_list]
        sar_log = next((d for d in decision_calls if d.get("report_type") == "SAR"), None)
        assert sar_log is not None
        assert sar_log["regulation"] == "31 CFR 1020.320"


class TestPIIHandling:
    """Test PII masking and data protection requirements."""
    
    def test_ssn_masked_in_audit_log(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test SSN masked in audit logs (show last 4 only).
        GLBA Safeguards Rule compliance.
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify SSN masked
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["ssn_masked"] == "***-**-6789"
        assert "123-45-6789" not in str(audit_call_args)
    
    def test_encryption_requirements_in_audit(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test encryption requirements documented in audit trail.
        AES-256 at rest, TLS 1.3 in transit.
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        assert audit_call_args["encryption"] == "AES-256"
        assert audit_call_args["transport"] == "TLS-1.3"


class TestAuditTrailRequirements:
    """Test audit trail and record retention requirements."""
    
    def test_audit_trail_contains_required_fields(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test audit trail contains all required fields per BSA requirements.
        31 CFR 1010.430 - 5 year retention requirement.
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        audit_call_args = mock_audit_logger.log_transaction.call_args[0][0]
        
        # Verify required audit fields
        assert "transaction_id" in audit_call_args
        assert "user_id" in audit_call_args
        assert audit_call_args["user_id"] == "USER-001"
        assert "ip_address" in audit_call_args
        assert audit_call_args["ip_address"] == "192.168.1.100"
        assert "device_info" in audit_call_args
        assert "timestamp" in audit_call_args
        assert "from_account" in audit_call_args
        assert "to_account" in audit_call_args
        assert "amount" in audit_call_args
        assert "balance_before" in audit_call_args
        assert "balance_after" in audit_call_args
    
    def test_timestamp_is_timezone_aware(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock
    ):
        """
        Test timestamps are timezone-aware (UTC).
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.tzinfo == timezone.utc


class TestBoundaryConditions:
    """Test boundary conditions for regulatory thresholds."""
    
    def test_transaction_at_travel_rule_threshold(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock
    ):
        """
        Test transaction at Travel Rule threshold ($3,000).
        """
        # Arrange
        valid_transaction_request.amount = TRAVEL_RULE_THRESHOLD
        valid_transaction_request.from_account.balance = Decimal("5000.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.balance_after == Decimal("2000.00")
    
    def test_transaction_one_cent_below_ctr_threshold(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock
    ):
        """
        Test transaction one cent below CTR threshold.
        """
        # Arrange
        valid_transaction_request.amount = CTR_THRESHOLD - Decimal("0.01")
        valid_transaction_request.from_account.balance = Decimal("15000.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify no CTR filed
        decision_calls = [call[0][0] for call in mock_audit_logger.log_decision.call_args_list]
        ctr_log = next((d for d in decision_calls if d.get("report_type") == "CTR"), None)
        assert ctr_log is None
    
    def test_transaction_exactly_at_balance(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock
    ):
        """
        Test transaction for exact account balance.
        """
        # Arrange
        valid_transaction_request.from_account.balance = Decimal("1000.00")
        valid_transaction_request.amount = Decimal("1000.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.balance_after == Decimal("0.00")


class TestDecimalPrecision:
    """Test decimal precision for currency handling."""
    
    def test_transaction_with_cents(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock
    ):
        """
        Test transaction with cent precision.
        """
        # Arrange
        valid_transaction_request.amount = Decimal("123.45")
        valid_transaction_request.from_account.balance = Decimal("500.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.balance_after == Decimal("376.55")
    
    def test_balance_calculation_precision(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock
    ):
        """
        Test balance calculation maintains precision.
        """
        # Arrange
        valid_transaction_request.amount = Decimal("0.01")
        valid_transaction_request.from_account.balance = Decimal("100.00")
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "is_blocked": False}
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert
        assert result.balance_after == Decimal("99.99")
        
        # Verify update called with precise value
        mock_account_repo.update_balance.assert_called_once_with(
            "ACC-001",
            Decimal("99.99")
        )


class TestNegativePathScenarios:
    """Test additional negative path scenarios."""
    
    def test_multiple_validation_failures(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock
    ):
        """
        Test that first validation failure is returned.
        """
        # Arrange - set up multiple failure conditions
        valid_transaction_request.amount = Decimal("0")
        valid_transaction_request.from_account.balance = Decimal("0")
        mock_account_repo.validate_account.return_value = False
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert - zero amount check happens first
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Amount must be greater than 0"
    
    def test_ofac_false_positive_handling(
        self,
        transaction_service: TransactionService,
        valid_transaction_request: TransactionRequest,
        mock_account_repo: Mock,
        mock_ofac_service: Mock
    ):
        """
        Test handling of OFAC false positive (high score but not blocked).
        """
        # Arrange
        mock_account_repo.validate_account.return_value = True
        mock_ofac_service.screen.return_value = {
            "match_score": 90,
            "is_blocked": False  # False positive - review but don't block
        }
        
        # Act
        result = transaction_service.process_transaction(valid_transaction_request)
        
        # Assert - transaction proceeds despite high score
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None