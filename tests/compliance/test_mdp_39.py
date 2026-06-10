import pytest
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# Constants - U.S. fallback thresholds
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
    retention_years: int = 5


class OFACService:
    def screen(self, account_number: str, routing_number: str, user_id: str) -> Dict[str, Any]:
        raise NotImplementedError


class AuditLogger:
    def log(self, record: AuditRecord) -> str:
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
        audit_logger: AuditLogger
    ):
        self.account_repo = account_repo
        self.ofac_service = ofac_service
        self.audit_logger = audit_logger
    
    def execute_transaction(self, request: TransactionRequest) -> TransactionResult:
        # Validate amount
        if request.amount == Decimal("0"):
            audit_record = self._create_audit_record(request, "REJECTED", None, 
                                                     {"reason": "Amount must be greater than 0"})
            self.audit_logger.log(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Amount must be greater than 0",
                audit_id=audit_record.audit_id,
                new_balance=None
            )
        
        if request.amount < Decimal("0"):
            audit_record = self._create_audit_record(request, "REJECTED", None,
                                                     {"reason": "Invalid amount"})
            self.audit_logger.log(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid amount",
                audit_id=audit_record.audit_id,
                new_balance=None
            )
        
        # Validate beneficiary
        if not self.account_repo.validate_beneficiary(request.to_account, request.to_routing):
            audit_record = self._create_audit_record(request, "REJECTED", None,
                                                     {"reason": "Invalid beneficiary account"})
            self.audit_logger.log(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Invalid beneficiary account",
                audit_id=audit_record.audit_id,
                new_balance=None
            )
        
        # Get account and check balance
        account = self.account_repo.get_account(request.from_account)
        if not account:
            audit_record = self._create_audit_record(request, "REJECTED", None,
                                                     {"reason": "Account not found"})
            self.audit_logger.log(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Account not found",
                audit_id=audit_record.audit_id,
                new_balance=None
            )
        
        if account.balance < request.amount:
            audit_record = self._create_audit_record(request, "REJECTED", None,
                                                     {"reason": "Insufficient balance"})
            self.audit_logger.log(audit_record)
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                transaction_id=None,
                message="Insufficient balance",
                audit_id=audit_record.audit_id,
                new_balance=None
            )
        
        # OFAC screening
        ofac_result = self.ofac_service.screen(request.to_account, request.to_routing, request.user_id)
        if ofac_result["match_score"] >= OFAC_FUZZY_THRESHOLD:
            audit_record = self._create_audit_record(request, "BLOCKED", None,
                                                     {"reason": "OFAC match", "ofac_result": ofac_result})
            self.audit_logger.log(audit_record)
            return TransactionResult(
                status=TransactionStatus.BLOCKED,
                transaction_id=None,
                message="Transaction blocked - compliance review required",
                audit_id=audit_record.audit_id,
                new_balance=None
            )
        
        # Execute transaction
        transaction_id = self._generate_transaction_id()
        new_balance = account.balance - request.amount
        self.account_repo.update_balance(request.from_account, new_balance)
        
        # Create audit record
        audit_record = self._create_audit_record(request, "SUCCESS", transaction_id,
                                                 {"new_balance": str(new_balance), "ofac_cleared": True})
        audit_id = self.audit_logger.log(audit_record)
        
        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            transaction_id=transaction_id,
            message="Transaction successful",
            audit_id=audit_id,
            new_balance=new_balance
        )
    
    def _create_audit_record(
        self,
        request: TransactionRequest,
        status: str,
        transaction_id: Optional[str],
        details: Dict[str, Any]
    ) -> AuditRecord:
        return AuditRecord(
            audit_id=self._generate_audit_id(),
            transaction_id=transaction_id,
            user_id=self._mask_pii(request.user_id),
            ip_address=request.ip_address,
            device_info=request.device_info,
            timestamp=request.timestamp,
            action="TRANSFER",
            status=status,
            amount=request.amount,
            details=details,
            encrypted=True,
            retention_years=5
        )
    
    def _generate_transaction_id(self) -> str:
        return f"TXN-{datetime.now(timezone.utc).timestamp()}"
    
    def _generate_audit_id(self) -> str:
        return f"AUD-{datetime.now(timezone.utc).timestamp()}"
    
    def _mask_pii(self, value: str) -> str:
        if len(value) > 4:
            return f"***{value[-4:]}"
        return "****"


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
    logger.log.return_value = "AUD-12345"
    return logger


@pytest.fixture
def transaction_service(
    mock_account_repo: Mock,
    mock_ofac_service: Mock,
    mock_audit_logger: Mock
) -> TransactionService:
    return TransactionService(mock_account_repo, mock_ofac_service, mock_audit_logger)


@pytest.fixture
def valid_account() -> Account:
    return Account(
        account_number="1234567890",
        routing_number="021000021",
        balance=Decimal("5000.00"),
        user_id="USER123",
        status="ACTIVE"
    )


@pytest.fixture
def valid_transaction_request() -> TransactionRequest:
    return TransactionRequest(
        from_account="1234567890",
        to_account="9876543210",
        to_routing="021000021",
        amount=Decimal("100.00"),
        user_id="USER123",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0",
        timestamp=datetime.now(timezone.utc)
    )


# Test Cases

class TestSuccessfulTransaction:
    """Test successful transaction scenario with compliance requirements."""
    
    def test_successful_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Scenario: successful_transaction
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None
        assert result.message == "Transaction successful"
        assert result.audit_id is not None
        assert result.new_balance == Decimal("4900.00")
        
        # Verify balance updated
        mock_account_repo.update_balance.assert_called_once_with(
            "1234567890",
            Decimal("4900.00")
        )
        
        # Verify audit trail recorded
        mock_audit_logger.log.assert_called_once()
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.user_id == "***R123"  # PII masked
        assert audit_call.ip_address == "192.168.1.1"
        assert audit_call.device_info == "Mozilla/5.0"
        assert audit_call.status == "SUCCESS"
        assert audit_call.amount == Decimal("100.00")
        assert audit_call.encrypted is True
        assert audit_call.retention_years == 5  # BSA requirement
        assert audit_call.timestamp is not None
        
        # Verify OFAC screening performed
        mock_ofac_service.screen.assert_called_once_with(
            "9876543210",
            "021000021",
            "USER123"
        )


class TestZeroAmountTransfer:
    """Test zero amount transfer rejection."""
    
    def test_zero_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
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
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Amount must be greater than 0"
        assert result.audit_id is not None
        assert result.new_balance is None
        
        # Verify audit logged
        mock_audit_logger.log.assert_called_once()
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Amount must be greater than 0"


class TestNegativeAmountTransfer:
    """Test negative amount transfer rejection."""
    
    def test_negative_amount_transfer(
        self,
        transaction_service: TransactionService,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
    ):
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
        
        # Verify audit logged
        mock_audit_logger.log.assert_called_once()
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Invalid amount"


class TestInsufficientBalance:
    """Test insufficient balance rejection."""
    
    def test_insufficient_balance(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
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
            user_id="USER123"
        )
        valid_transaction_request.amount = Decimal("5000.00")
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.transaction_id is None
        assert result.message == "Insufficient balance"
        assert result.audit_id is not None
        assert result.new_balance is None
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()
        
        # Verify audit logged
        mock_audit_logger.log.assert_called_once()
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Insufficient balance"


class TestInvalidBeneficiary:
    """Test invalid beneficiary account rejection."""
    
    def test_invalid_beneficiary(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
    ):
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
        
        # Verify validation attempted
        mock_account_repo.validate_beneficiary.assert_called_once_with(
            "9876543210",
            "021000021"
        )
        
        # Verify audit logged
        mock_audit_logger.log.assert_called_once()
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.status == "REJECTED"
        assert audit_call.details["reason"] == "Invalid beneficiary account"


class TestOFACCompliance:
    """Test OFAC screening and blocking."""
    
    def test_ofac_match_blocks_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that OFAC match above threshold blocks transaction.
        Compliance: OFAC/SDN screening requirement.
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_ofac_service.screen.return_value = {
            "match_score": 90,
            "matches": [{"name": "Sanctioned Entity", "list": "SDN"}]
        }
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.BLOCKED
        assert result.transaction_id is None
        assert "compliance review" in result.message.lower()
        assert result.audit_id is not None
        
        # Verify balance not updated
        mock_account_repo.update_balance.assert_not_called()
        
        # Verify audit logged with OFAC details
        mock_audit_logger.log.assert_called_once()
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.status == "BLOCKED"
        assert "OFAC match" in audit_call.details["reason"]
        assert "ofac_result" in audit_call.details
    
    def test_ofac_below_threshold_allows_transaction(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that OFAC match below threshold allows transaction.
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {
            "match_score": 50,
            "matches": []
        }
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.transaction_id is not None
        
        # Verify OFAC screening performed
        mock_ofac_service.screen.assert_called_once()


class TestBoundaryConditions:
    """Test boundary conditions based on U.S. thresholds."""
    
    def test_ctr_threshold_boundary(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test transaction at CTR threshold ($10,000).
        Compliance: CTR filing requirement at $10,000.
        """
        # Arrange
        account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("15000.00"),
            user_id="USER123"
        )
        valid_transaction_request.amount = CTR_THRESHOLD
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.new_balance == Decimal("5000.00")
        
        # Verify audit includes amount for CTR monitoring
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.amount == CTR_THRESHOLD
    
    def test_sar_threshold_boundary(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test transaction at SAR threshold ($5,000).
        Compliance: SAR filing for suspicious activity at $5,000.
        """
        # Arrange
        account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("10000.00"),
            user_id="USER123"
        )
        valid_transaction_request.amount = SAR_THRESHOLD
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.new_balance == Decimal("5000.00")
        
        # Verify audit trail for SAR monitoring
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.amount == SAR_THRESHOLD
    
    def test_travel_rule_threshold(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test transaction at Travel Rule threshold ($3,000).
        Compliance: Travel Rule requires transmittal of originator info at $3,000.
        """
        # Arrange
        account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("5000.00"),
            user_id="USER123"
        )
        valid_transaction_request.amount = TRAVEL_RULE_THRESHOLD
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify user ID captured for Travel Rule
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.user_id is not None
        assert audit_call.amount == TRAVEL_RULE_THRESHOLD


class TestAuditAndDataHandling:
    """Test audit trail and data handling compliance."""
    
    def test_pii_masking_in_audit(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that PII is masked in audit logs.
        Compliance: GLBA Safeguards Rule - protect consumer NPI.
        """
        # Arrange
        valid_transaction_request.user_id = "123456789"
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.user_id == "***6789"  # Last 4 only
        assert "123456789" not in audit_call.user_id
    
    def test_audit_record_encryption_flag(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that audit records are marked for encryption.
        Compliance: Encrypt data at rest (AES-256).
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.encrypted is True
    
    def test_audit_retention_period(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that audit records specify 5-year retention.
        Compliance: Retain BSA records for 5 years (31 CFR 1010.430).
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.retention_years == 5
    
    def test_timestamp_timezone_aware(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that timestamps are timezone-aware.
        Compliance: Record all transactions with timestamp.
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.timestamp.tzinfo is not None
        assert audit_call.timestamp.tzinfo == timezone.utc
    
    def test_device_and_ip_captured(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_account: Account,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that device info and IP address are captured.
        Compliance: Store user ID, IP address, device info.
        """
        # Arrange
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = valid_account
        mock_account_repo.update_balance.return_value = True
        mock_ofac_service.screen.return_value = {"match_score": 0, "matches": []}
        
        # Act
        result = transaction_service.execute_transaction(valid_transaction_request)
        
        # Assert
        audit_call = mock_audit_logger.log.call_args[0][0]
        assert audit_call.ip_address == "192.168.1.1"
        assert audit_call.device_info == "Mozilla/5.0"


class TestDecimalPrecision:
    """Test decimal precision for currency handling."""
    
    def test_decimal_precision_maintained(
        self,
        transaction_service: TransactionService,
        mock_account_repo: Mock,
        mock_ofac_service: Mock,
        mock_audit_logger: Mock,
        valid_transaction_request: TransactionRequest
    ):
        """
        Test that decimal precision is maintained for currency.
        Compliance: SOX compliance for financial reporting.
        """
        # Arrange
        account = Account(
            account_number="1234567890",
            routing_number="021000021",
            balance=Decimal("1000.99"),
            user_id="USER123"
        )
        valid_transaction_request.amount = Decimal("100.50")
        mock_account_repo.validate_beneficiary.return_value = True
        mock_account_repo.get_account.return_value = account
        mock_account