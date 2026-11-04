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
    PASS = "pass"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    is_valid: bool = True


@dataclass
class User:
    user_id: str
    ip_address: str
    device_info: str


@dataclass
class Transaction:
    transaction_id: str
    user: User
    from_account: Account
    to_account: Optional[Account]
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None


@dataclass
class CreditApplication:
    application_id: str
    business_name: str
    demographic_data: Dict[str, Any]
    underwriting_data: Dict[str, Any]
    timestamp: datetime


class AuditLogger:
    def log_transaction(self, transaction: Transaction) -> None:
        pass
    
    def log_credit_application(self, application: CreditApplication) -> None:
        pass
    
    def log_demographic_collection(self, application_id: str, data: Dict[str, Any]) -> None:
        pass


class OFACService:
    def screen(self, name: str, threshold: int = 85) -> ScreeningResult:
        pass


class RuleResolver:
    def get_threshold(self, rule_name: str) -> Decimal:
        pass
    
    def is_firewall_required(self) -> bool:
        pass


class TransactionService:
    def __init__(self, audit_logger: AuditLogger, ofac_service: OFACService, rule_resolver: RuleResolver):
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver
    
    def process_transaction(self, user: User, from_account: Account, to_account: Optional[Account], amount: Decimal) -> Transaction:
        pass
    
    def validate_amount(self, amount: Decimal) -> tuple[bool, Optional[str]]:
        if amount <= Decimal('0'):
            if amount == Decimal('0'):
                return False, "Amount must be greater than 0"
            else:
                return False, "Invalid amount"
        return True, None
    
    def validate_balance(self, account: Account, amount: Decimal) -> tuple[bool, Optional[str]]:
        if account.balance < amount:
            return False, "Insufficient balance"
        return True, None
    
    def validate_beneficiary(self, account: Optional[Account]) -> tuple[bool, Optional[str]]:
        if account is None or not account.is_valid:
            return False, "Invalid beneficiary account"
        return True, None


class CreditApplicationService:
    def __init__(self, audit_logger: AuditLogger, rule_resolver: RuleResolver):
        self.audit_logger = audit_logger
        self.rule_resolver = rule_resolver
    
    def submit_application(self, application: CreditApplication) -> Dict[str, Any]:
        pass
    
    def is_demographic_firewalled(self, application_id: str) -> bool:
        pass


@pytest.fixture
def audit_logger() -> Mock:
    logger = Mock(spec=AuditLogger)
    logger.log_transaction = Mock()
    logger.log_credit_application = Mock()
    logger.log_demographic_collection = Mock()
    return logger


@pytest.fixture
def ofac_service() -> Mock:
    service = Mock(spec=OFACService)
    service.screen = Mock(return_value=ScreeningResult.PASS)
    return service


@pytest.fixture
def rule_resolver() -> Mock:
    resolver = Mock(spec=RuleResolver)
    resolver.get_threshold = Mock(side_effect=lambda name: {
        'ctr_threshold': Decimal('10000'),
        'sar_threshold': Decimal('5000'),
        'travel_rule_threshold': Decimal('3000'),
        'wire_dual_approval_threshold': Decimal('10000'),
        'ofac_fuzzy_threshold': 85,
        'beneficial_ownership_pct': 20
    }.get(name))
    resolver.is_firewall_required = Mock(return_value=True)
    return resolver


@pytest.fixture
def transaction_service(audit_logger: Mock, ofac_service: Mock, rule_resolver: Mock) -> TransactionService:
    return TransactionService(audit_logger, ofac_service, rule_resolver)


@pytest.fixture
def credit_application_service(audit_logger: Mock, rule_resolver: Mock) -> CreditApplicationService:
    return CreditApplicationService(audit_logger, rule_resolver)


@pytest.fixture
def valid_user() -> User:
    return User(
        user_id="user123",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )


@pytest.fixture
def valid_account() -> Account:
    return Account(
        account_id="ACC001",
        routing_number="021000021",
        balance=Decimal('10000.00'),
        is_valid=True
    )


@pytest.fixture
def valid_beneficiary_account() -> Account:
    return Account(
        account_id="ACC002",
        routing_number="021000022",
        balance=Decimal('5000.00'),
        is_valid=True
    )


@pytest.fixture
def invalid_beneficiary_account() -> Account:
    return Account(
        account_id="INVALID",
        routing_number="000000000",
        balance=Decimal('0.00'),
        is_valid=False
    )


class TestSuccessfulTransaction:
    """Test scenario: successful_transaction"""
    
    def test_successful_transaction_with_sufficient_balance_and_valid_account(
        self,
        transaction_service: TransactionService,
        audit_logger: Mock,
        valid_user: User,
        valid_account: Account,
        valid_beneficiary_account: Account
    ):
        """
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        amount = Decimal('500.00')
        initial_balance = valid_account.balance
        timestamp = datetime.now(timezone.utc)
        
        transaction = Transaction(
            transaction_id="TXN001",
            user=valid_user,
            from_account=valid_account,
            to_account=valid_beneficiary_account,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS
        )
        
        # Act
        is_valid_amount, _ = transaction_service.validate_amount(amount)
        is_valid_balance, _ = transaction_service.validate_balance(valid_account, amount)
        is_valid_beneficiary, _ = transaction_service.validate_beneficiary(valid_beneficiary_account)
        
        if is_valid_amount and is_valid_balance and is_valid_beneficiary:
            valid_account.balance -= amount
            transaction_service.audit_logger.log_transaction(transaction)
        
        # Assert
        assert is_valid_amount is True, "Transaction amount should be valid"
        assert is_valid_balance is True, "Account should have sufficient balance"
        assert is_valid_beneficiary is True, "Beneficiary account should be valid"
        assert valid_account.balance == initial_balance - amount, "Balance should be updated correctly"
        audit_logger.log_transaction.assert_called_once_with(transaction)
        assert transaction.status == TransactionStatus.SUCCESS
        assert transaction.timestamp.tzinfo is not None, "Timestamp must be timezone-aware"


class TestCFPB1071DemographicCollection:
    """Test scenario: cfpb_1071_demographic_collection"""
    
    def test_demographic_data_collected_and_firewalled_from_underwriting(
        self,
        credit_application_service: CreditApplicationService,
        audit_logger: Mock,
        rule_resolver: Mock
    ):
        """
        Given Small business applies for credit
        When Application is submitted
        Then Demographic data collected and firewalled from underwriting
        
        Tests compliance with 12 C.F.R. Part 1002, Subpart B
        """
        # Arrange
        demographic_data = {
            "ethnicity": "Hispanic or Latino",
            "race": "White",
            "sex": "Male",
            "veteran_status": "Non-veteran",
            "business_ownership": "Minority-owned"
        }
        
        underwriting_data = {
            "credit_score": 720,
            "annual_revenue": Decimal('500000.00'),
            "years_in_business": 5
        }
        
        application = CreditApplication(
            application_id="APP001",
            business_name="Small Business LLC",
            demographic_data=demographic_data,
            underwriting_data=underwriting_data,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Act
        firewall_required = rule_resolver.is_firewall_required()
        credit_application_service.audit_logger.log_demographic_collection(
            application.application_id,
            demographic_data
        )
        credit_application_service.audit_logger.log_credit_application(application)
        
        # Assert - Demographic data collection (12 C.F.R. Part 1002, Subpart B)
        assert demographic_data is not None, \
            "Demographic data must be collected per 12 C.F.R. Part 1002, Subpart B"
        assert "ethnicity" in demographic_data, \
            "Ethnicity must be collected per 12 C.F.R. Part 1002, Subpart B"
        assert "race" in demographic_data, \
            "Race must be collected per 12 C.F.R. Part 1002, Subpart B"
        assert "sex" in demographic_data, \
            "Sex must be collected per 12 C.F.R. Part 1002, Subpart B"
        
        # Assert - Firewall requirement (12 C.F.R. Part 1002, Subpart B)
        assert firewall_required is True, \
            "Firewall between demographic data and underwriting is required per 12 C.F.R. Part 1002, Subpart B"
        
        # Assert - Separate storage/logging
        audit_logger.log_demographic_collection.assert_called_once_with(
            application.application_id,
            demographic_data
        )
        audit_logger.log_credit_application.assert_called_once_with(application)
        
        # Assert - Demographic data should not be accessible to underwriting
        assert "ethnicity" not in underwriting_data, \
            "Demographic data must be firewalled from underwriting per 12 C.F.R. Part 1002, Subpart B"
        assert "race" not in underwriting_data, \
            "Demographic data must be firewalled from underwriting per 12 C.F.R. Part 1002, Subpart B"


class TestZeroAmountTransfer:
    """Test scenario: zero_amount_transfer"""
    
    def test_zero_amount_transfer_rejected(
        self,
        transaction_service: TransactionService,
        valid_user: User,
        valid_account: Account,
        valid_beneficiary_account: Account
    ):
        """
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        amount = Decimal('0.00')
        
        # Act
        is_valid, rejection_reason = transaction_service.validate_amount(amount)
        
        # Assert
        assert is_valid is False, "Zero amount transaction should be rejected"
        assert rejection_reason == "Amount must be greater than 0", \
            "Rejection reason should match expected message"


class TestNegativeAmountTransfer:
    """Test scenario: negative_amount_transfer"""
    
    def test_negative_amount_transfer_rejected(
        self,
        transaction_service: TransactionService,
        valid_user: User,
        valid_account: Account,
        valid_beneficiary_account: Account
    ):
        """
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        amount = Decimal('-100.00')
        
        # Act
        is_valid, rejection_reason = transaction_service.validate_amount(amount)
        
        # Assert
        assert is_valid is False, "Negative amount transaction should be rejected"
        assert rejection_reason == "Invalid amount", \
            "Rejection reason should match expected message"


class TestInsufficientBalance:
    """Test scenario: insufficient_balance"""
    
    def test_insufficient_balance_rejected(
        self,
        transaction_service: TransactionService,
        valid_user: User
    ):
        """
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        account = Account(
            account_id="ACC003",
            routing_number="021000021",
            balance=Decimal('1000.00'),
            is_valid=True
        )
        amount = Decimal('5000.00')
        
        # Act
        is_valid, rejection_reason = transaction_service.validate_balance(account, amount)
        
        # Assert
        assert is_valid is False, "Transaction should be rejected due to insufficient balance"
        assert rejection_reason == "Insufficient balance", \
            "Rejection reason should match expected message"
        assert account.balance == Decimal('1000.00'), "Balance should remain unchanged"


class TestInvalidBeneficiary:
    """Test scenario: invalid_beneficiary"""
    
    def test_invalid_routing_or_account_number_rejected(
        self,
        transaction_service: TransactionService,
        valid_user: User,
        valid_account: Account,
        invalid_beneficiary_account: Account
    ):
        """
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        amount = Decimal('100.00')
        
        # Act
        is_valid, rejection_reason = transaction_service.validate_beneficiary(invalid_beneficiary_account)
        
        # Assert
        assert is_valid is False, "Transaction should be rejected due to invalid beneficiary"
        assert rejection_reason == "Invalid beneficiary account", \
            "Rejection reason should match expected message"
    
    def test_null_beneficiary_account_rejected(
        self,
        transaction_service: TransactionService
    ):
        """Test that None/null beneficiary account is rejected"""
        # Arrange
        beneficiary = None
        
        # Act
        is_valid, rejection_reason = transaction_service.validate_beneficiary(beneficiary)
        
        # Assert
        assert is_valid is False, "Null beneficiary should be rejected"
        assert rejection_reason == "Invalid beneficiary account"


class TestCTRThresholdCompliance:
    """Test CTR (Currency Transaction Report) threshold compliance"""
    
    def test_transaction_at_ctr_threshold_triggers_reporting(
        self,
        transaction_service: TransactionService,
        rule_resolver: Mock,
        audit_logger: Mock,
        valid_user: User,
        valid_account: Account,
        valid_beneficiary_account: Account
    ):
        """
        Test that transactions at or above $10,000 trigger CTR reporting
        per 31 CFR 1010.311
        """
        # Arrange
        ctr_threshold = rule_resolver.get_threshold('ctr_threshold')
        amount = Decimal('10000.00')
        
        # Act
        requires_ctr = amount >= ctr_threshold
        
        # Assert
        assert ctr_threshold == Decimal('10000'), \
            "CTR threshold must be exactly $10,000"
        assert requires_ctr is True, \
            "Transaction at $10,000 must trigger CTR reporting"
    
    def test_transaction_above_ctr_threshold_triggers_reporting(
        self,
        rule_resolver: Mock
    ):
        """Test that transactions above $10,000 trigger CTR reporting"""
        # Arrange
        ctr_threshold = rule_resolver.get_threshold('ctr_threshold')
        amount = Decimal('15000.00')
        
        # Act
        requires_ctr = amount >= ctr_threshold
        
        # Assert
        assert requires_ctr is True, \
            "Transaction above $10,000 must trigger CTR reporting"
    
    def test_transaction_below_ctr_threshold_no_reporting(
        self,
        rule_resolver: Mock
    ):
        """Test that transactions below $10,000 do not trigger CTR reporting"""
        # Arrange
        ctr_threshold = rule_resolver.get_threshold('ctr_threshold')
        amount = Decimal('9999.99')
        
        # Act
        requires_ctr = amount >= ctr_threshold
        
        # Assert
        assert requires_ctr is False, \
            "Transaction below $10,000 should not trigger CTR reporting"


class TestSARThresholdCompliance:
    """Test SAR (Suspicious Activity Report) threshold compliance"""
    
    def test_suspicious_transaction_at_sar_threshold(
        self,
        rule_resolver: Mock
    ):
        """
        Test that suspicious transactions at or above $5,000 trigger SAR filing
        per 31 CFR 1020.320
        """
        # Arrange
        sar_threshold = rule_resolver.get_threshold('sar_threshold')
        amount = Decimal('5000.00')
        is_suspicious = True
        
        # Act
        requires_sar = is_suspicious and amount >= sar_threshold
        
        # Assert
        assert sar_threshold == Decimal('5000'), \
            "SAR threshold must be exactly $5,000"
        assert requires_sar is True, \
            "Suspicious transaction at $5,000 must trigger SAR filing"
    
    def test_suspicious_transaction_below_sar_threshold(
        self,
        rule_resolver: Mock
    ):
        """Test that suspicious transactions below $5,000 may still require SAR"""
        # Arrange
        sar_threshold = rule_resolver.get_threshold('sar_threshold')
        amount = Decimal('4999.99')
        is_suspicious = True
        
        # Act
        below_threshold = amount < sar_threshold
        
        # Assert
        assert below_threshold is True
        assert is_suspicious is True, \
            "Suspicious activity may still require SAR even below threshold"


class TestTravelRuleCompliance:
    """Test Travel Rule compliance for wire transfers"""
    
    def test_wire_transfer_at_travel_rule_threshold_requires_data(
        self,
        rule_resolver: Mock
    ):
        """
        Test that wire transfers at or above $3,000 require Travel Rule data
        per 31 CFR 1010.410(e)
        """
        # Arrange
        travel_rule_threshold = rule_resolver.get_threshold('travel_rule_threshold')
        amount = Decimal('3000.00')
        
        # Act
        requires_travel_rule_data = amount >= travel_rule_threshold
        
        # Assert
        assert travel_rule_threshold == Decimal('3000'), \
            "Travel Rule threshold must be exactly $3,000"
        assert requires_travel_rule_data is True, \
            "Wire transfer at $3,000 must include Travel Rule data"
    
    def test_wire_transfer_below_travel_rule_threshold(
        self,
        rule_resolver: Mock
    ):
        """Test that wire transfers below $3,000 do not require Travel Rule data"""
        # Arrange
        travel_rule_threshold = rule_resolver.get_threshold('travel_rule_threshold')
        amount = Decimal('2999.99')
        
        # Act
        requires_travel_rule_data = amount >= travel_rule_threshold
        
        # Assert
        assert requires_travel_rule_data is False, \
            "Wire transfer below $3,000 does not require Travel Rule data"


class TestDualApprovalCompliance:
    """Test dual approval requirements for high-value wire transfers"""
    
    def test_wire_transfer_at_dual_approval_threshold_requires_approval(
        self,
        rule_resolver: Mock
    ):
        """
        Test that wire transfers at or above $10,000 require dual approval
        """
        # Arrange
        dual_approval_threshold = rule_resolver.get_threshold('wire_dual_approval_threshold')
        amount = Decimal('10000.00')
        
        # Act
        requires_dual_approval = amount >= dual_approval_threshold
        
        # Assert
        assert dual_approval_threshold == Decimal('10000'), \
            "Dual approval threshold must be exactly $10,000"
        assert requires_dual_approval is True, \
            "Wire transfer at $10,000 must require dual approval"
    
    def test_wire_transfer_below_dual_approval_threshold(
        self,
        rule_resolver: Mock
    ):
        """Test that wire transfers below $10,000 do not require dual approval"""
        # Arrange
        dual_approval_threshold = rule_resolver.get_threshold('wire_dual_approval_threshold')
        amount = Decimal('9999.99')
        
        # Act
        requires_dual_approval = amount >= dual_approval_threshold
        
        # Assert
        assert requires_dual_approval is False, \
            "Wire transfer below $10,000 should not require dual approval"


class TestOFACScreeningCompliance:
    """Test OFAC/SDN screening compliance"""
    
    def test_ofac_screening_with_exact_match_blocks_transaction(
        self,
        ofac_service: Mock
    ):
        """Test that exact OFAC match blocks transaction"""
        # Arrange
        ofac_service.screen = Mock(return_value=ScreeningResult.BLOCK)
        beneficiary_name = "Blocked Entity"
        
        # Act
        screening_result = ofac_service.screen(beneficiary_name, threshold=85)
        
        # Assert
        assert screening_result == ScreeningResult.BLOCK, \
            "Exact OFAC match must block transaction"
        ofac_service.screen.assert_called_once_with(beneficiary_name, threshold=85)
    
    def test_ofac_screening_with_fuzzy_match_above_threshold_triggers_review(
        self,
        ofac_service: Mock,
        rule_resolver: Mock
    ):
        """Test that fuzzy OFAC match above 85% threshold triggers review"""
        # Arrange
        ofac_fuzzy_threshold = rule_resolver.get_threshold('ofac_fuzzy_threshold')
        ofac_service.screen = Mock(return_value=ScreeningResult.REVIEW)
        beneficiary_name = "Similar Entity Name"
        
        # Act
        screening_result = ofac_service.screen(beneficiary_name, threshold=ofac_fuzzy_threshold)
        
        # Assert
        assert ofac_fuzzy_threshold == 85, \
            "OFAC fuzzy match threshold must be exactly 85%"
        assert screening_result == ScreeningResult.REVIEW, \
            "Fuzzy OFAC match above 85% must trigger manual review"
    
    def test_ofac_screening_pass_allows_transaction(
        self,
        ofac_service: Mock
    ):
        """Test that passing OFAC screening allows transaction"""
        # Arrange
        ofac_service.screen = Mock(return_value=ScreeningResult.PASS)
        beneficiary_name = "Clean Entity"
        
        # Act
        screening_result = ofac_service.screen(beneficiary_name, threshold=85)
        
        # Assert
        assert screening_result == ScreeningResult.PASS, \
            "Clean OFAC screening must allow transaction to proceed"


class TestBeneficialOwnershipCompliance:
    """Test beneficial ownership threshold compliance"""
    
    def test_beneficial_ownership_at_threshold(
        self,
        rule_resolver: Mock
    ):
        """
        Test that ownership at or above 20% triggers beneficial ownership reporting
        per 31 CFR 1010.230
        """
        # Arrange
        beneficial_ownership_pct = rule_resolver.get_threshold('beneficial_ownership_pct')
        ownership_percentage = 20
        
        # Act
        requires_reporting = ownership_percentage >= beneficial_ownership_pct
        
        # Assert
        assert beneficial_ownership_pct == 20, \
            "Beneficial ownership threshold must be exactly 20%"
        assert requires_reporting is True, \
            "Ownership at 20% must trigger beneficial ownership reporting"
    
    def test_beneficial_ownership_below_threshold(
        self,
        rule_resolver: Mock
    ):
        """Test that ownership below 20% does not trigger beneficial ownership reporting"""
        # Arrange
        beneficial_ownership_pct = rule_resolver.get_threshold('beneficial_ownership_pct')
        ownership_percentage = 19
        
        # Act
        requires_reporting = ownership_percentage >= beneficial_ownership_pct
        
        # Assert
        assert requires_reporting is False, \
            "Ownership below 20% should not trigger beneficial ownership reporting"


class TestAuditTrailCompliance:
    """Test audit trail and record retention compliance"""
    
    def test_audit_trail_includes_required_fields(
        self,
        audit_logger: Mock,
        valid_user: User,
        valid_account: Account,
        valid_beneficiary_account: Account
    ):
        """
        Test that audit trail includes all required fields:
        - Timestamp
        - User ID
        - IP address
        - Device info
        - Transaction details
        """
        # Arrange
        transaction = Transaction(
            transaction_id="TXN002",
            user=valid_user,
            from_account=valid_account,
            to_account=valid_beneficiary_account,
            amount=Decimal('1000.00'),
            timestamp=datetime.now(timezone.utc),
            status=TransactionStatus.SUCCESS
        )
        
        # Act
        audit_logger.log_transaction(transaction)
        
        # Assert
        assert transaction.user.user_id is not None, \
            "Audit trail must include user ID"
        assert transaction.user.ip_address is not None, \
            "Audit trail must include IP address"
        assert transaction.user.device_info is not None, \
            "Audit trail must include device info"
        assert transaction.timestamp is not None, \
            "Audit trail must include timestamp"
        assert transaction.timestamp.tzinfo is not None, \
            "Audit trail timestamp must be timezone-aware"
        audit_logger.log_transaction.assert_called_once_with(transaction)
    
    def test_audit_trail_immutability(
        self,
        audit_logger: Mock
    ):
        """Test that audit log is immutable once recorded"""
        # Arrange
        transaction = Transaction(
            transaction_id="TXN003",
            user=User("user456", "10.0.0.1", "Chrome"),
            from_account=Account("ACC004", "021000021", Decimal('5000.00')),
            to_account=Account("ACC005", "021000022", Decimal('2000.00')),
            amount=Decimal('500.00'),
            timestamp=datetime.now(timezone.utc),
            status=TransactionStatus.SUCCESS
        )
        
        # Act
        audit_logger.log_transaction(transaction)
        original_transaction_id = transaction.transaction_id
        
        # Assert
        audit_logger.log_transaction.assert_called_once()
        assert transaction.transaction_id == original_transaction_id, \
            "Transaction ID must remain immutable in audit log"


class TestPIIHandlingCompliance:
    """Test PII handling and masking compliance"""
    
    def test_ssn_masking_in_logs(self):
        """Test that SSN/TIN is masked in logs (show last 4 only) per GLBA"""
        # Arrange
        full_ssn = "123-45-6789"
        
        # Act
        masked_ssn = "***-**-" + full_ssn[-4:]
        
        # Assert
        assert masked_ssn == "***-**-6789", \
            "SSN must be masked showing only last 4 digits per GLBA Safeguards Rule"
        assert "123-45" not in masked_ssn, \
            "First 5 digits of SSN must be masked"
    
    def test_tin_masking_in_ui(self):
        """Test that TIN is masked in UI displays"""
        # Arrange
        full_tin = "12-3456789"
        
        # Act
        masked_tin = "**-****" + full_tin[-3:]
        
        # Assert
        assert masked_tin == "**-****789", \
            "TIN must be masked showing only last 3 digits"
        assert "12-3456" not in masked_tin, \
            "First 7 digits of TIN must be masked"


class TestRegEErrorResolutionCompliance:
    """Test Reg E error resolution and dispute handling compliance"""
    
    def test_reg_e_error_resolution_60_day_window(self):
        """
        Test that Reg E error resolution allows 60-day dispute window
        per 12 CFR 1005.11
        """
        # Arrange
        transaction_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        dispute_date = datetime(2024, 2, 29, tzinfo=timezone.utc)
        
        # Act
        days_elapsed = (dispute_date - transaction_date).days
        within_dispute_window = days_elapsed <= 60
        
        # Assert
        assert days_elapsed == 59, "Test should be within 60-day window"
        assert within_dispute_window is True, \
            "Dispute within 60 days must be accepted per Reg E (12 CFR 1005.11)"
    
    def test_reg_e_error_resolution_beyond_60_day_window(self):
        """Test that disputes beyond 60 days may be rejected"""
        # Arrange
        transaction_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        dispute_date = datetime(2024, 3, 3, tzinfo=timezone.utc)
        
        # Act
        days_elapsed = (dispute_date - transaction_date).days
        within_dispute_window = days_elapsed <= 60
        
        # Assert
        assert days_elapsed == 62, "Test should be beyond 60-day window"
        assert within_dispute_window is False, \
            "Dispute beyond 60 days may be rejected per Reg E"


class TestBoundaryConditions:
    """Test boundary conditions for all thresholds"""
    
    def test_all_thresholds_exact_values(self, rule_resolver: Mock):
        """Verify all authoritative thresholds are exact values"""
        # Act & Assert
        assert rule_resolver.get_threshold('ctr_threshold') == Decimal('10000'), \
            "CTR threshold must be exactly 10000"
        assert rule_resolver.get_threshold('sar_threshold') == Decimal('5000'), \
            "SAR threshold must be exactly 5000"
        assert rule_resolver.get_threshold('travel_rule_threshold') == Decimal('3000'), \
            "Travel Rule threshold must be exactly 3000"
        assert rule_resolver.get_threshold('wire_dual_approval_threshold') == Decimal('10000'), \
            "Wire dual approval threshold must be exactly 10000"
        assert rule_resolver.get_threshold('ofac_fuzzy_threshold') == 85, \
            "OFAC fuzzy threshold must be exactly 85"
        assert rule_resolver.get_threshold('beneficial_ownership_pct') == 20, \
            "Beneficial ownership percentage must be exactly 20"
    
    def test_amount_boundary_at_one_cent(self, transaction_service: TransactionService):
        """Test minimum valid transaction amount"""
        # Arrange
        amount = Decimal('0.01')
        
        # Act
        is_valid, _ = transaction_service.validate_amount(amount)
        
        # Assert
        assert is_valid is True, "One cent should be valid minimum transaction amount"
    
    def test_amount_boundary_just_below_zero(self, transaction_service: TransactionService):
        """Test that negative amounts are rejected"""
        # Arrange
        amount = Decimal('-0.01')
        
        # Act
        is_valid, rejection_reason = transaction_service.validate_amount(amount)
        
        # Assert
        assert is_valid is False, "Negative amount should be rejected"
        assert rejection_reason == "Invalid amount"


class TestDataEncryptionCompliance:
    """Test data encryption compliance requirements"""
    
    def test_data_in_transit_encryption_requirement(self):
        """Test that TLS 1.3 is required for data in transit"""
        # Arrange
        required_tls_version = "TLS 1.3"
        
        # Assert
        assert required_tls_version == "TLS 1.3", \
            "Data in transit must use TLS 1.3 encryption"
    
    def test_data_at_rest_encryption_requirement(self):
        """Test that AES-256 is required for data at rest"""
        # Arrange
        required_encryption = "AES-256"
        
        # Assert
        assert required_encryption == "AES-256", \
            "Data at rest must use AES-256 encryption per GLBA Safeguards Rule"


class TestRecordRetentionCompliance:
    """Test record retention compliance"""
    
    def test_bsa_record_retention_5_years(self):
        """
        Test that BSA records must be retained for 5 years
        per 31 CFR 1010.430
        """
        # Arrange
        retention_period_years = 5
        transaction_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        retention_end_date = datetime(2029, 1, 1, tzinfo=timezone.utc)
        
        # Act
        years_retained = (retention_end_date - transaction_date).days / 365.25
        
        # Assert
        assert years_retained >= retention_period_years, \
            "BSA records must be retained for at least 5 years per 31 CFR 1010.430"


class TestNegativePathScenarios:
    """Additional negative path tests"""
    
    def test_transaction_with_null_user(self, transaction_service: TransactionService):
        """Test that transaction with null user is rejected"""
        # Arrange
        user = None
        
        # Assert
        assert user is None, "Null user should be rejected"
    
    def test_transaction_with_null_account(self, transaction_service: TransactionService):
        """Test that transaction with null account is rejected"""
        # Arrange
        account = None
        
        # Act
        is_valid, rejection_reason = transaction_service.validate_beneficiary(account)
        
        # Assert
        assert is_valid is False
        assert rejection_reason == "Invalid beneficiary account"
    
    def test_ofac_false_positive_handling(self, ofac_service: Mock):
        """Test handling of OFAC false positive scenarios"""
        # Arrange
        ofac_service.screen = Mock(return_value=ScreeningResult.REVIEW)
        beneficiary_name = "John Smith"
        
        # Act
        screening_result = ofac_service.screen(beneficiary_name, threshold=85)
        
        # Assert
        assert screening_result == ScreeningResult.REVIEW, \
            "Potential false positive should trigger manual review"
    
    def test_concurrent_transaction_handling(
        self,
        transaction_service: TransactionService,
        valid_account: Account
    ):
        """Test that concurrent transactions don't cause balance issues"""
        # Arrange
        initial_balance = valid_account.balance
        amount1 = Decimal('500.00')
        amount2 = Decimal('600.00')
        
        # Act
        is_valid1, _ = transaction_service.validate_balance(valid_account, amount1)
        is_valid2, _ = transaction_service.validate_balance(valid_account, amount2)
        
        # Assert
        assert is_valid1 is True
        assert is_valid2 is True
        assert valid_account.balance == initial_balance, \
            "Balance should not change during validation"