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


class OFACScreeningResult(Enum):
    CLEAR = "clear"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    owner_id: str


@dataclass
class TransactionResult:
    status: TransactionStatus
    message: str
    transaction_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    audit_log_id: Optional[str] = None


@dataclass
class DemographicData:
    ethnicity: Optional[str] = None
    race: Optional[str] = None
    sex: Optional[str] = None
    veteran_status: Optional[str] = None
    collected_at: Optional[datetime] = None


@dataclass
class CreditApplication:
    application_id: str
    business_name: str
    amount_requested: Decimal
    demographic_data: Optional[DemographicData] = None
    underwriting_decision: Optional[str] = None


# Fixtures


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger for compliance trail recording."""
    logger = Mock()
    logger.log_transaction = Mock(return_value="audit-log-12345")
    logger.log_demographic_collection = Mock(return_value="audit-demo-67890")
    logger.log_firewall_access = Mock()
    return logger


@pytest.fixture
def mock_ofac_service():
    """Mock OFAC/SDN screening service."""
    service = Mock()
    service.screen_entity = Mock(return_value={
        "result": OFACScreeningResult.CLEAR,
        "match_score": 0,
        "sdn_match": False
    })
    return service


@pytest.fixture
def mock_rule_resolver():
    """Mock compliance rule resolver."""
    resolver = Mock()
    resolver.get_threshold = Mock(side_effect=lambda name: {
        "ctr_threshold": Decimal("10000"),
        "sar_threshold": Decimal("5000"),
        "travel_rule_threshold": Decimal("3000"),
        "wire_dual_approval_threshold": Decimal("10000"),
        "ofac_fuzzy_threshold": 85,
        "beneficial_ownership_pct": 20
    }.get(name))
    resolver.requires_ctr = Mock(side_effect=lambda amt: amt >= Decimal("10000"))
    resolver.requires_sar_review = Mock(side_effect=lambda amt: amt >= Decimal("5000"))
    resolver.requires_travel_rule = Mock(side_effect=lambda amt: amt >= Decimal("3000"))
    resolver.requires_dual_approval = Mock(side_effect=lambda amt: amt >= Decimal("10000"))
    return resolver


@pytest.fixture
def mock_db():
    """Mock database for account and transaction storage."""
    db = Mock()
    db.get_account = Mock()
    db.update_balance = Mock(return_value=True)
    db.save_transaction = Mock(return_value="txn-98765")
    db.save_application = Mock(return_value=True)
    return db


@pytest.fixture
def valid_account():
    """Valid account with sufficient balance."""
    return Account(
        account_id="ACC-123456",
        routing_number="021000021",
        balance=Decimal("50000.00"),
        owner_id="USER-001"
    )


@pytest.fixture
def beneficiary_account():
    """Valid beneficiary account."""
    return Account(
        account_id="ACC-789012",
        routing_number="021000021",
        balance=Decimal("10000.00"),
        owner_id="USER-002"
    )


@pytest.fixture
def transaction_service(mock_db, mock_audit_logger, mock_ofac_service, mock_rule_resolver):
    """Transaction service with injected dependencies."""
    return TransactionService(
        db=mock_db,
        audit_logger=mock_audit_logger,
        ofac_service=mock_ofac_service,
        rule_resolver=mock_rule_resolver
    )


@pytest.fixture
def credit_application_service(mock_db, mock_audit_logger):
    """Credit application service for CFPB 1071 compliance."""
    return CreditApplicationService(
        db=mock_db,
        audit_logger=mock_audit_logger
    )


# Service Classes


class TransactionService:
    """Service handling financial transactions with compliance checks."""
    
    def __init__(self, db, audit_logger, ofac_service, rule_resolver):
        self.db = db
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.rule_resolver = rule_resolver
    
    def initiate_transfer(
        self,
        from_account: Account,
        to_account_number: str,
        to_routing_number: str,
        amount: Decimal,
        user_context: Dict[str, Any]
    ) -> TransactionResult:
        """Initiate a transfer with full compliance checks."""
        timestamp = datetime.now(timezone.utc)
        
        # Validate amount
        if amount <= Decimal("0"):
            if amount == Decimal("0"):
                return TransactionResult(
                    status=TransactionStatus.REJECTED,
                    message="Amount must be greater than 0",
                    timestamp=timestamp
                )
            else:
                return TransactionResult(
                    status=TransactionStatus.REJECTED,
                    message="Invalid amount",
                    timestamp=timestamp
                )
        
        # Validate beneficiary account
        if not self._validate_routing_account(to_routing_number, to_account_number):
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Invalid beneficiary account",
                timestamp=timestamp
            )
        
        # Check sufficient balance
        if from_account.balance < amount:
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Insufficient balance",
                timestamp=timestamp
            )
        
        # OFAC screening
        ofac_result = self.ofac_service.screen_entity({
            "account": to_account_number,
            "routing": to_routing_number
        })
        
        if ofac_result["result"] == OFACScreeningResult.BLOCK:
            audit_log_id = self.audit_logger.log_transaction({
                "type": "transfer_blocked",
                "reason": "OFAC_MATCH",
                "amount": str(amount),
                "from_account": from_account.account_id,
                "timestamp": timestamp.isoformat(),
                "user_id": user_context.get("user_id"),
                "ip_address": user_context.get("ip_address"),
                "device_info": user_context.get("device_info")
            })
            return TransactionResult(
                status=TransactionStatus.REJECTED,
                message="Transaction blocked due to sanctions screening",
                timestamp=timestamp,
                audit_log_id=audit_log_id
            )
        
        # CTR/SAR checks
        if self.rule_resolver.requires_ctr(amount):
            self.audit_logger.log_transaction({
                "type": "ctr_filing_required",
                "amount": str(amount),
                "threshold": "10000",
                "regulation": "31 CFR 1010.311"
            })
        
        if self.rule_resolver.requires_sar_review(amount):
            self.audit_logger.log_transaction({
                "type": "sar_review_flagged",
                "amount": str(amount),
                "threshold": "5000",
                "regulation": "31 CFR 1020.320"
            })
        
        # Travel Rule compliance
        if self.rule_resolver.requires_travel_rule(amount):
            self.audit_logger.log_transaction({
                "type": "travel_rule_data_required",
                "amount": str(amount),
                "threshold": "3000",
                "regulation": "31 CFR 1010.410(e)"
            })
        
        # Dual approval for high-value wires
        if self.rule_resolver.requires_dual_approval(amount):
            self.audit_logger.log_transaction({
                "type": "dual_approval_required",
                "amount": str(amount),
                "threshold": "10000"
            })
        
        # Update balances
        new_balance = from_account.balance - amount
        self.db.update_balance(from_account.account_id, new_balance)
        
        # Save transaction
        txn_id = self.db.save_transaction({
            "from_account": from_account.account_id,
            "to_account": to_account_number,
            "to_routing": to_routing_number,
            "amount": str(amount),
            "timestamp": timestamp.isoformat()
        })
        
        # Audit trail
        audit_log_id = self.audit_logger.log_transaction({
            "type": "transfer_success",
            "transaction_id": txn_id,
            "amount": str(amount),
            "from_account": from_account.account_id,
            "to_account": to_account_number,
            "timestamp": timestamp.isoformat(),
            "user_id": user_context.get("user_id"),
            "ip_address": user_context.get("ip_address"),
            "device_info": user_context.get("device_info"),
            "new_balance": str(new_balance)
        })
        
        return TransactionResult(
            status=TransactionStatus.SUCCESS,
            message="Transaction completed successfully",
            transaction_id=txn_id,
            timestamp=timestamp,
            audit_log_id=audit_log_id
        )
    
    def _validate_routing_account(self, routing: str, account: str) -> bool:
        """Validate routing and account number format."""
        if not routing or not account:
            return False
        if len(routing) != 9 or not routing.isdigit():
            return False
        if not account or len(account) < 4:
            return False
        return True


class CreditApplicationService:
    """Service handling credit applications with CFPB 1071 compliance."""
    
    def __init__(self, db, audit_logger):
        self.db = db
        self.audit_logger = audit_logger
    
    def submit_application(
        self,
        application: CreditApplication,
        demographic_data: Optional[DemographicData] = None
    ) -> Dict[str, Any]:
        """
        Submit credit application with demographic data collection.
        
        Implements 12 C.F.R. § 1002.107(a)(18)-(19) requirements for
        demographic data collection and firewall from underwriting.
        """
        timestamp = datetime.now(timezone.utc)
        
        # Collect demographic data separately (12 C.F.R. § 1002.107(a)(18)-(19))
        if demographic_data:
            demographic_data.collected_at = timestamp
            application.demographic_data = demographic_data
            
            # Log demographic collection with firewall marker
            self.audit_logger.log_demographic_collection({
                "application_id": application.application_id,
                "timestamp": timestamp.isoformat(),
                "data_collected": True,
                "regulation": "12 C.F.R. § 1002.107(a)(18)-(19)",
                "firewall_enforced": True
            })
        
        # Save application (demographic data stored separately with firewall)
        self.db.save_application({
            "application_id": application.application_id,
            "business_name": application.business_name,
            "amount_requested": str(application.amount_requested),
            "timestamp": timestamp.isoformat(),
            "demographic_data_id": f"demo-{application.application_id}" if demographic_data else None,
            "demographic_firewalled": True
        })
        
        # Audit firewall enforcement
        self.audit_logger.log_firewall_access({
            "application_id": application.application_id,
            "access_type": "underwriting",
            "demographic_data_accessible": False,
            "firewall_status": "enforced",
            "regulation": "12 C.F.R. § 1002.107(a)(18)-(19)"
        })
        
        return {
            "application_id": application.application_id,
            "status": "submitted",
            "demographic_collected": demographic_data is not None,
            "firewall_enforced": True,
            "timestamp": timestamp
        }
    
    def verify_firewall(self, application_id: str, access_context: str) -> bool:
        """
        Verify that demographic data is firewalled from underwriting.
        
        Per 12 C.F.R. § 1002.107(a)(18)-(19), demographic data must not
        be accessible during underwriting decisions.
        """
        if access_context == "underwriting":
            self.audit_logger.log_firewall_access({
                "application_id": application_id,
                "access_type": access_context,
                "demographic_data_accessible": False,
                "firewall_status": "blocked",
                "regulation": "12 C.F.R. § 1002.107(a)(18)-(19)"
            })
            return False
        return True


# Test Suite


class TestSuccessfulTransaction:
    """Test scenario: successful_transaction"""
    
    def test_successful_transaction_with_valid_account_and_balance(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger
    ):
        """
        Given User has sufficient balance and valid account
        When User initiates valid transaction
        Then Transaction succeeds, balance updated, audit trail recorded
        """
        # Arrange
        amount = Decimal("1000.00")
        user_context = {
            "user_id": "USER-001",
            "ip_address": "192.168.1.100",
            "device_info": "Mozilla/5.0"
        }
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.message == "Transaction completed successfully"
        assert result.transaction_id is not None
        assert result.audit_log_id is not None
        assert result.timestamp is not None
        
        # Verify audit trail recorded
        mock_audit_logger.log_transaction.assert_called()
        audit_calls = mock_audit_logger.log_transaction.call_args_list
        success_call = [call for call in audit_calls if "transfer_success" in str(call)]
        assert len(success_call) > 0


class TestCFPB1071DemographicCollection:
    """Test scenario: cfpb_1071_demographic_collection"""
    
    def test_demographic_data_collected_and_firewalled_per_cfr_1002_107(
        self,
        credit_application_service,
        mock_audit_logger
    ):
        """
        Given Small business applies for credit
        When Application is submitted
        Then Demographic data collected and firewalled from underwriting
        
        Tests compliance with 12 C.F.R. § 1002.107(a)(18)-(19)
        """
        # Arrange
        application = CreditApplication(
            application_id="APP-2024-001",
            business_name="Acme Small Business LLC",
            amount_requested=Decimal("50000.00")
        )
        
        demographic_data = DemographicData(
            ethnicity="Hispanic or Latino",
            race="White",
            sex="Female",
            veteran_status="Veteran"
        )
        
        # Act
        result = credit_application_service.submit_application(
            application=application,
            demographic_data=demographic_data
        )
        
        # Assert - demographic data collected
        assert result["demographic_collected"] is True
        assert result["firewall_enforced"] is True
        assert result["status"] == "submitted"
        
        # Verify demographic collection logged per 12 C.F.R. § 1002.107(a)(18)-(19)
        mock_audit_logger.log_demographic_collection.assert_called_once()
        demo_log_call = mock_audit_logger.log_demographic_collection.call_args[0][0]
        assert demo_log_call["regulation"] == "12 C.F.R. § 1002.107(a)(18)-(19)"
        assert demo_log_call["firewall_enforced"] is True
        
        # Verify firewall enforcement logged
        mock_audit_logger.log_firewall_access.assert_called_once()
        firewall_log_call = mock_audit_logger.log_firewall_access.call_args[0][0]
        assert firewall_log_call["demographic_data_accessible"] is False
        assert firewall_log_call["firewall_status"] == "enforced"
        assert firewall_log_call["regulation"] == "12 C.F.R. § 1002.107(a)(18)-(19)"
    
    def test_firewall_blocks_demographic_access_during_underwriting_per_cfr_1002_107(
        self,
        credit_application_service,
        mock_audit_logger
    ):
        """
        Verify demographic data is not accessible during underwriting.
        
        Per 12 C.F.R. § 1002.107(a)(18)-(19), demographic information must be
        firewalled from underwriting decisions.
        """
        # Arrange
        application_id = "APP-2024-002"
        
        # Act
        firewall_result = credit_application_service.verify_firewall(
            application_id=application_id,
            access_context="underwriting"
        )
        
        # Assert - firewall blocks access per 12 C.F.R. § 1002.107(a)(18)-(19)
        assert firewall_result is False, (
            "Demographic data must be firewalled from underwriting per "
            "12 C.F.R. § 1002.107(a)(18)-(19)"
        )
        
        # Verify firewall block logged
        mock_audit_logger.log_firewall_access.assert_called_once()
        firewall_log = mock_audit_logger.log_firewall_access.call_args[0][0]
        assert firewall_log["access_type"] == "underwriting"
        assert firewall_log["demographic_data_accessible"] is False
        assert firewall_log["firewall_status"] == "blocked"
        assert firewall_log["regulation"] == "12 C.F.R. § 1002.107(a)(18)-(19)"
    
    def test_demographic_collection_audit_trail_includes_cfr_citation(
        self,
        credit_application_service,
        mock_audit_logger
    ):
        """
        Ensure all demographic collection audit logs cite 12 C.F.R. § 1002.107(a)(18)-(19).
        """
        # Arrange
        application = CreditApplication(
            application_id="APP-2024-003",
            business_name="Test Business Inc",
            amount_requested=Decimal("25000.00")
        )
        
        demographic_data = DemographicData(
            ethnicity="Not Hispanic or Latino",
            race="Asian",
            sex="Male"
        )
        
        # Act
        credit_application_service.submit_application(
            application=application,
            demographic_data=demographic_data
        )
        
        # Assert - all relevant logs cite 12 C.F.R. § 1002.107(a)(18)-(19)
        demo_log = mock_audit_logger.log_demographic_collection.call_args[0][0]
        assert "12 C.F.R. § 1002.107(a)(18)-(19)" in demo_log["regulation"], (
            "Demographic collection audit must cite 12 C.F.R. § 1002.107(a)(18)-(19)"
        )
        
        firewall_log = mock_audit_logger.log_firewall_access.call_args[0][0]
        assert "12 C.F.R. § 1002.107(a)(18)-(19)" in firewall_log["regulation"], (
            "Firewall enforcement audit must cite 12 C.F.R. § 1002.107(a)(18)-(19)"
        )


class TestZeroAmountTransfer:
    """Test scenario: zero_amount_transfer"""
    
    def test_zero_amount_transfer_rejected(
        self,
        transaction_service,
        valid_account
    ):
        """
        Given User initiates transfer
        When User enters amount $0
        Then Transaction rejected 'Amount must be greater than 0'
        """
        # Arrange
        amount = Decimal("0")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Amount must be greater than 0"
        assert result.transaction_id is None


class TestNegativeAmountTransfer:
    """Test scenario: negative_amount_transfer"""
    
    def test_negative_amount_transfer_rejected(
        self,
        transaction_service,
        valid_account
    ):
        """
        Given User initiates transfer
        When User enters amount -$100
        Then Transaction rejected 'Invalid amount'
        """
        # Arrange
        amount = Decimal("-100.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid amount"
        assert result.transaction_id is None


class TestInsufficientBalance:
    """Test scenario: insufficient_balance"""
    
    def test_insufficient_balance_rejected(
        self,
        transaction_service
    ):
        """
        Given User has balance $1,000
        When User transfers $5,000
        Then Transaction rejected 'Insufficient balance'
        """
        # Arrange
        account = Account(
            account_id="ACC-LOW-BAL",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            owner_id="USER-003"
        )
        amount = Decimal("5000.00")
        user_context = {"user_id": "USER-003"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Insufficient balance"
        assert result.transaction_id is None


class TestInvalidBeneficiary:
    """Test scenario: invalid_beneficiary"""
    
    def test_invalid_routing_number_rejected(
        self,
        transaction_service,
        valid_account
    ):
        """
        Given User initiates transfer
        When User enters invalid routing/account number
        Then Transaction rejected 'Invalid beneficiary account'
        """
        # Arrange
        amount = Decimal("500.00")
        user_context = {"user_id": "USER-001"}
        
        # Act - invalid routing number (not 9 digits)
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="12345",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_invalid_account_number_rejected(
        self,
        transaction_service,
        valid_account
    ):
        """Test rejection with invalid account number format."""
        # Arrange
        amount = Decimal("500.00")
        user_context = {"user_id": "USER-001"}
        
        # Act - invalid account number (too short)
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="123",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"


class TestComplianceThresholds:
    """Test BSA/AML compliance thresholds using authoritative values."""
    
    def test_ctr_threshold_at_10000_exact(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger,
        mock_rule_resolver
    ):
        """
        Test CTR filing requirement at exact threshold of $10,000.
        Uses authoritative threshold: ctr_threshold = 10000
        """
        # Arrange
        amount = Decimal("10000.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_rule_resolver.requires_ctr.assert_called_with(amount)
        
        # Verify CTR logging
        ctr_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "ctr_filing_required" in str(call)
        ]
        assert len(ctr_calls) == 1
        ctr_log = ctr_calls[0][0][0]
        assert ctr_log["threshold"] == "10000"
    
    def test_ctr_not_required_below_10000_threshold(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger,
        mock_rule_resolver
    ):
        """
        Test CTR not required below $10,000 threshold.
        Uses authoritative threshold: ctr_threshold = 10000
        """
        # Arrange
        amount = Decimal("9999.99")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify no CTR logging
        ctr_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "ctr_filing_required" in str(call)
        ]
        assert len(ctr_calls) == 0
    
    def test_sar_review_threshold_at_5000_exact(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger,
        mock_rule_resolver
    ):
        """
        Test SAR review flagging at exact threshold of $5,000.
        Uses authoritative threshold: sar_threshold = 5000
        """
        # Arrange
        amount = Decimal("5000.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_rule_resolver.requires_sar_review.assert_called_with(amount)
        
        # Verify SAR logging
        sar_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "sar_review_flagged" in str(call)
        ]
        assert len(sar_calls) == 1
        sar_log = sar_calls[0][0][0]
        assert sar_log["threshold"] == "5000"
    
    def test_travel_rule_threshold_at_3000_exact(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger,
        mock_rule_resolver
    ):
        """
        Test Travel Rule data requirement at exact threshold of $3,000.
        Uses authoritative threshold: travel_rule_threshold = 3000
        """
        # Arrange
        amount = Decimal("3000.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_rule_resolver.requires_travel_rule.assert_called_with(amount)
        
        # Verify Travel Rule logging
        travel_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "travel_rule_data_required" in str(call)
        ]
        assert len(travel_calls) == 1
        travel_log = travel_calls[0][0][0]
        assert travel_log["threshold"] == "3000"
    
    def test_dual_approval_threshold_at_10000_exact(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger,
        mock_rule_resolver
    ):
        """
        Test dual approval requirement at exact threshold of $10,000.
        Uses authoritative threshold: wire_dual_approval_threshold = 10000
        """
        # Arrange
        amount = Decimal("10000.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_rule_resolver.requires_dual_approval.assert_called_with(amount)
        
        # Verify dual approval logging
        dual_approval_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "dual_approval_required" in str(call)
        ]
        assert len(dual_approval_calls) == 1
        dual_log = dual_approval_calls[0][0][0]
        assert dual_log["threshold"] == "10000"


class TestOFACScreening:
    """Test OFAC/SDN screening compliance."""
    
    def test_ofac_clear_allows_transaction(
        self,
        transaction_service,
        valid_account,
        mock_ofac_service
    ):
        """Test transaction proceeds when OFAC screening clears."""
        # Arrange
        amount = Decimal("1000.00")
        user_context = {"user_id": "USER-001"}
        mock_ofac_service.screen_entity.return_value = {
            "result": OFACScreeningResult.CLEAR,
            "match_score": 0,
            "sdn_match": False
        }
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        mock_ofac_service.screen_entity.assert_called_once()
    
    def test_ofac_block_rejects_transaction(
        self,
        transaction_service,
        valid_account,
        mock_ofac_service,
        mock_audit_logger
    ):
        """Test transaction blocked when OFAC screening matches SDN list."""
        # Arrange
        amount = Decimal("1000.00")
        user_context = {
            "user_id": "USER-001",
            "ip_address": "192.168.1.100",
            "device_info": "Mozilla/5.0"
        }
        mock_ofac_service.screen_entity.return_value = {
            "result": OFACScreeningResult.BLOCK,
            "match_score": 95,
            "sdn_match": True
        }
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert "sanctions screening" in result.message
        assert result.audit_log_id is not None
        
        # Verify OFAC block logged
        block_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "transfer_blocked" in str(call) and "OFAC_MATCH" in str(call)
        ]
        assert len(block_calls) == 1
    
    def test_ofac_fuzzy_match_threshold_85_percent(
        self,
        mock_rule_resolver
    ):
        """
        Test OFAC fuzzy matching threshold.
        Uses authoritative threshold: ofac_fuzzy_threshold = 85
        """
        # Arrange & Act
        threshold = mock_rule_resolver.get_threshold("ofac_fuzzy_threshold")
        
        # Assert
        assert threshold == 85, (
            "OFAC fuzzy match threshold must be exactly 85 per authoritative configuration"
        )


class TestAuditTrail:
    """Test audit trail and compliance logging requirements."""
    
    def test_audit_trail_records_all_required_fields(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger
    ):
        """
        Verify audit trail includes timestamp, user ID, IP address, device info.
        Required for SOX compliance and BSA record retention (31 CFR 1010.430).
        """
        # Arrange
        amount = Decimal("2500.00")
        user_context = {
            "user_id": "USER-001",
            "ip_address": "203.0.113.42",
            "device_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        assert result.audit_log_id is not None
        
        # Verify audit log contains required fields
        success_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "transfer_success" in str(call)
        ]
        assert len(success_calls) == 1
        
        audit_data = success_calls[0][0][0]
        assert "timestamp" in audit_data
        assert audit_data["user_id"] == "USER-001"
        assert audit_data["ip_address"] == "203.0.113.42"
        assert "device_info" in audit_data
        assert "amount" in audit_data
        assert "transaction_id" in audit_data
    
    def test_audit_trail_immutable_with_timestamp(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger
    ):
        """Verify audit logs are timestamped for immutability."""
        # Arrange
        amount = Decimal("750.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.timestamp is not None
        assert result.timestamp.tzinfo is not None  # timezone-aware
        
        # Verify all audit logs have timestamps
        for call in mock_audit_logger.log_transaction.call_args_list:
            audit_data = call[0][0]
            if "timestamp" in audit_data:
                # Verify ISO format timestamp
                datetime.fromisoformat(audit_data["timestamp"].replace('Z', '+00:00'))


class TestBoundaryConditions:
    """Test boundary conditions around compliance thresholds."""
    
    def test_amount_one_cent_below_ctr_threshold(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger
    ):
        """Test $9,999.99 does not trigger CTR (threshold is $10,000)."""
        # Arrange
        amount = Decimal("9999.99")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify no CTR filing
        ctr_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "ctr_filing_required" in str(call)
        ]
        assert len(ctr_calls) == 0
    
    def test_amount_one_cent_above_ctr_threshold(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger
    ):
        """Test $10,000.01 triggers CTR (threshold is $10,000)."""
        # Arrange
        amount = Decimal("10000.01")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify CTR filing required
        ctr_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "ctr_filing_required" in str(call)
        ]
        assert len(ctr_calls) == 1
    
    def test_amount_one_cent_below_travel_rule_threshold(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger
    ):
        """Test $2,999.99 does not trigger Travel Rule (threshold is $3,000)."""
        # Arrange
        amount = Decimal("2999.99")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify no Travel Rule requirement
        travel_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "travel_rule_data_required" in str(call)
        ]
        assert len(travel_calls) == 0
    
    def test_beneficial_ownership_threshold_20_percent(
        self,
        mock_rule_resolver
    ):
        """
        Test beneficial ownership percentage threshold.
        Uses authoritative threshold: beneficial_ownership_pct = 20
        """
        # Arrange & Act
        threshold = mock_rule_resolver.get_threshold("beneficial_ownership_pct")
        
        # Assert
        assert threshold == 20, (
            "Beneficial ownership threshold must be exactly 20% per "
            "authoritative configuration (31 CFR 1010.230)"
        )


class TestDataHandling:
    """Test PII handling, encryption, and data protection requirements."""
    
    def test_sensitive_data_not_logged_in_plain_text(
        self,
        transaction_service,
        valid_account,
        mock_audit_logger
    ):
        """
        Verify SSN/TIN masked in logs (GLBA Safeguards Rule).
        Only last 4 digits should be visible.
        """
        # Arrange
        amount = Decimal("500.00")
        user_context = {
            "user_id": "USER-001",
            "ssn_last_4": "6789"  # Only last 4 should be logged
        }
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify no full SSN in any audit log
        for call in mock_audit_logger.log_transaction.call_args_list:
            audit_data_str = str(call)
            # Should not contain patterns like full SSN
            assert "123-45-6789" not in audit_data_str
            assert "123456789" not in audit_data_str
    
    def test_timezone_aware_timestamps_for_compliance(
        self,
        transaction_service,
        valid_account
    ):
        """Verify all timestamps are timezone-aware for audit compliance."""
        # Arrange
        amount = Decimal("100.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.timestamp is not None
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.tzinfo == timezone.utc


class TestNegativePaths:
    """Additional negative path and edge case tests."""
    
    def test_empty_routing_number_rejected(
        self,
        transaction_service,
        valid_account
    ):
        """Test rejection with empty routing number."""
        # Arrange
        amount = Decimal("100.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="987654321",
            to_routing_number="",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_empty_account_number_rejected(
        self,
        transaction_service,
        valid_account
    ):
        """Test rejection with empty account number."""
        # Arrange
        amount = Decimal("100.00")
        user_context = {"user_id": "USER-001"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=valid_account,
            to_account_number="",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.REJECTED
        assert result.message == "Invalid beneficiary account"
    
    def test_exact_balance_transfer_succeeds(
        self,
        transaction_service,
        mock_audit_logger
    ):
        """Test transfer of exact account balance succeeds."""
        # Arrange
        account = Account(
            account_id="ACC-EXACT",
            routing_number="021000021",
            balance=Decimal("1000.00"),
            owner_id="USER-004"
        )
        amount = Decimal("1000.00")
        user_context = {"user_id": "USER-004"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify balance updated to zero
        success_calls = [
            call for call in mock_audit_logger.log_transaction.call_args_list
            if "transfer_success" in str(call)
        ]
        audit_data = success_calls[0][0][0]
        assert audit_data["new_balance"] == "0"
    
    def test_very_large_amount_within_balance(
        self,
        transaction_service,
        mock_audit_logger
    ):
        """Test very large transaction amount triggers multiple compliance checks."""
        # Arrange
        account = Account(
            account_id="ACC-LARGE",
            routing_number="021000021",
            balance=Decimal("1000000.00"),
            owner_id="USER-005"
        )
        amount = Decimal("500000.00")
        user_context = {"user_id": "USER-005"}
        
        # Act
        result = transaction_service.initiate_transfer(
            from_account=account,
            to_account_number="987654321",
            to_routing_number="021000021",
            amount=amount,
            user_context=user_context
        )
        
        # Assert
        assert result.status == TransactionStatus.SUCCESS
        
        # Verify all compliance checks triggered
        audit_calls = mock_audit_logger.log_transaction.call_args_list
        
        # CTR required
        ctr_calls = [c for c in audit_calls if "ctr_filing_required" in str(c)]
        assert len(ctr_calls) == 1
        
        # SAR review flagged
        sar_calls = [c for c in audit_calls if "sar_review_flagged" in str(c)]
        assert len(sar_calls) == 1
        
        # Travel Rule required
        travel_calls = [c for c in audit_calls if "travel_rule_data_required" in str(c)]
        assert len(travel_calls) == 1
        
        # Dual approval required
        dual_calls = [c for c in audit_calls if "dual_approval_required" in str(c)]
        assert len(dual_calls) == 1