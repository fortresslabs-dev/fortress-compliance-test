import pytest
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# Domain Models
# ============================================================================

class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    PENDING_REVIEW = "PENDING_REVIEW"
    BLOCKED = "BLOCKED"


class SARStatus(Enum):
    FILED = "FILED"
    PENDING = "PENDING"
    NOT_REQUIRED = "NOT_REQUIRED"


@dataclass
class Account:
    account_id: str
    balance: Decimal
    routing_number: str
    account_number: str
    customer_id: str
    is_valid: bool = True


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    rejection_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SARFiling:
    sar_id: str
    transaction_id: Optional[str]
    customer_id: str
    amount: Decimal
    reason: str
    filed_date: datetime
    detection_date: datetime
    status: SARStatus
    is_insider_abuse: bool = False
    subject_notified: bool = False


@dataclass
class AMLProgram:
    program_id: str
    has_internal_controls: bool
    has_independent_testing: bool
    has_designated_officer: bool
    has_ongoing_training: bool
    has_risk_based_cdd: bool
    board_approved: bool
    board_approval_date: Optional[datetime]
    is_consistent_with_cip: bool


@dataclass
class CIPPolicy:
    policy_id: str
    is_part_of_aml_program: bool
    is_consistent_with_aml_program: bool
    requires_identity_verification: bool
    requires_beneficial_ownership: bool
    last_updated: datetime


@dataclass
class AuditLogEntry:
    log_id: str
    timestamp: datetime
    user_id: str
    ip_address: str
    device_info: str
    action: str
    transaction_id: Optional[str]
    details: Dict[str, Any]


# ============================================================================
# Service Interfaces
# ============================================================================

class ComplianceRuleResolver:
    """Resolves compliance thresholds and rules."""
    
    # AUTHORITATIVE THRESHOLDS from grounding block
    CTR_THRESHOLD = Decimal("10000")
    SAR_THRESHOLD = Decimal("5000")
    TRAVEL_RULE_THRESHOLD = Decimal("3000")
    WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
    OFAC_FUZZY_THRESHOLD = 85
    BENEFICIAL_OWNERSHIP_PCT = Decimal("20")
    
    SAR_FILING_DEADLINE_DAYS = 30
    SAR_RETENTION_YEARS = 5
    BSA_RETENTION_YEARS = 5
    
    def get_sar_threshold(self) -> Decimal:
        return self.SAR_THRESHOLD
    
    def get_sar_insider_threshold(self) -> Decimal:
        return Decimal("0")
    
    def get_sar_filing_deadline_days(self) -> int:
        return self.SAR_FILING_DEADLINE_DAYS


class OFACScreeningService:
    """Mock OFAC/SDN screening service."""
    
    def screen(self, customer_id: str, name: str) -> Dict[str, Any]:
        return {
            "is_match": False,
            "score": 0,
            "action": "ALLOW"
        }


class AuditLogger:
    """Audit logging service."""
    
    def __init__(self):
        self.logs: List[AuditLogEntry] = []
    
    def log(self, user_id: str, ip_address: str, device_info: str, 
            action: str, transaction_id: Optional[str] = None, 
            details: Optional[Dict[str, Any]] = None) -> AuditLogEntry:
        entry = AuditLogEntry(
            log_id=f"LOG-{len(self.logs) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info,
            action=action,
            transaction_id=transaction_id,
            details=details or {}
        )
        self.logs.append(entry)
        return entry


class TransactionService:
    """Core transaction processing service."""
    
    def __init__(self, rule_resolver: ComplianceRuleResolver, 
                 audit_logger: AuditLogger,
                 ofac_service: OFACScreeningService):
        self.rule_resolver = rule_resolver
        self.audit_logger = audit_logger
        self.ofac_service = ofac_service
        self.accounts: Dict[str, Account] = {}
        self.transactions: List[Transaction] = []
    
    def process_transaction(self, from_account_id: str, to_account_id: str,
                          amount: Decimal, user_id: str, ip_address: str,
                          device_info: str) -> Transaction:
        """Process a transaction with compliance checks."""
        
        # Validate amount
        if amount <= 0:
            rejection_reason = "Amount must be greater than 0" if amount == 0 else "Invalid amount"
            txn = Transaction(
                transaction_id=f"TXN-{len(self.transactions) + 1}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.transactions.append(txn)
            self.audit_logger.log(user_id, ip_address, device_info, 
                                "TRANSACTION_REJECTED", txn.transaction_id,
                                {"reason": rejection_reason})
            return txn
        
        # Validate accounts
        from_account = self.accounts.get(from_account_id)
        to_account = self.accounts.get(to_account_id)
        
        if not from_account or not from_account.is_valid:
            rejection_reason = "Invalid source account"
            txn = Transaction(
                transaction_id=f"TXN-{len(self.transactions) + 1}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.transactions.append(txn)
            self.audit_logger.log(user_id, ip_address, device_info,
                                "TRANSACTION_REJECTED", txn.transaction_id,
                                {"reason": rejection_reason})
            return txn
        
        if not to_account or not to_account.is_valid:
            rejection_reason = "Invalid beneficiary account"
            txn = Transaction(
                transaction_id=f"TXN-{len(self.transactions) + 1}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.transactions.append(txn)
            self.audit_logger.log(user_id, ip_address, device_info,
                                "TRANSACTION_REJECTED", txn.transaction_id,
                                {"reason": rejection_reason})
            return txn
        
        # Check sufficient balance
        if from_account.balance < amount:
            rejection_reason = "Insufficient balance"
            txn = Transaction(
                transaction_id=f"TXN-{len(self.transactions) + 1}",
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=datetime.now(timezone.utc),
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.transactions.append(txn)
            self.audit_logger.log(user_id, ip_address, device_info,
                                "TRANSACTION_REJECTED", txn.transaction_id,
                                {"reason": rejection_reason})
            return txn
        
        # Process successful transaction
        from_account.balance -= amount
        to_account.balance += amount
        
        txn = Transaction(
            transaction_id=f"TXN-{len(self.transactions) + 1}",
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=datetime.now(timezone.utc),
            status=TransactionStatus.SUCCESS
        )
        self.transactions.append(txn)
        self.audit_logger.log(user_id, ip_address, device_info,
                            "TRANSACTION_SUCCESS", txn.transaction_id,
                            {"amount": str(amount), "from": from_account_id, "to": to_account_id})
        return txn


class SARFilingService:
    """SAR filing and management service."""
    
    def __init__(self, rule_resolver: ComplianceRuleResolver):
        self.rule_resolver = rule_resolver
        self.filings: List[SARFiling] = []
        self.customer_sar_map: Dict[str, List[str]] = {}
    
    def should_file_sar(self, amount: Decimal, is_suspicious: bool, 
                       is_insider_abuse: bool) -> bool:
        """Determine if SAR filing is required."""
        if is_insider_abuse:
            return True
        if is_suspicious and amount > self.rule_resolver.get_sar_threshold():
            return True
        return False
    
    def file_sar(self, customer_id: str, amount: Decimal, reason: str,
                detection_date: datetime, is_insider_abuse: bool = False,
                transaction_id: Optional[str] = None) -> SARFiling:
        """File a SAR with FinCEN."""
        filing = SARFiling(
            sar_id=f"SAR-{len(self.filings) + 1}",
            transaction_id=transaction_id,
            customer_id=customer_id,
            amount=amount,
            reason=reason,
            filed_date=datetime.now(timezone.utc),
            detection_date=detection_date,
            status=SARStatus.FILED,
            is_insider_abuse=is_insider_abuse,
            subject_notified=False
        )
        self.filings.append(filing)
        
        if customer_id not in self.customer_sar_map:
            self.customer_sar_map[customer_id] = []
        self.customer_sar_map[customer_id].append(filing.sar_id)
        
        return filing
    
    def has_sar_for_customer(self, customer_id: str) -> bool:
        """Check if customer has any SAR filings."""
        return customer_id in self.customer_sar_map
    
    def disclose_sar_to_customer(self, customer_id: str) -> bool:
        """MUST return False - no tipping off rule."""
        return False


class AMLComplianceService:
    """AML program and CIP compliance service."""
    
    def __init__(self):
        self.aml_programs: Dict[str, AMLProgram] = {}
        self.cip_policies: Dict[str, CIPPolicy] = {}
    
    def validate_cip_consistency_with_aml(self, aml_program_id: str, 
                                         cip_policy_id: str) -> bool:
        """
        Validate that CIP is part of and consistent with AML program.
        31 C.F.R. § 1010.220(a) requirement.
        """
        aml_program = self.aml_programs.get(aml_program_id)
        cip_policy = self.cip_policies.get(cip_policy_id)
        
        if not aml_program or not cip_policy:
            return False
        
        return (cip_policy.is_part_of_aml_program and 
                cip_policy.is_consistent_with_aml_program and
                aml_program.is_consistent_with_cip)
    
    def create_aml_program(self, program_id: str, has_internal_controls: bool,
                          has_independent_testing: bool, has_designated_officer: bool,
                          has_ongoing_training: bool, has_risk_based_cdd: bool,
                          board_approved: bool, board_approval_date: Optional[datetime],
                          is_consistent_with_cip: bool) -> AMLProgram:
        """Create an AML program."""
        program = AMLProgram(
            program_id=program_id,
            has_internal_controls=has_internal_controls,
            has_independent_testing=has_independent_testing,
            has_designated_officer=has_designated_officer,
            has_ongoing_training=has_ongoing_training,
            has_risk_based_cdd=has_risk_based_cdd,
            board_approved=board_approved,
            board_approval_date=board_approval_date,
            is_consistent_with_cip=is_consistent_with_cip
        )
        self.aml_programs[program_id] = program
        return program
    
    def create_cip_policy(self, policy_id: str, is_part_of_aml_program: bool,
                         is_consistent_with_aml_program: bool,
                         requires_identity_verification: bool,
                         requires_beneficial_ownership: bool) -> CIPPolicy:
        """Create a CIP policy."""
        policy = CIPPolicy(
            policy_id=policy_id,
            is_part_of_aml_program=is_part_of_aml_program,
            is_consistent_with_aml_program=is_consistent_with_aml_program,
            requires_identity_verification=requires_identity_verification,
            requires_beneficial_ownership=requires_beneficial_ownership,
            last_updated=datetime.now(timezone.utc)
        )
        self.cip_policies[policy_id] = policy
        return policy


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def rule_resolver() -> ComplianceRuleResolver:
    """Provide compliance rule resolver."""
    return ComplianceRuleResolver()


@pytest.fixture
def audit_logger() -> AuditLogger:
    """Provide audit logger."""
    return AuditLogger()


@pytest.fixture
def ofac_service() -> OFACScreeningService:
    """Provide OFAC screening service."""
    return OFACScreeningService()


@pytest.fixture
def transaction_service(rule_resolver: ComplianceRuleResolver,
                       audit_logger: AuditLogger,
                       ofac_service: OFACScreeningService) -> TransactionService:
    """Provide transaction service."""
    return TransactionService(rule_resolver, audit_logger, ofac_service)


@pytest.fixture
def sar_filing_service(rule_resolver: ComplianceRuleResolver) -> SARFilingService:
    """Provide SAR filing service."""
    return SARFilingService(rule_resolver)


@pytest.fixture
def aml_compliance_service() -> AMLComplianceService:
    """Provide AML compliance service."""
    return AMLComplianceService()


@pytest.fixture
def valid_account_from() -> Account:
    """Provide valid source account with sufficient balance."""
    return Account(
        account_id="ACC-001",
        balance=Decimal("10000.00"),
        routing_number="021000021",
        account_number="1234567890",
        customer_id="CUST-001",
        is_valid=True
    )


@pytest.fixture
def valid_account_to() -> Account:
    """Provide valid destination account."""
    return Account(
        account_id="ACC-002",
        balance=Decimal("5000.00"),
        routing_number="021000021",
        account_number="0987654321",
        customer_id="CUST-002",
        is_valid=True
    )


@pytest.fixture
def invalid_account() -> Account:
    """Provide invalid account."""
    return Account(
        account_id="ACC-999",
        balance=Decimal("0.00"),
        routing_number="000000000",
        account_number="0000000000",
        customer_id="CUST-999",
        is_valid=False
    )


# ============================================================================
# MUST-TEST OBLIGATION: FINCEN-1010-220-a-R1::OBL::001
# Written CIP must be part of, and consistent with, the institution's AML program
# ============================================================================

def test_cip_must_be_part_of_aml_program(aml_compliance_service: AMLComplianceService):
    """
    Test that CIP is part of and consistent with AML program.
    
    MUST-TEST: FINCEN-1010-220-a-R1::OBL::001
    Citation: 31 C.F.R. § 1010.220(a)
    """
    # Arrange
    aml_program = aml_compliance_service.create_aml_program(
        program_id="AML-001",
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=datetime.now(timezone.utc),
        is_consistent_with_cip=True
    )
    
    cip_policy = aml_compliance_service.create_cip_policy(
        policy_id="CIP-001",
        is_part_of_aml_program=True,
        is_consistent_with_aml_program=True,
        requires_identity_verification=True,
        requires_beneficial_ownership=True
    )
    
    # Act
    is_compliant = aml_compliance_service.validate_cip_consistency_with_aml(
        "AML-001", "CIP-001"
    )
    
    # Assert
    assert is_compliant is True, (
        "CIP must be part of and consistent with AML program per 31 C.F.R. § 1010.220(a)"
    )
    assert cip_policy.is_part_of_aml_program is True, (
        "CIP must be part of AML program per 31 C.F.R. § 1010.220(a)"
    )
    assert cip_policy.is_consistent_with_aml_program is True, (
        "CIP must be consistent with AML program per 31 C.F.R. § 1010.220(a)"
    )
    assert aml_program.is_consistent_with_cip is True, (
        "AML program must be consistent with CIP per 31 C.F.R. § 1010.220(a)"
    )


def test_cip_not_part_of_aml_program_fails_compliance(
    aml_compliance_service: AMLComplianceService
):
    """
    Test that CIP not part of AML program fails compliance.
    
    MUST-TEST: FINCEN-1010-220-a-R1::OBL::001 (negative case)
    Citation: 31 C.F.R. § 1010.220(a)
    """
    # Arrange
    aml_program = aml_compliance_service.create_aml_program(
        program_id="AML-002",
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=datetime.now(timezone.utc),
        is_consistent_with_cip=False
    )
    
    cip_policy = aml_compliance_service.create_cip_policy(
        policy_id="CIP-002",
        is_part_of_aml_program=False,
        is_consistent_with_aml_program=False,
        requires_identity_verification=True,
        requires_beneficial_ownership=True
    )
    
    # Act
    is_compliant = aml_compliance_service.validate_cip_consistency_with_aml(
        "AML-002", "CIP-002"
    )
    
    # Assert
    assert is_compliant is False, (
        "CIP not part of AML program violates 31 C.F.R. § 1010.220(a)"
    )


def test_cip_inconsistent_with_aml_program_fails_compliance(
    aml_compliance_service: AMLComplianceService
):
    """
    Test that inconsistent CIP fails compliance.
    
    MUST-TEST: FINCEN-1010-220-a-R1::OBL::001 (negative case)
    Citation: 31 C.F.R. § 1010.220(a)
    """
    # Arrange
    aml_program = aml_compliance_service.create_aml_program(
        program_id="AML-003",
        has_internal_controls=True,
        has_independent_testing=True,
        has_designated_officer=True,
        has_ongoing_training=True,
        has_risk_based_cdd=True,
        board_approved=True,
        board_approval_date=datetime.now(timezone.utc),
        is_consistent_with_cip=True
    )
    
    cip_policy = aml_compliance_service.create_cip_policy(
        policy_id="CIP-003",
        is_part_of_aml_program=True,
        is_consistent_with_aml_program=False,
        requires_identity_verification=True,
        requires_beneficial_ownership=True
    )
    
    # Act
    is_compliant = aml_compliance_service.validate_cip_consistency_with_aml(
        "AML-003", "CIP-003"
    )
    
    # Assert
    assert is_compliant is False, (
        "CIP inconsistent with AML program violates 31 C.F.R. § 1010.220(a)"
    )


# ============================================================================
# BDD Scenario Tests
# ============================================================================

def test_successful_transaction(transaction_service: TransactionService,
                               valid_account_from: Account,
                               valid_account_to: Account,
                               audit_logger: AuditLogger):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    transaction_service.accounts[valid_account_from.account_id] = valid_account_from
    transaction_service.accounts[valid_account_to.account_id] = valid_account_to
    
    initial_from_balance = valid_account_from.balance
    initial_to_balance = valid_account_to.balance
    transfer_amount = Decimal("1000.00")
    
    # Act
    txn = transaction_service.process_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=transfer_amount,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert txn.status == TransactionStatus.SUCCESS
    assert txn.rejection_reason is None
    assert valid_account_from.balance == initial_from_balance - transfer_amount
    assert valid_account_to.balance == initial_to_balance + transfer_amount
    assert len(audit_logger.logs) > 0
    
    audit_entry = audit_logger.logs[-1]
    assert audit_entry.action == "TRANSACTION_SUCCESS"
    assert audit_entry.transaction_id == txn.transaction_id
    assert audit_entry.user_id == "USER-001"
    assert audit_entry.ip_address == "192.168.1.100"


def test_sar_suspicious_activity_above_threshold(
    sar_filing_service: SARFilingService,
    rule_resolver: ComplianceRuleResolver
):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    customer_id = "CUST-SUSPICIOUS-001"
    suspicious_amount = Decimal("6000.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    should_file = sar_filing_service.should_file_sar(
        amount=suspicious_amount,
        is_suspicious=True,
        is_insider_abuse=False
    )
    
    assert should_file is True
    
    filing = sar_filing_service.file_sar(
        customer_id=customer_id,
        amount=suspicious_amount,
        reason="Suspicious pattern detected - structuring",
        detection_date=detection_date,
        is_insider_abuse=False
    )
    
    # Assert
    assert filing.status == SARStatus.FILED
    assert filing.amount == suspicious_amount
    assert filing.amount > rule_resolver.get_sar_threshold()
    assert filing.subject_notified is False, "Subject must NOT be notified of SAR filing"
    
    filing_deadline = detection_date + timedelta(days=rule_resolver.get_sar_filing_deadline_days())
    assert filing.filed_date <= filing_deadline, "SAR must be filed within 30 days"
    
    # Verify no tipping off
    can_disclose = sar_filing_service.disclose_sar_to_customer(customer_id)
    assert can_disclose is False, "Bank must NOT disclose SAR filing to customer"


def test_sar_insider_abuse_any_amount(sar_filing_service: SARFilingService):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    employee_customer_id = "CUST-EMPLOYEE-001"
    small_amount = Decimal("100.00")
    detection_date = datetime.now(timezone.utc)
    
    # Act
    should_file = sar_filing_service.should_file_sar(
        amount=small_amount,
        is_suspicious=True,
        is_insider_abuse=True
    )
    
    assert should_file is True, "SAR required for insider abuse at any amount"
    
    filing = sar_filing_service.file_sar(
        customer_id=employee_customer_id,
        amount=small_amount,
        reason="Insider abuse - unauthorized account access",
        detection_date=detection_date,
        is_insider_abuse=True
    )
    
    # Assert
    assert filing.status == SARStatus.FILED
    assert filing.is_insider_abuse is True
    assert filing.amount < sar_filing_service.rule_resolver.get_sar_threshold()
    assert filing.subject_notified is False
    assert (filing.filed_date - detection_date).total_seconds() < 3600, \
        "Insider abuse SAR should be filed immediately"


def test_sar_no_tipping_off(sar_filing_service: SARFilingService):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    customer_id = "CUST-INQUIRY-001"
    detection_date = datetime.now(timezone.utc)
    
    filing = sar_filing_service.file_sar(
        customer_id=customer_id,
        amount=Decimal("7500.00"),
        reason="Suspicious wire transfers",
        detection_date=detection_date,
        is_insider_abuse=False
    )
    
    # Act
    has_sar = sar_filing_service.has_sar_for_customer(customer_id)
    can_disclose = sar_filing_service.disclose_sar_to_customer(customer_id)
    
    # Assert
    assert has_sar is True
    assert can_disclose is False, "Bank must NOT disclose SAR filing to customer"
    assert filing.subject_notified is False


def test_zero_amount_transfer(transaction_service: TransactionService,
                              valid_account_from: Account,
                              valid_account_to: Account):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    transaction_service.accounts[valid_account_from.account_id] = valid_account_from
    transaction_service.accounts[valid_account_to.account_id] = valid_account_to
    
    # Act
    txn = transaction_service.process_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=Decimal("0"),
        user_id="USER-002",
        ip_address="192.168.1.101",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert txn.status == TransactionStatus.REJECTED
    assert txn.rejection_reason == "Amount must be greater than 0"


def test_negative_amount_transfer(transaction_service: TransactionService,
                                 valid_account_from: Account,
                                 valid_account_to: Account):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    transaction_service.accounts[valid_account_from.account_id] = valid_account_from
    transaction_service.accounts[valid_account_to.account_id] = valid_account_to
    
    # Act
    txn = transaction_service.process_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=Decimal("-100.00"),
        user_id="USER-003",
        ip_address="192.168.1.102",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert txn.status == TransactionStatus.REJECTED
    assert txn.rejection_reason == "Invalid amount"


def test_insufficient_balance(transaction_service: TransactionService,
                             valid_account_to: Account):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    low_balance_account = Account(
        account_id="ACC-LOW",
        balance=Decimal("1000.00"),
        routing_number="021000021",
        account_number="1111111111",
        customer_id="CUST-LOW",
        is_valid=True
    )
    
    transaction_service.accounts[low_balance_account.account_id] = low_balance_account
    transaction_service.accounts[valid_account_to.account_id] = valid_account_to
    
    # Act
    txn = transaction_service.process_transaction(
        from_account_id=low_balance_account.account_id,
        to_account_id=valid_account_to.account_id,
        amount=Decimal("5000.00"),
        user_id="USER-004",
        ip_address="192.168.1.103",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert txn.status == TransactionStatus.REJECTED
    assert txn.rejection_reason == "Insufficient balance"
    assert low_balance_account.balance == Decimal("1000.00"), \
        "Balance should not change on rejected transaction"


def test_invalid_beneficiary(transaction_service: TransactionService,
                            valid_account_from: Account,
                            invalid_account: Account):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    transaction_service.accounts[valid_account_from.account_id] = valid_account_from
    transaction_service.accounts[invalid_account.account_id] = invalid_account
    
    # Act
    txn = transaction_service.process_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=invalid_account.account_id,
        amount=Decimal("500.00"),
        user_id="USER-005",
        ip_address="192.168.1.104",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert txn.status == TransactionStatus.REJECTED
    assert txn.rejection_reason == "Invalid beneficiary account"


# ============================================================================
# Boundary and Threshold Tests
# ============================================================================

def test_sar_threshold_boundary_at_5000(sar_filing_service: SARFilingService,
                                       rule_resolver: ComplianceRuleResolver):
    """
    Test SAR threshold boundary at exactly $5,000.
    Uses AUTHORITATIVE threshold: sar_threshold = 5000
    """
    # Arrange
    exactly_threshold = rule_resolver.get_sar_threshold()
    
    # Act - at threshold
    should_file_at = sar_filing_service.should_file_sar(
        amount=exactly_threshold,
        is_suspicious=True,
        is_insider_abuse=False
    )
    
    # Act - just below threshold
    should_file_below = sar_filing_service.should_file_sar(
        amount=exactly_threshold - Decimal("0.01"),
        is_suspicious=True,
        is_insider_abuse=False
    )
    
    # Act - just above threshold
    should_file_above = sar_filing_service.should_file_sar(
        amount=exactly_threshold + Decimal("0.01"),
        is_suspicious=True,
        is_insider_abuse=False
    )
    
    # Assert
    assert should_file_at is False, "SAR not required at exactly $5,000 (must be > threshold)"
    assert should_file_below is False, "SAR not required below $5,000"
    assert should_file_above is True, "SAR required above $5,000"


def test_sar_insider_threshold_is_zero(sar_filing_service: SARFilingService,
                                      rule_resolver: ComplianceRuleResolver):
    """
    Test that insider abuse SAR has zero threshold.
    Uses AUTHORITATIVE threshold: insider_threshold = 0
    """
    # Arrange
    insider_threshold = rule_resolver.get_sar_insider_threshold()
    assert insider_threshold == Decimal("0")
    
    # Act
    should_file_penny = sar_filing_service.should_file_sar(
        amount=Decimal("0.01"),
        is_suspicious=True,
        is_insider_abuse=True
    )
    
    should_file_one_dollar = sar_filing_service.should_file_sar(
        amount=Decimal("1.00"),
        is_suspicious=True,
        is_insider_abuse=True
    )
    
    # Assert
    assert should_file_penny is True, "Insider abuse SAR required for any amount > $0"
    assert should_file_one_dollar is True, "Insider abuse SAR required for any amount"


def test_authoritative_thresholds_match_grounding(rule_resolver: ComplianceRuleResolver):
    """
    Verify all AUTHORITATIVE THRESHOLDS match the grounding block exactly.
    """
    # Assert - verify exact values from grounding block
    assert rule_resolver.CTR_THRESHOLD == Decimal("10000"), \
        "CTR threshold must be exactly 10000"
    assert rule_resolver.SAR_THRESHOLD == Decimal("5000"), \
        "SAR threshold must be exactly 5000"
    assert rule_resolver.TRAVEL_RULE_THRESHOLD == Decimal("3000"), \
        "Travel rule threshold must be exactly 3000"
    assert rule_resolver.WIRE_DUAL_APPROVAL_THRESHOLD == Decimal("10000"), \
        "Wire dual approval threshold must be exactly 10000"
    assert rule_resolver.OFAC_FUZZY_THRESHOLD == 85, \
        "OFAC fuzzy threshold must be exactly 85"
    assert rule_resolver.BENEFICIAL_OWNERSHIP_PCT == Decimal("20"), \
        "Beneficial ownership percentage must be exactly 20"


def test_sar_filing_deadline_30_days(sar_filing_service: SARFilingService,
                                    rule_resolver: ComplianceRuleResolver):
    """
    Test SAR filing deadline is 30 days from detection.
    """
    # Arrange
    detection_date = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    expected_deadline = detection_date + timedelta(
        days=rule_resolver.get_sar_filing_deadline_days()
    )
    
    # Act
    filing = sar_filing_service.file_sar(
        customer_id="CUST-DEADLINE-001",
        amount=Decimal("6000.00"),
        reason="Test deadline",
        detection_date=detection_date,
        is_insider_abuse=False
    )
    
    # Assert
    assert rule_resolver.get_sar_filing_deadline_days() == 30
    assert filing.filed_date <= expected_deadline, \
        "SAR must be filed within 30 days of detection"


def test_audit_trail_contains_required_fields(transaction_service: TransactionService,
                                              valid_account_from: Account,
                                              valid_account_to: Account,
                                              audit_logger: AuditLogger):
    """
    Test audit trail contains all required compliance fields.
    """
    # Arrange
    transaction_service.accounts[valid_account_from.account_id] = valid_account_from
    transaction_service.accounts[valid_account_to.account_id] = valid_account_to
    
    # Act
    txn = transaction_service.process_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=Decimal("2500.00"),
        user_id="USER-AUDIT-001",
        ip_address="10.0.0.50",
        device_info="Chrome/120.0"
    )
    
    # Assert
    assert len(audit_logger.logs) > 0
    audit_entry = audit_logger.logs[-1]
    
    # Verify required audit fields
    assert audit_entry.timestamp is not None
    assert audit_entry.timestamp.tzinfo is not None, "Timestamp must be timezone-aware"
    assert audit_entry.user_id == "USER-AUDIT-001"
    assert audit_entry.ip_address == "10.0.0.50"
    assert audit_entry.device_info == "Chrome/120.0"
    assert audit_entry.action == "TRANSACTION_SUCCESS"
    assert audit_entry.transaction_id == txn.transaction_id
    assert "amount" in audit_entry.details
    assert "from" in audit_entry.details
    assert "to" in audit_entry.details


def test_sar_not_required_below_threshold_non_suspicious(
    sar_filing_service: SARFilingService,
    rule_resolver: ComplianceRuleResolver
):
    """
    Test SAR not required for non-suspicious activity below threshold.
    """
    # Arrange
    amount = Decimal("4999.99")
    
    # Act
    should_file = sar_filing_service.should_file_sar(
        amount=amount,
        is_suspicious=False,
        is_insider_abuse=False
    )
    
    # Assert
    assert should_file is False, \
        "SAR not required for non-suspicious activity below $5,000 threshold"


def test_multiple_sar_filings_for_same_customer(sar_filing_service: SARFilingService):
    """
    Test that multiple SARs can be filed for the same customer.
    """
    # Arrange
    customer_id = "CUST-MULTIPLE-001"
    detection_date = datetime.now(timezone.utc)
    
    # Act
    filing1 = sar_filing_service.file_sar(
        customer_id=customer_id,
        amount=Decimal("6000.00"),
        reason="Suspicious pattern 1",
        detection_date=detection_date,
        is_insider_abuse=False
    )
    
    filing2 = sar_filing_service.file_sar(
        customer_id=customer_id,
        amount=Decimal("7500.00"),
        reason="Suspicious pattern 2",
        detection_date=detection_date + timedelta(days=10),
        is_insider_abuse=False
    )
    
    # Assert
    assert filing1.sar_id != filing2.sar_id
    assert sar_filing_service.has_sar_for_customer(customer_id) is True
    assert len(sar_filing_service.customer_sar_map[customer_id]) == 2


def test_transaction_with_decimal_precision(transaction_service: TransactionService,
                                           valid_account_from: Account,
                                           valid_account_to: Account):
    """
    Test transaction handling with precise decimal amounts.
    """
    # Arrange
    transaction_service.accounts[valid_account_from.account_id] = valid_account_from
    transaction_service.accounts[valid_account_to.account_id] = valid_account_to
    
    initial_from = valid_account_from.balance
    initial_to = valid_account_to.balance
    
    # Act
    txn = transaction_service.process_transaction(
        from_account_id=valid_account_from.account_id,
        to_account_id=valid_account_to.account_id,
        amount=Decimal("1234.56"),
        user_id="USER-DECIMAL-001",
        ip_address="192.168.1.200",
        device_info="Safari/17.0"
    )
    
    # Assert
    assert txn.status == TransactionStatus.SUCCESS
    assert valid_account_from.balance == initial_from - Decimal("1234.56")
    assert valid_account_to.balance == initial_to + Decimal("1234.56")
    assert isinstance(txn.amount, Decimal), "Amount must be Decimal type"


def test_ofac_screening_integration(ofac_service: OFACScreeningService):
    """
    Test OFAC screening service integration (mock).
    """
    # Arrange
    customer_id = "CUST-OFAC-001"
    customer_name = "John Doe"
    
    # Act
    result = ofac_service.screen(customer_id, customer_name)
    
    # Assert
    assert "is_match" in result
    assert "score" in result
    assert "action" in result
    assert result["action"] in ["ALLOW", "BLOCK", "REVIEW"]


def test_timezone_aware_timestamps(sar_filing_service: SARFilingService):
    """
    Test that all timestamps are timezone-aware (UTC).
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    
    # Act
    filing = sar_filing_service.file_sar(
        customer_id="CUST-TZ-001",
        amount=Decimal("8000.00"),
        reason="Test timezone",
        detection_date=detection_date,
        is_insider_abuse=False
    )
    
    # Assert
    assert filing.detection_date.tzinfo is not None, \
        "Detection date must be timezone-aware"
    assert filing.filed_date.tzinfo is not None, \
        "Filed date must be timezone-aware"
    assert filing.detection_date.tzinfo == timezone.utc, \
        "Detection date must be in UTC"
    assert filing.filed_date.tzinfo == timezone.utc, \
        "Filed date must be in UTC"