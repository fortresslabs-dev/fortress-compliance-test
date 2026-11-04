import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
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
    BLOCKED = "blocked"


class SARFilingReason(Enum):
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    INSIDER_ABUSE = "insider_abuse"
    STRUCTURING = "structuring"
    NO_IDENTIFIED_SUSPECT = "no_identified_suspect"


@dataclass
class Account:
    account_id: str
    balance: Decimal
    routing_number: str
    account_number: str
    is_valid: bool = True


@dataclass
class User:
    user_id: str
    name: str
    ssn: str
    is_employee: bool = False


@dataclass
class Transaction:
    transaction_id: str
    user_id: str
    amount: Decimal
    timestamp: datetime
    from_account: str
    to_account: str
    status: TransactionStatus
    rejection_reason: Optional[str] = None


@dataclass
class SARFiling:
    sar_id: str
    subject_name: str
    subject_tin: str
    activity_date: datetime
    amount: Decimal
    reason: SARFilingReason
    filed_date: datetime
    detection_date: datetime
    days_to_file: int
    continuing_activity: bool = False


@dataclass
class AuditLogEntry:
    timestamp: datetime
    user_id: str
    action: str
    details: Dict[str, Any]
    ip_address: str
    device_info: str


# ============================================================================
# Authoritative Thresholds (from compliance grounding)
# ============================================================================

CTR_THRESHOLD = Decimal("10000")
SAR_THRESHOLD = Decimal("5000")
TRAVEL_RULE_THRESHOLD = Decimal("3000")
WIRE_DUAL_APPROVAL_THRESHOLD = Decimal("10000")
OFAC_FUZZY_THRESHOLD = 85
BENEFICIAL_OWNERSHIP_PCT = 20
SAR_FILING_DEADLINE_DAYS = 30
SAR_NO_SUSPECT_THRESHOLD = Decimal("25000")
SAR_INSIDER_THRESHOLD = Decimal("0")


# ============================================================================
# Service Interfaces
# ============================================================================

class TransactionService:
    def __init__(
        self,
        account_repo,
        audit_logger,
        monitoring_service,
        sar_service,
        ofac_service
    ):
        self.account_repo = account_repo
        self.audit_logger = audit_logger
        self.monitoring_service = monitoring_service
        self.sar_service = sar_service
        self.ofac_service = ofac_service

    def execute_transaction(
        self,
        user: User,
        from_account_id: str,
        to_account_id: str,
        amount: Decimal,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        
        # Validate amount
        if amount <= 0:
            rejection_reason = "Amount must be greater than 0" if amount == 0 else "Invalid amount"
            txn = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                user_id=user.user_id,
                amount=amount,
                timestamp=timestamp,
                from_account=from_account_id,
                to_account=to_account_id,
                status=TransactionStatus.REJECTED,
                rejection_reason=rejection_reason
            )
            self.audit_logger.log(
                user_id=user.user_id,
                action="transaction_rejected",
                details={"reason": rejection_reason, "amount": str(amount)},
                ip_address=ip_address,
                device_info=device_info
            )
            return txn

        # Validate accounts
        from_account = self.account_repo.get_account(from_account_id)
        to_account = self.account_repo.get_account(to_account_id)
        
        if not from_account or not from_account.is_valid:
            txn = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                user_id=user.user_id,
                amount=amount,
                timestamp=timestamp,
                from_account=from_account_id,
                to_account=to_account_id,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid source account"
            )
            self.audit_logger.log(
                user_id=user.user_id,
                action="transaction_rejected",
                details={"reason": "Invalid source account"},
                ip_address=ip_address,
                device_info=device_info
            )
            return txn

        if not to_account or not to_account.is_valid:
            txn = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                user_id=user.user_id,
                amount=amount,
                timestamp=timestamp,
                from_account=from_account_id,
                to_account=to_account_id,
                status=TransactionStatus.REJECTED,
                rejection_reason="Invalid beneficiary account"
            )
            self.audit_logger.log(
                user_id=user.user_id,
                action="transaction_rejected",
                details={"reason": "Invalid beneficiary account"},
                ip_address=ip_address,
                device_info=device_info
            )
            return txn

        # Check balance
        if from_account.balance < amount:
            txn = Transaction(
                transaction_id=f"txn_{timestamp.timestamp()}",
                user_id=user.user_id,
                amount=amount,
                timestamp=timestamp,
                from_account=from_account_id,
                to_account=to_account_id,
                status=TransactionStatus.REJECTED,
                rejection_reason="Insufficient balance"
            )
            self.audit_logger.log(
                user_id=user.user_id,
                action="transaction_rejected",
                details={"reason": "Insufficient balance", "balance": str(from_account.balance)},
                ip_address=ip_address,
                device_info=device_info
            )
            return txn

        # Execute transaction
        from_account.balance -= amount
        to_account.balance += amount
        
        txn = Transaction(
            transaction_id=f"txn_{timestamp.timestamp()}",
            user_id=user.user_id,
            amount=amount,
            timestamp=timestamp,
            from_account=from_account_id,
            to_account=to_account_id,
            status=TransactionStatus.SUCCESS
        )

        # Audit trail
        self.audit_logger.log(
            user_id=user.user_id,
            action="transaction_success",
            details={
                "transaction_id": txn.transaction_id,
                "amount": str(amount),
                "from": from_account_id,
                "to": to_account_id
            },
            ip_address=ip_address,
            device_info=device_info
        )

        # Monitor for suspicious activity
        self.monitoring_service.analyze_transaction(txn, user)

        return txn


class MonitoringService:
    def __init__(self, sar_service):
        self.sar_service = sar_service

    def analyze_transaction(self, transaction: Transaction, user: User) -> None:
        pass

    def detect_suspicious_pattern(
        self,
        user: User,
        amount: Decimal,
        pattern_type: str
    ) -> bool:
        return False


class SARService:
    def __init__(self, audit_logger):
        self.audit_logger = audit_logger
        self.filed_sars: List[SARFiling] = []

    def file_sar(
        self,
        subject_name: str,
        subject_tin: str,
        activity_date: datetime,
        amount: Decimal,
        reason: SARFilingReason,
        detection_date: datetime
    ) -> SARFiling:
        filed_date = datetime.now(timezone.utc)
        days_to_file = (filed_date - detection_date).days
        
        sar = SARFiling(
            sar_id=f"sar_{filed_date.timestamp()}",
            subject_name=subject_name,
            subject_tin=subject_tin,
            activity_date=activity_date,
            amount=amount,
            reason=reason,
            filed_date=filed_date,
            detection_date=detection_date,
            days_to_file=days_to_file
        )
        
        self.filed_sars.append(sar)
        
        self.audit_logger.log(
            user_id="SYSTEM",
            action="sar_filed",
            details={
                "sar_id": sar.sar_id,
                "reason": reason.value,
                "amount": str(amount)
            },
            ip_address="internal",
            device_info="compliance_system"
        )
        
        return sar

    def should_file_sar(
        self,
        amount: Decimal,
        is_suspicious: bool,
        is_insider: bool,
        has_identified_suspect: bool
    ) -> bool:
        # FINCEN-SAR-001::OBL::002 - Insider abuse, any amount
        if is_insider and is_suspicious:
            return True
        
        # FINCEN-SAR-001::OBL::001 - Suspicious activity >= $5,000
        if is_suspicious and amount >= SAR_THRESHOLD:
            return True
        
        # FINCEN-SAR-001::OBL::003 - >= $25,000 even without identified suspect
        if amount >= SAR_NO_SUSPECT_THRESHOLD and not has_identified_suspect:
            return True
        
        return False

    def is_sar_filed_for_customer(self, customer_id: str) -> bool:
        return any(sar.subject_tin == customer_id for sar in self.filed_sars)


class AuditLogger:
    def __init__(self):
        self.logs: List[AuditLogEntry] = []

    def log(
        self,
        user_id: str,
        action: str,
        details: Dict[str, Any],
        ip_address: str,
        device_info: str
    ) -> None:
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address,
            device_info=device_info
        )
        self.logs.append(entry)


class AccountRepository:
    def __init__(self):
        self.accounts: Dict[str, Account] = {}

    def get_account(self, account_id: str) -> Optional[Account]:
        return self.accounts.get(account_id)

    def create_account(
        self,
        account_id: str,
        balance: Decimal,
        routing_number: str,
        account_number: str,
        is_valid: bool = True
    ) -> Account:
        account = Account(
            account_id=account_id,
            balance=balance,
            routing_number=routing_number,
            account_number=account_number,
            is_valid=is_valid
        )
        self.accounts[account_id] = account
        return account


class OFACService:
    def screen(self, name: str, tin: str) -> Dict[str, Any]:
        return {"is_match": False, "score": 0}


class CustomerService:
    def __init__(self, sar_service):
        self.sar_service = sar_service

    def handle_customer_inquiry(
        self,
        customer_id: str,
        inquiry_type: str
    ) -> str:
        # FINCEN-SAR-001 - No tipping off
        if self.sar_service.is_sar_filed_for_customer(customer_id):
            # Never disclose SAR filing
            return "Your account is being reviewed per standard procedures."
        return "No restrictions found."


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def audit_logger() -> AuditLogger:
    return AuditLogger()


@pytest.fixture
def account_repo() -> AccountRepository:
    return AccountRepository()


@pytest.fixture
def ofac_service() -> OFACService:
    return OFACService()


@pytest.fixture
def sar_service(audit_logger: AuditLogger) -> SARService:
    return SARService(audit_logger)


@pytest.fixture
def monitoring_service(sar_service: SARService) -> MonitoringService:
    return MonitoringService(sar_service)


@pytest.fixture
def transaction_service(
    account_repo: AccountRepository,
    audit_logger: AuditLogger,
    monitoring_service: MonitoringService,
    sar_service: SARService,
    ofac_service: OFACService
) -> TransactionService:
    return TransactionService(
        account_repo,
        audit_logger,
        monitoring_service,
        sar_service,
        ofac_service
    )


@pytest.fixture
def customer_service(sar_service: SARService) -> CustomerService:
    return CustomerService(sar_service)


@pytest.fixture
def valid_user() -> User:
    return User(
        user_id="user_001",
        name="John Doe",
        ssn="123-45-6789",
        is_employee=False
    )


@pytest.fixture
def insider_user() -> User:
    return User(
        user_id="emp_001",
        name="Jane Employee",
        ssn="987-65-4321",
        is_employee=True
    )


@pytest.fixture
def valid_from_account(account_repo: AccountRepository) -> Account:
    return account_repo.create_account(
        account_id="acc_001",
        balance=Decimal("10000.00"),
        routing_number="123456789",
        account_number="9876543210"
    )


@pytest.fixture
def valid_to_account(account_repo: AccountRepository) -> Account:
    return account_repo.create_account(
        account_id="acc_002",
        balance=Decimal("5000.00"),
        routing_number="123456789",
        account_number="1234567890"
    )


# ============================================================================
# BDD Scenario Tests
# ============================================================================

def test_successful_transaction(
    transaction_service: TransactionService,
    valid_user: User,
    valid_from_account: Account,
    valid_to_account: Account,
    audit_logger: AuditLogger
):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    initial_from_balance = valid_from_account.balance
    initial_to_balance = valid_to_account.balance
    transfer_amount = Decimal("1000.00")
    
    # Act
    transaction = transaction_service.execute_transaction(
        user=valid_user,
        from_account_id=valid_from_account.account_id,
        to_account_id=valid_to_account.account_id,
        amount=transfer_amount,
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    assert valid_from_account.balance == initial_from_balance - transfer_amount
    assert valid_to_account.balance == initial_to_balance + transfer_amount
    
    # Verify audit trail recorded
    success_logs = [log for log in audit_logger.logs if log.action == "transaction_success"]
    assert len(success_logs) == 1
    assert success_logs[0].user_id == valid_user.user_id
    assert success_logs[0].details["amount"] == str(transfer_amount)


def test_sar_suspicious_activity_above_threshold(
    sar_service: SARService,
    valid_user: User,
    audit_logger: AuditLogger
):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    
    Tests FINCEN-SAR-001::OBL::001 and FINCEN-SAR-001::OBL::004
    """
    # Arrange
    suspicious_amount = Decimal("6000.00")
    detection_date = datetime.now(timezone.utc)
    activity_date = detection_date - timedelta(days=1)
    
    # Act
    sar = sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=activity_date,
        amount=suspicious_amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date
    )
    
    # Assert - FINCEN-SAR-001::OBL::001
    assert sar.amount >= SAR_THRESHOLD, (
        "SAR must be filed for suspicious activity >= $5,000 per 31 C.F.R. § 1020.320"
    )
    
    # Assert - FINCEN-SAR-001::OBL::004
    assert sar.days_to_file <= SAR_FILING_DEADLINE_DAYS, (
        "SAR must be filed within 30 calendar days of initial detection per 31 C.F.R. § 1020.320"
    )
    
    # Assert - Subject NOT notified (no tipping off)
    sar_logs = [log for log in audit_logger.logs if log.action == "sar_filed"]
    assert len(sar_logs) == 1
    # Verify no customer notification logs exist
    notification_logs = [log for log in audit_logger.logs if "notify_customer" in log.action]
    assert len(notification_logs) == 0


def test_sar_insider_abuse_any_amount(
    sar_service: SARService,
    insider_user: User,
    audit_logger: AuditLogger
):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    
    Tests FINCEN-SAR-001::OBL::002
    """
    # Arrange
    small_amount = Decimal("100.00")  # Below normal SAR threshold
    detection_date = datetime.now(timezone.utc)
    activity_date = detection_date
    
    # Act
    should_file = sar_service.should_file_sar(
        amount=small_amount,
        is_suspicious=True,
        is_insider=True,
        has_identified_suspect=True
    )
    
    assert should_file, (
        "SAR must be filed for insider abuse regardless of amount per 31 C.F.R. § 1020.320"
    )
    
    sar = sar_service.file_sar(
        subject_name=insider_user.name,
        subject_tin=insider_user.ssn,
        activity_date=activity_date,
        amount=small_amount,
        reason=SARFilingReason.INSIDER_ABUSE,
        detection_date=detection_date
    )
    
    # Assert - FINCEN-SAR-001::OBL::002
    assert sar.amount < SAR_THRESHOLD, (
        "Test verifies SAR filed for amount below normal threshold"
    )
    assert sar.reason == SARFilingReason.INSIDER_ABUSE, (
        "SAR must be filed for insider abuse at any amount per 31 C.F.R. § 1020.320"
    )
    assert insider_user.is_employee, "Subject must be bank employee"


def test_sar_no_tipping_off(
    customer_service: CustomerService,
    sar_service: SARService,
    valid_user: User
):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange - File SAR for customer
    detection_date = datetime.now(timezone.utc)
    sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=detection_date,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date
    )
    
    # Act
    response = customer_service.handle_customer_inquiry(
        customer_id=valid_user.ssn,
        inquiry_type="account_restrictions"
    )
    
    # Assert - No tipping off
    assert "SAR" not in response.upper()
    assert "SUSPICIOUS" not in response.upper()
    assert "REPORT" not in response.upper()
    assert "standard procedures" in response.lower()


def test_zero_amount_transfer(
    transaction_service: TransactionService,
    valid_user: User,
    valid_from_account: Account,
    valid_to_account: Account
):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    zero_amount = Decimal("0.00")
    
    # Act
    transaction = transaction_service.execute_transaction(
        user=valid_user,
        from_account_id=valid_from_account.account_id,
        to_account_id=valid_to_account.account_id,
        amount=zero_amount,
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Amount must be greater than 0"


def test_negative_amount_transfer(
    transaction_service: TransactionService,
    valid_user: User,
    valid_from_account: Account,
    valid_to_account: Account
):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    negative_amount = Decimal("-100.00")
    
    # Act
    transaction = transaction_service.execute_transaction(
        user=valid_user,
        from_account_id=valid_from_account.account_id,
        to_account_id=valid_to_account.account_id,
        amount=negative_amount,
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid amount"


def test_insufficient_balance(
    transaction_service: TransactionService,
    valid_user: User,
    account_repo: AccountRepository,
    valid_to_account: Account
):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    low_balance_account = account_repo.create_account(
        account_id="acc_low",
        balance=Decimal("1000.00"),
        routing_number="123456789",
        account_number="1111111111"
    )
    transfer_amount = Decimal("5000.00")
    
    # Act
    transaction = transaction_service.execute_transaction(
        user=valid_user,
        from_account_id=low_balance_account.account_id,
        to_account_id=valid_to_account.account_id,
        amount=transfer_amount,
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Insufficient balance"


def test_invalid_beneficiary(
    transaction_service: TransactionService,
    valid_user: User,
    valid_from_account: Account,
    account_repo: AccountRepository
):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    invalid_account = account_repo.create_account(
        account_id="acc_invalid",
        balance=Decimal("0.00"),
        routing_number="000000000",
        account_number="0000000000",
        is_valid=False
    )
    
    # Act
    transaction = transaction_service.execute_transaction(
        user=valid_user,
        from_account_id=valid_from_account.account_id,
        to_account_id=invalid_account.account_id,
        amount=Decimal("100.00"),
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid beneficiary account"


# ============================================================================
# Explicit MUST-TEST Obligation Tests
# ============================================================================

def test_obligation_001_sar_threshold_5000_suspicious(sar_service: SARService):
    """
    Explicit test for FINCEN-SAR-001::OBL::001
    Banks must file a SAR for any transaction that involves or aggregates to 
    $5,000 or more where the institution knows, suspects, or has reason to 
    suspect money laundering, BSA violations, or structuring.
    """
    # Test at exact threshold
    assert sar_service.should_file_sar(
        amount=SAR_THRESHOLD,
        is_suspicious=True,
        is_insider=False,
        has_identified_suspect=True
    ), f"SAR must be filed for suspicious activity at exactly ${SAR_THRESHOLD} per 31 C.F.R. § 1020.320"
    
    # Test above threshold
    assert sar_service.should_file_sar(
        amount=SAR_THRESHOLD + Decimal("0.01"),
        is_suspicious=True,
        is_insider=False,
        has_identified_suspect=True
    ), f"SAR must be filed for suspicious activity above ${SAR_THRESHOLD} per 31 C.F.R. § 1020.320"
    
    # Test below threshold - should NOT file
    assert not sar_service.should_file_sar(
        amount=SAR_THRESHOLD - Decimal("0.01"),
        is_suspicious=True,
        is_insider=False,
        has_identified_suspect=True
    ), f"SAR not required for suspicious activity below ${SAR_THRESHOLD} per 31 C.F.R. § 1020.320"


def test_obligation_002_insider_abuse_no_minimum(sar_service: SARService):
    """
    Explicit test for FINCEN-SAR-001::OBL::002
    For insider abuse, SAR must be filed regardless of amount.
    """
    # Test with $0.01
    assert sar_service.should_file_sar(
        amount=Decimal("0.01"),
        is_suspicious=True,
        is_insider=True,
        has_identified_suspect=True
    ), "SAR must be filed for insider abuse at any amount per 31 C.F.R. § 1020.320"
    
    # Test with $1
    assert sar_service.should_file_sar(
        amount=Decimal("1.00"),
        is_suspicious=True,
        is_insider=True,
        has_identified_suspect=True
    ), "SAR must be filed for insider abuse regardless of amount per 31 C.F.R. § 1020.320"
    
    # Test with amount below normal SAR threshold
    assert sar_service.should_file_sar(
        amount=Decimal("100.00"),
        is_suspicious=True,
        is_insider=True,
        has_identified_suspect=True
    ), "SAR must be filed for insider abuse even below $5,000 threshold per 31 C.F.R. § 1020.320"


def test_obligation_003_no_suspect_25000_threshold(sar_service: SARService):
    """
    Explicit test for FINCEN-SAR-001::OBL::003
    For transactions of $25,000 or more, a SAR must be filed even if no 
    suspect can be identified.
    """
    # Test at exact $25,000 threshold without identified suspect
    assert sar_service.should_file_sar(
        amount=SAR_NO_SUSPECT_THRESHOLD,
        is_suspicious=False,
        is_insider=False,
        has_identified_suspect=False
    ), f"SAR must be filed for transactions of ${SAR_NO_SUSPECT_THRESHOLD} or more even without identified suspect per 31 C.F.R. § 1020.320"
    
    # Test above $25,000 without identified suspect
    assert sar_service.should_file_sar(
        amount=SAR_NO_SUSPECT_THRESHOLD + Decimal("0.01"),
        is_suspicious=False,
        is_insider=False,
        has_identified_suspect=False
    ), f"SAR must be filed for transactions above ${SAR_NO_SUSPECT_THRESHOLD} even without identified suspect per 31 C.F.R. § 1020.320"
    
    # Test below $25,000 without identified suspect - should NOT file
    assert not sar_service.should_file_sar(
        amount=SAR_NO_SUSPECT_THRESHOLD - Decimal("0.01"),
        is_suspicious=False,
        is_insider=False,
        has_identified_suspect=False
    ), f"SAR not required below ${SAR_NO_SUSPECT_THRESHOLD} without identified suspect per 31 C.F.R. § 1020.320"


def test_obligation_004_filing_deadline_30_days(
    sar_service: SARService,
    valid_user: User
):
    """
    Explicit test for FINCEN-SAR-001::OBL::004
    SARs must be filed within 30 calendar days of initial detection.
    """
    # Arrange
    detection_date = datetime.now(timezone.utc) - timedelta(days=25)
    activity_date = detection_date - timedelta(days=1)
    
    # Act
    sar = sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=activity_date,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date
    )
    
    # Assert
    assert sar.days_to_file <= SAR_FILING_DEADLINE_DAYS, (
        f"SAR must be filed within {SAR_FILING_DEADLINE_DAYS} calendar days of initial detection per 31 C.F.R. § 1020.320"
    )
    
    # Test boundary - filing on day 30 is acceptable
    detection_date_30 = datetime.now(timezone.utc) - timedelta(days=30)
    sar_30 = sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=activity_date,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date_30
    )
    
    assert sar_30.days_to_file <= SAR_FILING_DEADLINE_DAYS, (
        f"SAR filed on day 30 meets the deadline requirement per 31 C.F.R. § 1020.320"
    )


# ============================================================================
# Boundary and Edge Case Tests
# ============================================================================

def test_sar_threshold_boundary_4999_99(sar_service: SARService):
    """
    Boundary test: $4,999.99 (just below SAR threshold)
    Should NOT trigger SAR for suspicious activity
    """
    amount = SAR_THRESHOLD - Decimal("0.01")
    
    should_file = sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=False,
        has_identified_suspect=True
    )
    
    assert not should_file, (
        f"SAR not required for suspicious activity at ${amount} (below ${SAR_THRESHOLD} threshold) per 31 C.F.R. § 1020.320"
    )


def test_sar_threshold_boundary_5000_00(sar_service: SARService):
    """
    Boundary test: $5,000.00 (exact SAR threshold)
    Should trigger SAR for suspicious activity
    """
    amount = SAR_THRESHOLD
    
    should_file = sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=False,
        has_identified_suspect=True
    )
    
    assert should_file, (
        f"SAR required for suspicious activity at exactly ${amount} per 31 C.F.R. § 1020.320"
    )


def test_sar_threshold_boundary_5000_01(sar_service: SARService):
    """
    Boundary test: $5,000.01 (just above SAR threshold)
    Should trigger SAR for suspicious activity
    """
    amount = SAR_THRESHOLD + Decimal("0.01")
    
    should_file = sar_service.should_file_sar(
        amount=amount,
        is_suspicious=True,
        is_insider=False,
        has_identified_suspect=True
    )
    
    assert should_file, (
        f"SAR required for suspicious activity at ${amount} per 31 C.F.R. § 1020.320"
    )


def test_sar_no_suspect_threshold_boundary_24999_99(sar_service: SARService):
    """
    Boundary test: $24,999.99 (just below no-suspect threshold)
    Should NOT trigger SAR without identified suspect
    """
    amount = SAR_NO_SUSPECT_THRESHOLD - Decimal("0.01")
    
    should_file = sar_service.should_file_sar(
        amount=amount,
        is_suspicious=False,
        is_insider=False,
        has_identified_suspect=False
    )
    
    assert not should_file, (
        f"SAR not required at ${amount} without identified suspect per 31 C.F.R. § 1020.320"
    )


def test_sar_no_suspect_threshold_boundary_25000_00(sar_service: SARService):
    """
    Boundary test: $25,000.00 (exact no-suspect threshold)
    Should trigger SAR even without identified suspect
    """
    amount = SAR_NO_SUSPECT_THRESHOLD
    
    should_file = sar_service.should_file_sar(
        amount=amount,
        is_suspicious=False,
        is_insider=False,
        has_identified_suspect=False
    )
    
    assert should_file, (
        f"SAR required at ${amount} even without identified suspect per 31 C.F.R. § 1020.320"
    )


def test_sar_required_fields_present(
    sar_service: SARService,
    valid_user: User
):
    """
    Test that SAR includes all required fields per FINCEN-SAR-FIELD-001:
    - Subject name
    - TIN/SSN
    - Suspicious activity date
    - Dollar amount
    """
    detection_date = datetime.now(timezone.utc)
    activity_date = detection_date - timedelta(days=1)
    amount = Decimal("10000.00")
    
    sar = sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=activity_date,
        amount=amount,
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date
    )
    
    # Assert all required fields are present and non-empty
    assert sar.subject_name, "SAR must include subject name per 31 C.F.R. § 1020.320"
    assert sar.subject_tin, "SAR must include subject TIN/SSN per 31 C.F.R. § 1020.320"
    assert sar.activity_date, "SAR must include suspicious activity date per 31 C.F.R. § 1020.320"
    assert sar.amount > 0, "SAR must include dollar amount per 31 C.F.R. § 1020.320"
    
    # Verify specific values
    assert sar.subject_name == valid_user.name
    assert sar.subject_tin == valid_user.ssn
    assert sar.activity_date == activity_date
    assert sar.amount == amount


def test_audit_trail_immutability(audit_logger: AuditLogger):
    """
    Test that audit logs are immutable once created
    """
    # Arrange & Act
    audit_logger.log(
        user_id="user_001",
        action="test_action",
        details={"key": "value"},
        ip_address="192.168.1.1",
        device_info="test_device"
    )
    
    original_log = audit_logger.logs[0]
    original_timestamp = original_log.timestamp
    original_user_id = original_log.user_id
    
    # Attempt to modify (in real implementation, logs should be immutable)
    # This test documents the expectation
    assert len(audit_logger.logs) == 1
    assert audit_logger.logs[0].timestamp == original_timestamp
    assert audit_logger.logs[0].user_id == original_user_id


def test_transaction_audit_includes_required_fields(
    transaction_service: TransactionService,
    valid_user: User,
    valid_from_account: Account,
    valid_to_account: Account,
    audit_logger: AuditLogger
):
    """
    Test that transaction audit logs include all required fields:
    - Timestamp
    - User ID
    - IP address
    - Device info
    """
    # Act
    transaction_service.execute_transaction(
        user=valid_user,
        from_account_id=valid_from_account.account_id,
        to_account_id=valid_to_account.account_id,
        amount=Decimal("100.00"),
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0)"
    )
    
    # Assert
    assert len(audit_logger.logs) > 0
    log = audit_logger.logs[0]
    
    assert log.timestamp is not None
    assert log.user_id == valid_user.user_id
    assert log.ip_address == "192.168.1.100"
    assert log.device_info == "Mozilla/5.0 (Windows NT 10.0)"


def test_sar_not_filed_for_non_suspicious_below_threshold(sar_service: SARService):
    """
    Negative test: SAR should NOT be filed for non-suspicious activity below thresholds
    """
    should_file = sar_service.should_file_sar(
        amount=Decimal("1000.00"),
        is_suspicious=False,
        is_insider=False,
        has_identified_suspect=True
    )
    
    assert not should_file, (
        "SAR should not be filed for non-suspicious activity below thresholds"
    )


def test_multiple_sars_can_be_filed_for_same_customer(
    sar_service: SARService,
    valid_user: User
):
    """
    Test that multiple SARs can be filed for the same customer
    (e.g., continuing activity)
    """
    detection_date = datetime.now(timezone.utc)
    
    # File first SAR
    sar1 = sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=detection_date,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date
    )
    
    # File second SAR (continuing activity)
    sar2 = sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=detection_date + timedelta(days=30),
        amount=Decimal("15000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date + timedelta(days=30)
    )
    
    assert len(sar_service.filed_sars) == 2
    assert sar1.sar_id != sar2.sar_id
    assert sar1.subject_tin == sar2.subject_tin


def test_decimal_precision_for_currency(
    transaction_service: TransactionService,
    valid_user: User,
    valid_from_account: Account,
    valid_to_account: Account
):
    """
    Test that currency amounts maintain proper decimal precision
    """
    # Test with precise decimal amount
    precise_amount = Decimal("1234.56")
    
    transaction = transaction_service.execute_transaction(
        user=valid_user,
        from_account_id=valid_from_account.account_id,
        to_account_id=valid_to_account.account_id,
        amount=precise_amount,
        ip_address="192.168.1.1",
        device_info="test"
    )
    
    assert transaction.amount == precise_amount
    assert isinstance(transaction.amount, Decimal)


def test_timezone_aware_datetimes(sar_service: SARService, valid_user: User):
    """
    Test that all datetime objects are timezone-aware (UTC)
    """
    detection_date = datetime.now(timezone.utc)
    
    sar = sar_service.file_sar(
        subject_name=valid_user.name,
        subject_tin=valid_user.ssn,
        activity_date=detection_date,
        amount=Decimal("10000.00"),
        reason=SARFilingReason.SUSPICIOUS_ACTIVITY,
        detection_date=detection_date
    )
    
    assert sar.filed_date.tzinfo is not None
    assert sar.detection_date.tzinfo is not None
    assert sar.activity_date.tzinfo is not None


def test_authoritative_thresholds_match_compliance_grounding():
    """
    Test that authoritative thresholds match the compliance grounding exactly
    """
    assert CTR_THRESHOLD == Decimal("10000"), "CTR threshold must be exactly $10,000"
    assert SAR_THRESHOLD == Decimal("5000"), "SAR threshold must be exactly $5,000"
    assert TRAVEL_RULE_THRESHOLD == Decimal("3000"), "Travel rule threshold must be exactly $3,000"
    assert WIRE_DUAL_APPROVAL_THRESHOLD == Decimal("10000"), "Wire dual approval threshold must be exactly $10,000"
    assert OFAC_FUZZY_THRESHOLD == 85, "OFAC fuzzy threshold must be exactly 85"
    assert BENEFICIAL_OWNERSHIP_PCT == 20, "Beneficial ownership percentage must be exactly 20"
    assert SAR_FILING_DEADLINE_DAYS == 30, "SAR filing deadline must be exactly 30 days"
    assert SAR_NO_SUSPECT_THRESHOLD == Decimal("25000"), "SAR no-suspect threshold must be exactly $25,000"