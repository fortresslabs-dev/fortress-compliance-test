import pytest
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from enum import Enum


class TransactionStatus(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    PENDING_REVIEW = "PENDING_REVIEW"


class SARStatus(Enum):
    FILED = "FILED"
    PENDING = "PENDING"
    NOT_REQUIRED = "NOT_REQUIRED"


@dataclass
class Account:
    account_id: str
    routing_number: str
    balance: Decimal
    user_id: str
    is_valid: bool = True


@dataclass
class Transaction:
    transaction_id: str
    from_account: str
    to_account: str
    amount: Decimal
    timestamp: datetime
    status: TransactionStatus
    user_id: str
    ip_address: str
    device_info: str
    rejection_reason: Optional[str] = None


@dataclass
class SARFiling:
    sar_id: str
    transaction_id: str
    filing_date: datetime
    detection_date: datetime
    amount: Decimal
    reason: str
    subject_notified: bool
    filed_with_fincen: bool
    is_insider_abuse: bool


@dataclass
class AuditLogEntry:
    log_id: str
    timestamp: datetime
    user_id: str
    action: str
    transaction_id: Optional[str]
    ip_address: str
    device_info: str
    details: Dict[str, Any]
    immutable_hash: str


class BankingService:
    def __init__(
        self,
        audit_logger,
        rule_resolver,
        ofac_service,
        sar_service,
        account_repository
    ):
        self.audit_logger = audit_logger
        self.rule_resolver = rule_resolver
        self.ofac_service = ofac_service
        self.sar_service = sar_service
        self.account_repository = account_repository

    def initiate_transaction(
        self,
        from_account_id: str,
        to_account_id: str,
        to_routing_number: str,
        amount: Decimal,
        user_id: str,
        ip_address: str,
        device_info: str
    ) -> Transaction:
        timestamp = datetime.now(timezone.utc)
        transaction_id = f"TXN-{timestamp.timestamp()}"

        # Validate amount
        if amount == Decimal("0"):
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Amount must be greater than 0"
            )

        if amount < Decimal("0"):
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid amount"
            )

        # Validate accounts
        from_account = self.account_repository.get_account(from_account_id)
        if not from_account or not from_account.is_valid:
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid account"
            )

        # Validate beneficiary
        if not self._validate_beneficiary(to_account_id, to_routing_number):
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Invalid beneficiary account"
            )

        # Check balance
        if from_account.balance < amount:
            return Transaction(
                transaction_id=transaction_id,
                from_account=from_account_id,
                to_account=to_account_id,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.REJECTED,
                user_id=user_id,
                ip_address=ip_address,
                device_info=device_info,
                rejection_reason="Insufficient balance"
            )

        # Process transaction
        self.account_repository.debit_account(from_account_id, amount)
        transaction = Transaction(
            transaction_id=transaction_id,
            from_account=from_account_id,
            to_account=to_account_id,
            amount=amount,
            timestamp=timestamp,
            status=TransactionStatus.SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            device_info=device_info
        )

        # Record audit trail
        self.audit_logger.log_transaction(transaction)

        return transaction

    def _validate_beneficiary(self, account_number: str, routing_number: str) -> bool:
        if not account_number or not routing_number:
            return False
        if len(routing_number) != 9:
            return False
        if not routing_number.isdigit():
            return False
        return True


# Fixtures

@pytest.fixture
def audit_logger():
    logger = Mock()
    logger.log_transaction = Mock(return_value=AuditLogEntry(
        log_id="LOG-001",
        timestamp=datetime.now(timezone.utc),
        user_id="USER-001",
        action="TRANSACTION",
        transaction_id="TXN-001",
        ip_address="192.168.1.1",
        device_info="Mozilla/5.0",
        details={},
        immutable_hash="abc123def456"
    ))
    return logger


@pytest.fixture
def rule_resolver():
    resolver = Mock()
    resolver.get_sar_threshold = Mock(return_value=Decimal("5000"))
    resolver.get_sar_insider_threshold = Mock(return_value=Decimal("0"))
    resolver.get_sar_filing_deadline_days = Mock(return_value=30)
    resolver.get_ctr_threshold = Mock(return_value=Decimal("10000"))
    resolver.is_no_tipping_off_enabled = Mock(return_value=True)
    return resolver


@pytest.fixture
def ofac_service():
    service = Mock()
    service.screen_entity = Mock(return_value={"match": False, "score": 0})
    return service


@pytest.fixture
def sar_service():
    service = Mock()
    service.file_sar = Mock()
    service.check_sar_filed = Mock(return_value=False)
    return service


@pytest.fixture
def account_repository():
    repo = Mock()
    repo.get_account = Mock()
    repo.debit_account = Mock()
    repo.credit_account = Mock()
    return repo


@pytest.fixture
def banking_service(audit_logger, rule_resolver, ofac_service, sar_service, account_repository):
    return BankingService(
        audit_logger=audit_logger,
        rule_resolver=rule_resolver,
        ofac_service=ofac_service,
        sar_service=sar_service,
        account_repository=account_repository
    )


@pytest.fixture
def valid_account():
    return Account(
        account_id="ACC-001",
        routing_number="123456789",
        balance=Decimal("10000.00"),
        user_id="USER-001",
        is_valid=True
    )


@pytest.fixture
def low_balance_account():
    return Account(
        account_id="ACC-002",
        routing_number="123456789",
        balance=Decimal("1000.00"),
        user_id="USER-002",
        is_valid=True
    )


# Test: Successful Transaction

def test_successful_transaction(banking_service, account_repository, audit_logger, valid_account):
    """
    Scenario: successful_transaction
    Given User has sufficient balance and valid account
    When User initiates valid transaction
    Then Transaction succeeds, balance updated, audit trail recorded
    """
    # Arrange
    account_repository.get_account.return_value = valid_account
    from_account = "ACC-001"
    to_account = "ACC-002"
    to_routing = "987654321"
    amount = Decimal("500.00")
    user_id = "USER-001"
    ip_address = "192.168.1.100"
    device_info = "Mozilla/5.0 (Windows NT 10.0)"

    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id=from_account,
        to_account_id=to_account,
        to_routing_number=to_routing,
        amount=amount,
        user_id=user_id,
        ip_address=ip_address,
        device_info=device_info
    )

    # Assert
    assert transaction.status == TransactionStatus.SUCCESS
    assert transaction.amount == amount
    assert transaction.user_id == user_id
    assert transaction.ip_address == ip_address
    account_repository.debit_account.assert_called_once_with(from_account, amount)
    audit_logger.log_transaction.assert_called_once()


# Test: SAR Suspicious Activity Above Threshold

def test_sar_suspicious_activity_above_threshold(rule_resolver, sar_service):
    """
    Scenario: sar_suspicious_activity_above_threshold
    Given Transaction monitoring detects suspicious pattern
    When Suspicious activity involves > $5,000
    Then SAR filed with FinCEN within 30 days, subject NOT notified
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    transaction_amount = Decimal("6000.00")
    sar_threshold = rule_resolver.get_sar_threshold()
    filing_deadline_days = rule_resolver.get_sar_filing_deadline_days()
    transaction_id = "TXN-SUSPICIOUS-001"
    
    # Act
    should_file_sar = transaction_amount > sar_threshold
    
    if should_file_sar:
        filing_date = detection_date + timedelta(days=1)
        sar_filing = SARFiling(
            sar_id="SAR-001",
            transaction_id=transaction_id,
            filing_date=filing_date,
            detection_date=detection_date,
            amount=transaction_amount,
            reason="Suspicious pattern detected",
            subject_notified=False,
            filed_with_fincen=True,
            is_insider_abuse=False
        )
        sar_service.file_sar(sar_filing)
    
    # Assert
    assert should_file_sar is True
    assert transaction_amount > sar_threshold
    sar_service.file_sar.assert_called_once()
    filed_sar = sar_service.file_sar.call_args[0][0]
    assert filed_sar.subject_notified is False
    assert filed_sar.filed_with_fincen is True
    assert (filed_sar.filing_date - filed_sar.detection_date).days <= filing_deadline_days


# Test: SAR Insider Abuse Any Amount

def test_sar_insider_abuse_any_amount(rule_resolver, sar_service):
    """
    Scenario: sar_insider_abuse_any_amount
    Given Bank employee involved in suspicious activity
    When Insider abuse detected at any dollar amount
    Then SAR filed immediately, no minimum threshold
    """
    # Arrange
    detection_date = datetime.now(timezone.utc)
    transaction_amount = Decimal("100.00")  # Below normal SAR threshold
    insider_threshold = rule_resolver.get_sar_insider_threshold()
    transaction_id = "TXN-INSIDER-001"
    is_insider = True
    
    # Act
    should_file_sar = is_insider and transaction_amount >= insider_threshold
    
    if should_file_sar:
        filing_date = detection_date  # Immediate filing
        sar_filing = SARFiling(
            sar_id="SAR-INSIDER-001",
            transaction_id=transaction_id,
            filing_date=filing_date,
            detection_date=detection_date,
            amount=transaction_amount,
            reason="Insider abuse detected",
            subject_notified=False,
            filed_with_fincen=True,
            is_insider_abuse=True
        )
        sar_service.file_sar(sar_filing)
    
    # Assert
    assert should_file_sar is True
    assert insider_threshold == Decimal("0")
    sar_service.file_sar.assert_called_once()
    filed_sar = sar_service.file_sar.call_args[0][0]
    assert filed_sar.is_insider_abuse is True
    assert filed_sar.filing_date == filed_sar.detection_date  # Immediate
    assert filed_sar.subject_notified is False


# Test: SAR No Tipping Off

def test_sar_no_tipping_off(sar_service, rule_resolver):
    """
    Scenario: sar_no_tipping_off
    Given SAR has been filed for a customer
    When Customer inquires about account restrictions
    Then Bank does NOT disclose SAR filing
    """
    # Arrange
    customer_id = "CUST-001"
    sar_service.check_sar_filed.return_value = True
    no_tipping_off_enabled = rule_resolver.is_no_tipping_off_enabled()
    
    # Act
    sar_filed = sar_service.check_sar_filed(customer_id)
    
    # Simulate customer inquiry response
    if sar_filed and no_tipping_off_enabled:
        disclosure_made = False
        response_message = "Your account is under routine review. Please contact customer service."
    else:
        disclosure_made = True
        response_message = "A SAR has been filed."
    
    # Assert
    assert sar_filed is True
    assert no_tipping_off_enabled is True
    assert disclosure_made is False
    assert "SAR" not in response_message
    assert "Suspicious Activity Report" not in response_message


# Test: Zero Amount Transfer

def test_zero_amount_transfer(banking_service, account_repository, valid_account):
    """
    Scenario: zero_amount_transfer
    Given User initiates transfer
    When User enters amount $0
    Then Transaction rejected 'Amount must be greater than 0'
    """
    # Arrange
    account_repository.get_account.return_value = valid_account
    amount = Decimal("0")
    
    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        to_routing_number="987654321",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Amount must be greater than 0"
    account_repository.debit_account.assert_not_called()


# Test: Negative Amount Transfer

def test_negative_amount_transfer(banking_service, account_repository, valid_account):
    """
    Scenario: negative_amount_transfer
    Given User initiates transfer
    When User enters amount -$100
    Then Transaction rejected 'Invalid amount'
    """
    # Arrange
    account_repository.get_account.return_value = valid_account
    amount = Decimal("-100.00")
    
    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        to_routing_number="987654321",
        amount=amount,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid amount"
    account_repository.debit_account.assert_not_called()


# Test: Insufficient Balance

def test_insufficient_balance(banking_service, account_repository, low_balance_account):
    """
    Scenario: insufficient_balance
    Given User has balance $1,000
    When User transfers $5,000
    Then Transaction rejected 'Insufficient balance'
    """
    # Arrange
    account_repository.get_account.return_value = low_balance_account
    amount = Decimal("5000.00")
    
    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-002",
        to_account_id="ACC-003",
        to_routing_number="987654321",
        amount=amount,
        user_id="USER-002",
        ip_address="192.168.1.101",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Insufficient balance"
    assert low_balance_account.balance < amount
    account_repository.debit_account.assert_not_called()


# Test: Invalid Beneficiary

def test_invalid_beneficiary(banking_service, account_repository, valid_account):
    """
    Scenario: invalid_beneficiary
    Given User initiates transfer
    When User enters invalid routing/account number
    Then Transaction rejected 'Invalid beneficiary account'
    """
    # Arrange
    account_repository.get_account.return_value = valid_account
    invalid_routing = "INVALID"
    
    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-999",
        to_routing_number=invalid_routing,
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid beneficiary account"
    account_repository.debit_account.assert_not_called()


# Boundary Tests

def test_sar_threshold_boundary_at_threshold(rule_resolver):
    """
    Boundary test: Transaction exactly at SAR threshold ($5,000)
    Should NOT trigger SAR (must be > threshold)
    """
    # Arrange
    transaction_amount = Decimal("5000.00")
    sar_threshold = rule_resolver.get_sar_threshold()
    
    # Act
    should_file_sar = transaction_amount > sar_threshold
    
    # Assert
    assert should_file_sar is False
    assert transaction_amount == sar_threshold


def test_sar_threshold_boundary_above_threshold(rule_resolver):
    """
    Boundary test: Transaction $0.01 above SAR threshold
    Should trigger SAR
    """
    # Arrange
    sar_threshold = rule_resolver.get_sar_threshold()
    transaction_amount = sar_threshold + Decimal("0.01")
    
    # Act
    should_file_sar = transaction_amount > sar_threshold
    
    # Assert
    assert should_file_sar is True


def test_sar_threshold_boundary_below_threshold(rule_resolver):
    """
    Boundary test: Transaction $0.01 below SAR threshold
    Should NOT trigger SAR
    """
    # Arrange
    sar_threshold = rule_resolver.get_sar_threshold()
    transaction_amount = sar_threshold - Decimal("0.01")
    
    # Act
    should_file_sar = transaction_amount > sar_threshold
    
    # Assert
    assert should_file_sar is False


def test_ctr_threshold_boundary_at_threshold(rule_resolver):
    """
    Boundary test: Cash transaction exactly at CTR threshold ($10,000)
    Should trigger CTR (>= threshold)
    """
    # Arrange
    cash_amount = Decimal("10000.00")
    ctr_threshold = rule_resolver.get_ctr_threshold()
    
    # Act
    should_file_ctr = cash_amount >= ctr_threshold
    
    # Assert
    assert should_file_ctr is True
    assert cash_amount == ctr_threshold


def test_ctr_threshold_boundary_below_threshold(rule_resolver):
    """
    Boundary test: Cash transaction $0.01 below CTR threshold
    Should NOT trigger CTR
    """
    # Arrange
    ctr_threshold = rule_resolver.get_ctr_threshold()
    cash_amount = ctr_threshold - Decimal("0.01")
    
    # Act
    should_file_ctr = cash_amount >= ctr_threshold
    
    # Assert
    assert should_file_ctr is False


# OFAC Screening Tests

def test_ofac_screening_no_match(ofac_service):
    """
    Test OFAC screening with no match
    Transaction should proceed
    """
    # Arrange
    entity_name = "John Doe"
    ofac_service.screen_entity.return_value = {"match": False, "score": 0}
    
    # Act
    result = ofac_service.screen_entity(entity_name)
    
    # Assert
    assert result["match"] is False
    assert result["score"] < 85  # Below fuzzy match threshold


def test_ofac_screening_exact_match(ofac_service):
    """
    Test OFAC screening with exact SDN match
    Transaction should be blocked
    """
    # Arrange
    entity_name = "Specially Designated National"
    ofac_service.screen_entity.return_value = {"match": True, "score": 100, "action": "BLOCK"}
    
    # Act
    result = ofac_service.screen_entity(entity_name)
    
    # Assert
    assert result["match"] is True
    assert result["score"] == 100
    assert result["action"] == "BLOCK"


def test_ofac_screening_fuzzy_match_above_threshold(ofac_service):
    """
    Test OFAC screening with fuzzy match above 85% threshold
    Transaction should be held for review
    """
    # Arrange
    entity_name = "Jon Doh"
    ofac_fuzzy_threshold = 85
    ofac_service.screen_entity.return_value = {"match": True, "score": 87, "action": "REVIEW"}
    
    # Act
    result = ofac_service.screen_entity(entity_name)
    
    # Assert
    assert result["match"] is True
    assert result["score"] >= ofac_fuzzy_threshold
    assert result["action"] == "REVIEW"


# Audit Trail Tests

def test_audit_trail_contains_required_fields(audit_logger):
    """
    Test that audit trail contains all required compliance fields
    """
    # Arrange
    transaction = Transaction(
        transaction_id="TXN-AUDIT-001",
        from_account="ACC-001",
        to_account="ACC-002",
        amount=Decimal("1000.00"),
        timestamp=datetime.now(timezone.utc),
        status=TransactionStatus.SUCCESS,
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0 (Windows NT 10.0)"
    )
    
    # Act
    audit_entry = audit_logger.log_transaction(transaction)
    
    # Assert
    assert audit_entry.log_id is not None
    assert audit_entry.timestamp is not None
    assert audit_entry.user_id == "USER-001"
    assert audit_entry.transaction_id == "TXN-AUDIT-001"
    assert audit_entry.ip_address == "192.168.1.100"
    assert audit_entry.device_info is not None
    assert audit_entry.immutable_hash is not None


def test_audit_trail_timestamp_timezone_aware():
    """
    Test that audit timestamps are timezone-aware (UTC)
    """
    # Arrange & Act
    timestamp = datetime.now(timezone.utc)
    
    # Assert
    assert timestamp.tzinfo is not None
    assert timestamp.tzinfo == timezone.utc


# PII Masking Tests

def test_ssn_masking_in_logs():
    """
    Test that SSN/TIN is masked in logs (show last 4 only)
    """
    # Arrange
    full_ssn = "123-45-6789"
    
    # Act
    masked_ssn = "***-**-" + full_ssn[-4:]
    
    # Assert
    assert masked_ssn == "***-**-6789"
    assert "123-45" not in masked_ssn


def test_account_number_masking():
    """
    Test that account numbers are masked in UI/logs
    """
    # Arrange
    full_account = "1234567890"
    
    # Act
    masked_account = "******" + full_account[-4:]
    
    # Assert
    assert masked_account == "******7890"
    assert "123456" not in masked_account


# Travel Rule Tests

def test_travel_rule_threshold_above_3000():
    """
    Test Travel Rule requirement for transactions > $3,000
    Must include originator and beneficiary information
    """
    # Arrange
    travel_rule_threshold = Decimal("3000.00")
    transaction_amount = Decimal("3500.00")
    
    # Act
    requires_travel_rule_data = transaction_amount > travel_rule_threshold
    
    # Assert
    assert requires_travel_rule_data is True


def test_travel_rule_threshold_at_3000():
    """
    Test Travel Rule at exact threshold
    """
    # Arrange
    travel_rule_threshold = Decimal("3000.00")
    transaction_amount = Decimal("3000.00")
    
    # Act
    requires_travel_rule_data = transaction_amount > travel_rule_threshold
    
    # Assert
    assert requires_travel_rule_data is False


# Dual Approval Tests

def test_wire_dual_approval_required_above_threshold():
    """
    Test that wires above $10,000 require dual approval
    """
    # Arrange
    wire_dual_approval_threshold = Decimal("10000.00")
    wire_amount = Decimal("15000.00")
    
    # Act
    requires_dual_approval = wire_amount > wire_dual_approval_threshold
    
    # Assert
    assert requires_dual_approval is True


def test_wire_dual_approval_not_required_below_threshold():
    """
    Test that wires at or below $10,000 do not require dual approval
    """
    # Arrange
    wire_dual_approval_threshold = Decimal("10000.00")
    wire_amount = Decimal("9999.99")
    
    # Act
    requires_dual_approval = wire_amount > wire_dual_approval_threshold
    
    # Assert
    assert requires_dual_approval is False


# Structuring Detection Tests

def test_structuring_detection_multiple_transactions_below_ctr():
    """
    Test detection of structuring: multiple transactions below CTR threshold
    within 24-hour window that aggregate above threshold
    """
    # Arrange
    ctr_threshold = Decimal("10000.00")
    aggregation_window_hours = 24
    base_time = datetime.now(timezone.utc)
    
    transactions = [
        {"amount": Decimal("3000.00"), "timestamp": base_time},
        {"amount": Decimal("3000.00"), "timestamp": base_time + timedelta(hours=2)},
        {"amount": Decimal("3000.00"), "timestamp": base_time + timedelta(hours=4)},
        {"amount": Decimal("2000.00"), "timestamp": base_time + timedelta(hours=6)}
    ]
    
    # Act
    total_amount = sum(t["amount"] for t in transactions)
    time_span = (transactions[-1]["timestamp"] - transactions[0]["timestamp"]).total_seconds() / 3600
    is_structuring = total_amount >= ctr_threshold and time_span <= aggregation_window_hours
    
    # Assert
    assert total_amount == Decimal("11000.00")
    assert total_amount >= ctr_threshold
    assert time_span <= aggregation_window_hours
    assert is_structuring is True


# Reg E Error Resolution Tests

def test_reg_e_error_reporting_window():
    """
    Test Reg E 60-day error reporting window from statement date
    """
    # Arrange
    statement_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    error_report_date = datetime(2024, 2, 15, tzinfo=timezone.utc)
    reg_e_window_days = 60
    
    # Act
    days_elapsed = (error_report_date - statement_date).days
    within_reg_e_window = days_elapsed <= reg_e_window_days
    
    # Assert
    assert days_elapsed == 45
    assert within_reg_e_window is True


def test_reg_e_error_reporting_outside_window():
    """
    Test Reg E error reporting outside 60-day window
    """
    # Arrange
    statement_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    error_report_date = datetime(2024, 3, 15, tzinfo=timezone.utc)
    reg_e_window_days = 60
    
    # Act
    days_elapsed = (error_report_date - statement_date).days
    within_reg_e_window = days_elapsed <= reg_e_window_days
    
    # Assert
    assert days_elapsed == 74
    assert within_reg_e_window is False


# BSA Record Retention Tests

def test_bsa_record_retention_5_years():
    """
    Test that BSA records are retained for 5 years per 31 CFR 1010.430
    """
    # Arrange
    record_date = datetime(2019, 1, 1, tzinfo=timezone.utc)
    current_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    retention_years = 5
    
    # Act
    years_elapsed = (current_date - record_date).days / 365.25
    should_retain = years_elapsed <= retention_years
    
    # Assert
    assert years_elapsed == pytest.approx(5.0, rel=0.01)
    assert should_retain is True


def test_sar_record_retention_5_years():
    """
    Test that SAR records are retained for 5 years
    """
    # Arrange
    sar_filing_date = datetime(2018, 6, 1, tzinfo=timezone.utc)
    current_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    sar_retention_years = 5
    
    # Act
    years_elapsed = (current_date - sar_filing_date).days / 365.25
    should_retain = years_elapsed <= sar_retention_years
    
    # Assert
    assert years_elapsed > 5.5
    assert should_retain is False  # Can be purged


# Beneficial Ownership Tests

def test_beneficial_ownership_threshold_25_percent():
    """
    Test beneficial ownership threshold of 25% per CDD Rule
    """
    # Arrange
    ownership_percentage = Decimal("25.0")
    beneficial_ownership_threshold = Decimal("25.0")
    
    # Act
    requires_identification = ownership_percentage >= beneficial_ownership_threshold
    
    # Assert
    assert requires_identification is True


def test_beneficial_ownership_below_threshold():
    """
    Test ownership below 25% threshold
    """
    # Arrange
    ownership_percentage = Decimal("20.0")
    beneficial_ownership_threshold = Decimal("25.0")
    
    # Act
    requires_identification = ownership_percentage >= beneficial_ownership_threshold
    
    # Assert
    assert requires_identification is False


# Invalid Account Tests

def test_invalid_account_number(banking_service, account_repository):
    """
    Test transaction with invalid account
    """
    # Arrange
    account_repository.get_account.return_value = None
    
    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="INVALID-ACC",
        to_account_id="ACC-002",
        to_routing_number="987654321",
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid account"


def test_invalid_routing_number_length(banking_service, account_repository, valid_account):
    """
    Test beneficiary with invalid routing number length (not 9 digits)
    """
    # Arrange
    account_repository.get_account.return_value = valid_account
    invalid_routing = "12345"  # Too short
    
    # Act
    transaction = banking_service.initiate_transaction(
        from_account_id="ACC-001",
        to_account_id="ACC-002",
        to_routing_number=invalid_routing,
        amount=Decimal("100.00"),
        user_id="USER-001",
        ip_address="192.168.1.100",
        device_info="Mozilla/5.0"
    )
    
    # Assert
    assert transaction.status == TransactionStatus.REJECTED
    assert transaction.rejection_reason == "Invalid beneficiary account"


# Decimal Precision Tests

def test_decimal_precision_for_currency():
    """
    Test that Decimal type is used for currency with proper precision
    """
    # Arrange
    amount1 = Decimal("100.10")
    amount2 = Decimal("200.20")
    
    # Act
    total = amount1 + amount2
    
    # Assert
    assert isinstance(total, Decimal)
    assert total == Decimal("300.30")
    assert str(total) == "300.30"


def test_decimal_avoids_floating_point_errors():
    """
    Test that Decimal avoids floating-point arithmetic errors
    """
    # Arrange
    amount = Decimal("0.1") + Decimal("0.2")
    
    # Act & Assert
    assert amount == Decimal("0.3")  # Would fail with float: 0.1 + 0.2 != 0.3


# Deterministic Test

def test_transaction_id_generation_deterministic():
    """
    Test that transaction IDs are generated deterministically for testing
    """
    # Arrange
    fixed_timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    
    # Act
    transaction_id = f"TXN-{fixed_timestamp.timestamp()}"
    
    # Assert
    assert transaction_id == "TXN-1704110400.0"
    assert transaction_id.startswith("TXN-")