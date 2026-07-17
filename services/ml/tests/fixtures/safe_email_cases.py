"""Small, synthetic, non-deliverable fixtures for scenario-level regression tests."""

from __future__ import annotations


def raw_email(index: int, subject: str, body: str, *, html: str | None = None) -> str:
    headers = (
        f"From: Fixture Sender <sender{index}@example.com>\n"
        f"To: recipient@example.net\nDate: Thu, 17 Jul 2026 10:{index % 60:02d}:00 +0000\n"
        f"Message-ID: <fixture-{index}@example.com>\nSubject: {subject}\n"
    )
    if html is None:
        return f"{headers}Content-Type: text/plain; charset=utf-8\n\n{body}"
    return f"{headers}MIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=x{index}\n\n--x{index}\nContent-Type: text/plain\n\n{body}\n--x{index}\nContent-Type: text/html\n\n{html}\n--x{index}--"


PHISHING_SCENARIOS = [
    ("facebook_impersonation", "Facebook activity review", "Review account activity now.", '<a href="https://facebook-review.example.net/login">https://www.facebook.com/security</a>'),
    ("credential", "Password expires today", "Confirm your password at hxxps://account-review.example[.]net/login", None),
    ("invoice", "Unpaid invoice", "Pay invoice INV-100 at hxxps://billing-review.example[.]org/invoice", None),
    ("delivery", "Delivery failed", "Pay a redelivery fee at hxxps://parcel-update.example[.]com/track", None),
    ("suspension", "Account suspension", "Verify within six hours at hxxps://secure-check.example[.]net/verify", None),
    ("payroll", "Payroll interrupted", "Re-enter payroll credentials at hxxps://payroll.example[.]net", None),
    ("qr_lure", "Account QR verification", "Scan the supplied QR code to verify your account password and prevent access from expiring.", None),
    ("refund", "Refund pending", "Submit banking details at hxxps://refund.example[.]net/claim", None),
    ("mailbox", "Mailbox full", "Verify your mailbox password to keep messages.", None),
    ("gift_cards", "Confidential request", "Buy gift cards and send the codes immediately.", None),
    ("mfa", "MFA reset", "Restore access at hxxps://mfa-reset.example[.]com", None),
    ("tax", "Tax refund", "Confirm identity and banking information today.", None),
    ("fake_job", "Remote position available", "Remote position, no interview required. Pay for training and submit banking details today.", None),
    ("support", "Support validation", "Reply with your recovery code.", None),
    ("cryptocurrency", "Wallet recovery required", "Send bitcoin to the listed crypto wallet to restore access.", None),
]

LEGITIMATE_SCENARIOS = [
    ("project", "Project meeting", "The project meeting is Tuesday. The agenda is in our workspace."),
    ("support", "Support case update", "Reply with issue details. We will never ask for your password."),
    ("security", "Account security reminder", "Open the official app directly to review account security."),
    ("password", "Password training", "Annual password security training is in the employee portal."),
    ("invoice", "Invoice received", "Invoice INV-200 is queued for normal approval."),
    ("delivery", "Office delivery", "Office supplies arrive Friday; no payment is required."),
    ("calendar", "Meeting notes", "Approved meeting notes are in the team workspace."),
    ("hr", "Benefits calendar", "Contact HR through the directory with questions."),
    ("maintenance", "Planned maintenance", "No account action is required."),
    ("receipt", "Payment receipt", "The approved order payment is complete."),
    ("code_review", "Pull request review", "Please leave comments in the repository."),
    ("newsletter", "Monthly update", "Product release notes and webinars are available."),
    ("travel", "Travel itinerary", "The approved itinerary is attached as a PDF."),
    ("training", "Security workshop", "The workshop discusses phishing and secure passwords."),
    ("customer", "Customer follow-up", "Thank you for contacting support about your account."),
]

HARD_NEGATIVES = [
    ("password_reset_confirmation", "Password changed", "Your password was changed successfully. If this was not you, open the official app."),
    ("account_lockout_policy", "Account lockout policy", "Security policy locks an account after repeated password failures."),
    ("invoice_escalation", "Invoice escalation meeting", "The overdue invoice will be reviewed by finance; do not pay from this email."),
    ("delivery_security", "Secure delivery guidance", "Never pay an unexpected delivery fee from an email link."),
    ("phishing_training", "Phishing simulation training", "This training explains urgent credential phishing and fake login pages."),
    ("support_warning", "Support security notice", "Support will not request recovery codes or passwords."),
    ("mfa_policy", "MFA policy", "Account security requires MFA; enroll only through the official portal."),
    ("bank_notification", "Bank transaction notice", "The bank confirmed the card transaction in the official app; no reply or login is required."),
    ("brand_guidance", "Facebook security guidance", "Navigate directly to facebook.com for account security settings."),
    ("otp_notice", "One-time code notice", "Your OTP is for the sign-in you started. Staff will never ask you to send the code by email."),
]

DISAGREEMENT_SCENARIOS = [
    ("benign_rules_flag", "Account review meeting", "The security team will review your account at https://security.example.com/login."),
    ("subtle_phish", "Recent activity", "Please review the activity using the page below."),
    ("invoice_context", "Invoice question", "Could you confirm whether invoice INV-301 belongs to your team?"),
    ("trusted_link_mismatch", "Shared page", "Open the company page.", '<a href="https://review.example.net">https://www.microsoft.com</a>'),
    ("display_name", "Routine notice", "Review when convenient."),
]

INCOMPLETE_INPUTS = [
    {"id": f"incomplete-{index}", "category": "incomplete", "input_mode": "quick_paste", "subject": subject, "body": body}
    for index, (subject, body) in enumerate([
        ("Account security", "Review account security in the official application."),
        ("Invoice", "Please review the invoice with finance."),
        ("Delivery", "A delivery is expected tomorrow."),
        ("Password", "Never send your password by email."),
        ("Support", "Support has updated your case."),
    ], start=1)
]

RAW_CASES = []
for category, scenarios in (("phishing", PHISHING_SCENARIOS), ("legitimate", LEGITIMATE_SCENARIOS), ("hard_negative", HARD_NEGATIVES), ("disagreement", DISAGREEMENT_SCENARIOS)):
    for index, item in enumerate(scenarios, start=len(RAW_CASES) + 1):
        scenario, subject, body, *html = item
        RAW_CASES.append({"id": f"{category}-{index}", "category": category, "scenario": scenario, "input_mode": "raw_email", "raw_email": raw_email(index, subject, body, html=html[0] if html else None)})

ALL_CASES = RAW_CASES + INCOMPLETE_INPUTS
