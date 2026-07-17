"""Build the English-first training corpus and frozen external benchmark.

Raw downloads and generated CSVs are intentionally git-ignored. Only this
reproducible builder, documentation, and small regression fixtures are tracked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from phishshield_ml.dataset import MIN_ENGLISH_PERCENTAGE, canonicalize_template, estimate_language
from phishshield_ml.preprocessing import normalize_email_text


CORE_SOURCE = "zenodo-social-engineering-15235123"
EXTERNAL_SOURCE = "zenodo-validation-13474746"
FINAL_BENCHMARK_SOURCE = "kaggle-contextual-email-deception-cc0"

PHISHING_TEMPLATES = [
    ("credential", "Account access review {n}", "We noticed unusual activity. Confirm your password at hxxps://account-review{n}.example[.]net/login within {hours} hours to prevent restricted access."),
    ("facebook_impersonation", "Facebook security review {n}", "We noticed activity on your Facebook account. Review it at hxxps://facebook-review{n}.example[.]net/security. Access may be limited if the review is not completed."),
    ("invoice", "Invoice {invoice} requires attention", "The attached invoice has an unpaid balance of ${amount}. Open hxxps://billing-review{n}.example[.]org/invoice and confirm payment today."),
    ("delivery", "Delivery attempt {n}", "Your parcel could not be delivered. Pay the small redelivery charge at hxxps://parcel-update{n}.example[.]com/track to choose a new date."),
    ("account_suspension", "Urgent account suspension notice {n}", "Your account is scheduled for suspension. Sign in through hxxps://secure-check{n}.example[.]net/verify within {hours} hours to keep access."),
    ("support_impersonation", "Support case {ticket}", "Customer support detected an ownership issue. Reply with your recovery code or use hxxps://case-desk{n}.example[.]org/login to validate the account."),
    ("payroll", "Payroll profile update {n}", "Payroll processing is paused. Re-enter your employee credentials at hxxps://payroll-confirm{n}.example[.]net before the next payment run."),
    ("shared_document", "A secure document was shared", "A document is waiting for your signature. Authenticate at hxxps://document-access{n}.example[.]com/view to prevent the request from expiring."),
    ("refund", "Refund available {n}", "A refund of ${amount} is pending. Submit your banking details at hxxps://refund-desk{n}.example[.]org/claim to receive it."),
    ("mailbox_quota", "Mailbox quota warning {n}", "Your mailbox is over quota and messages may be removed. Verify the mailbox password at hxxps://mail-quota{n}.example[.]net."),
    ("executive_request", "Confidential request {ticket}", "I am in a meeting. Purchase gift cards worth ${amount} and send the codes immediately. Do not call because this is confidential."),
    ("mfa", "Multi-factor authentication reset {n}", "Your authentication token was disabled. Scan the code or sign in at hxxps://mfa-reset{n}.example[.]com to restore access."),
]

LEGITIMATE_TEMPLATES = [
    ("project", "Project update {ticket}", "Hello team, the project review is scheduled for {day}. The agenda and action items are in our internal workspace. No response is needed before the meeting."),
    ("customer_support", "Support case {ticket} update", "Hello, support case {ticket} remains open. Please reply to this email with a description of the issue. We will never ask for your password or recovery code."),
    ("security_notice", "Account security reminder {n}", "This is a routine security reminder. Review your account settings by opening the official application directly. Never share your password by email."),
    ("password_policy", "Password policy training {n}", "The annual account and password security training is available in the employee portal. Use your existing bookmark; this message contains no sign-in link."),
    ("invoice", "Invoice {invoice} received", "Finance received invoice {invoice} for ${amount}. It is queued for the normal approval meeting on {day}. Contact the procurement team with questions."),
    ("delivery", "Office delivery scheduled {n}", "The office supply delivery is scheduled for {day} between 10:00 and 12:00. Reception already has the purchase order and no payment is required."),
    ("calendar", "Meeting notes {ticket}", "Thanks for today's discussion. The approved notes, owners, and due dates are stored in the team workspace. Our next meeting is {day}."),
    ("hr", "Benefits information {n}", "Human Resources published the benefits calendar. Read it in the employee portal or contact HR through the directory. Do not send personal information by email."),
    ("maintenance", "Planned maintenance {n}", "The service will undergo planned maintenance on {day}. Existing sessions may reconnect automatically. There is no required account action."),
    ("receipt", "Payment receipt {invoice}", "This confirms the approved payment for order {invoice}. The transaction was completed through the existing company account. Keep this email for your records."),
    ("code_review", "Code review {ticket}", "The pull request is ready for review. Please leave comments in the repository before {day}. The change does not affect account security settings."),
    ("newsletter", "Monthly product newsletter {n}", "Here is the monthly product update, including release notes and upcoming webinars. Manage newsletter preferences through the company website."),
]

TRAINING_ANCHORS = [
    (1, "facebook_impersonation", "Facebook account activity notice", "A recent sign-in was recorded for your Facebook profile. Inspect the event on the security page. If you recognize it, no response is necessary."),
    (1, "credential", "Account protection notice", "A security check is pending. The message asks you to confirm account credentials through a supplied page."),
    (1, "invoice", "Payment document needs review", "A sender demands immediate settlement of an unexpected bill through a new payment page."),
    (1, "delivery", "Parcel address problem", "A delivery message requests personal details and a small fee through an unfamiliar tracking page."),
    (1, "account_suspension", "Access limitation warning", "The notice threatens to restrict account access unless identity details are submitted quickly."),
    (1, "support_impersonation", "Help desk ownership check", "A supposed support agent asks for a recovery code to prove ownership of the account."),
    (1, "payroll", "Salary profile interrupted", "The recipient is directed to enter employee sign-in details before payroll can continue."),
    (1, "shared_document", "Protected file waiting", "The document invitation requires authentication on an unrelated site before it expires."),
    (1, "refund", "Reimbursement requires bank data", "The message promises money but first requests banking information through a claim form."),
    (1, "mailbox_quota", "Email storage termination", "The warning says stored mail will be deleted unless the mailbox password is confirmed."),
    (1, "executive_request", "Private purchasing task", "An executive impersonator asks an employee to buy prepaid cards and quietly return the codes."),
    (1, "mfa", "Authenticator recovery required", "A fake authentication notice directs the recipient to a new site to restore the security token."),
    (0, "project", "Engineering project status", "The team reviewed milestones and will discuss open work during the scheduled project meeting."),
    (0, "customer_support", "Customer support follow-up", "Support confirmed the case remains open and explicitly says not to send passwords or recovery codes."),
    (0, "security_notice", "Routine security education", "Employees should open the official application directly when reviewing account security settings."),
    (0, "password_policy", "Password policy workshop", "The training explains secure password handling and warns against entering credentials from email links."),
    (0, "invoice", "Procurement invoice review", "Finance will review the supplier invoice during the ordinary approval meeting; no email payment is requested."),
    (0, "delivery", "Reception delivery schedule", "Reception expects the office shipment and already holds the purchase order, so no fee is due."),
    (0, "calendar", "Team meeting follow-up", "Meeting notes and assigned actions are available in the established internal workspace."),
    (0, "hr", "Employee benefits information", "Human Resources published the benefits schedule and directs questions to the known company directory."),
    (0, "maintenance", "Service maintenance window", "The application may reconnect after planned maintenance and no account action is required."),
    (0, "receipt", "Approved purchase receipt", "This is a record of a completed company purchase and does not request further payment."),
    (0, "code_review", "Repository review request", "Developers should leave technical comments on the existing pull request before the team review."),
    (0, "newsletter", "Product news digest", "The monthly newsletter summarizes product releases, documentation updates, and scheduled webinars."),
]


def _parse_social_engineering(path: Path) -> tuple[list[dict], Counter]:
    frame = pd.read_excel(path)
    rows: list[dict] = []
    excluded = Counter()
    for index, row in frame.iterrows():
        raw = str(row.get("Corpus", "")) if pd.notna(row.get("Corpus")) else ""
        supplied_label = str(row.get("Labels", "")) if pd.notna(row.get("Labels")) else ""
        if "\t" in raw:
            text, label = raw.rsplit("\t", 1)
        elif "\t" in supplied_label:
            continuation, label = supplied_label.rsplit("\t", 1)
            text = f"{raw} {continuation}"
        else:
            text, label = raw, supplied_label
        text, label = normalize_email_text(text), label.strip()
        if label == "Phishing":
            binary = 1
        elif label == "NOT-Malicious General Class":
            binary = 0
        else:
            excluded[label or "malformed"] += 1
            continue
        rows.append({
            "text": text,
            "label": binary,
            "source": CORE_SOURCE,
            "provenance_type": "real_or_curated",
            "scenario": "source_phishing" if binary else "source_legitimate",
            "template_group": f"{CORE_SOURCE}-{hashlib.sha256(canonicalize_template(text).encode()).hexdigest()[:20]}",
        })
    return rows, excluded


def _synthetic_rows(variants_per_template: int = 25) -> list[dict]:
    rows: list[dict] = []
    for label, templates in ((1, PHISHING_TEMPLATES), (0, LEGITIMATE_TEMPLATES)):
        for template_index, (scenario, subject_template, body_template) in enumerate(templates):
            for n in range(1, variants_per_template + 1):
                values = {
                    "n": n,
                    "hours": (n % 4 + 1) * 6,
                    "amount": 40 + n * 7,
                    "invoice": f"INV-{template_index + 1:02d}-{1000 + n}",
                    "ticket": f"CASE-{template_index + 1:02d}-{2000 + n}",
                    "day": ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")[n % 5],
                }
                subject = subject_template.format(**values)
                body = body_template.format(**values)
                rows.append({
                    "text": f"Subject: {subject}\n\n{body}",
                    "label": label,
                    "source": "phishphage-safe-synthetic-v2",
                    "provenance_type": "synthetic",
                    "scenario": scenario,
                    "template_group": f"synthetic-{'phish' if label else 'legit'}-{template_index:02d}",
                    "split_role": "development_pool",
                })
    for index, (label, scenario, subject, body) in enumerate(TRAINING_ANCHORS):
        rows.append({
            "text": f"Subject: {subject}\n\n{body}", "label": label,
            "source": "phishphage-targeted-training-anchors-v2", "provenance_type": "synthetic_training_anchor",
            "scenario": scenario, "template_group": f"training-anchor-{index:02d}", "split_role": "train_only",
        })
    return rows


def _external_rows(path: Path) -> tuple[list[dict], dict]:
    frame = pd.read_csv(path)
    mapping = {"Safe Email": 0, "Phishing Email": 1}
    rows = []
    input_count = len(frame)
    for _, row in frame.iterrows():
        text = normalize_email_text(row.get("Email Text", ""))
        label = mapping.get(row.get("Email Type"))
        if text and label is not None:
            rows.append({"text": text, "label": label, "source": EXTERNAL_SOURCE, "provenance_type": "external_benchmark", "scenario": "external", "template_group": hashlib.sha256(canonicalize_template(text).encode()).hexdigest()[:20]})
    clean = pd.DataFrame(rows).drop_duplicates(subset=["text"], keep="first")
    return clean.to_dict("records"), {"input_rows": input_count, "clean_rows": len(clean), "exact_duplicates_removed": len(rows) - len(clean)}


def _audit_languages(frame: pd.DataFrame) -> pd.DataFrame:
    estimates = [estimate_language(text) for text in frame["text"]]
    frame = frame.copy()
    frame["language"] = [language for language, _ in estimates]
    frame["language_confidence"] = [round(confidence, 6) for _, confidence in estimates]
    return frame


def _final_benchmark_rows(path: Path) -> tuple[pd.DataFrame, dict]:
    source = pd.read_csv(path)
    required = {"subject", "body", "label", "language", "category"}
    if missing := required - set(source.columns):
        raise ValueError(f"Missing final benchmark columns: {sorted(missing)}")
    frame = pd.DataFrame({
        "text": (source["subject"].fillna("") + "\n\n" + source["body"].fillna("")).map(normalize_email_text),
        "label": source["label"].astype(int), "source": FINAL_BENCHMARK_SOURCE,
        "provenance_type": "final_external_benchmark", "scenario": source["category"].astype(str),
    })
    input_rows = len(frame)
    frame = frame[frame.text.str.len() > 0].drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    frame["template_group"] = frame.text.map(lambda text: hashlib.sha256(canonicalize_template(text).encode()).hexdigest()[:20])
    frame = _audit_languages(frame)
    return frame, {
        "input_rows": input_rows, "clean_rows": len(frame),
        "exact_duplicates_removed": input_rows - len(frame),
        "class_counts": {"legitimate": int((frame.label == 0).sum()), "phishing": int((frame.label == 1).sum())},
        "spam_indicator_counts_excluded_from_labels": {
            str(key): int(value) for key, value in source["spam_indicator"].value_counts().to_dict().items()
        } if "spam_indicator" in source else {},
    }


def build(core_source: Path, external_source: Path, output: Path, external_output: Path, audit_output: Path, final_benchmark_source: Path | None = None, final_benchmark_output: Path | None = None) -> dict:
    source_rows, excluded = _parse_social_engineering(core_source)
    core = pd.DataFrame(source_rows + _synthetic_rows())
    before_dedup = len(core)
    core = core[core["text"].str.len() > 0].drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    core = _audit_languages(core)
    english_percentage = 100.0 * float(core["language"].eq("en").mean())
    if english_percentage < MIN_ENGLISH_PERCENTAGE:
        raise ValueError(f"English-language gate failed: {english_percentage:.2f}%")

    external_rows, external_cleaning = _external_rows(external_source)
    external = _audit_languages(pd.DataFrame(external_rows))
    overlap = set(core["text"]) & set(external["text"])
    if overlap:
        raise ValueError(f"Core/external exact-text leakage detected ({len(overlap)} rows)")

    output.parent.mkdir(parents=True, exist_ok=True)
    core.to_csv(output, index=False)
    external.to_csv(external_output, index=False)
    final_summary = None
    if final_benchmark_source and final_benchmark_output:
        final_benchmark, final_summary = _final_benchmark_rows(final_benchmark_source)
        if set(core["text"]) & set(final_benchmark["text"]):
            raise ValueError("Core/final benchmark exact-text leakage detected")
        final_benchmark.to_csv(final_benchmark_output, index=False)
    counts = core.groupby(["provenance_type", "label"]).size().to_dict()
    language_breakdown = [
        {"source": source, "label": "phishing" if int(label) else "legitimate", "language": language, "rows": int(rows)}
        for (source, label, language), rows in core.groupby(["source", "label", "language"]).size().items()
    ]
    audit = {
        "hard_gate": {"minimum_english_percentage": MIN_ENGLISH_PERCENTAGE, "passed": True},
        "core": {
            "rows_before_cleaning": before_dedup,
            "rows_after_cleaning": len(core),
            "exact_duplicates_removed": before_dedup - len(core),
            "class_counts": {"legitimate": int((core.label == 0).sum()), "phishing": int((core.label == 1).sum())},
            "language_counts": core.language.value_counts().to_dict(),
            "language_counts_by_source_and_label": language_breakdown,
            "required_language_label_counts": {
                "english_legitimate": int(((core.language == "en") & (core.label == 0)).sum()),
                "english_phishing": int(((core.language == "en") & (core.label == 1)).sum()),
                "spanish_legitimate": int(((core.language == "es") & (core.label == 0)).sum()),
                "spanish_phishing": int(((core.language == "es") & (core.label == 1)).sum()),
                "unknown_or_other": int((~core.language.isin(["en", "es"])).sum()),
            },
            "english_percentage": round(english_percentage, 4),
            "provenance_counts": {f"{kind}:{'phishing' if label else 'legitimate'}": int(value) for (kind, label), value in counts.items()},
            "template_groups": int(core.template_group.nunique()),
        },
        "excluded_source_classes": dict(excluded),
        "external_benchmark": {
            **external_cleaning,
            "class_counts": {"legitimate": int((external.label == 0).sum()), "phishing": int((external.label == 1).sum())},
            "language_counts": external.language.value_counts().to_dict(),
            "used_for_training_or_threshold_selection": False,
            "core_exact_text_overlap": 0,
        },
        "final_external_benchmark": ({**final_summary, "used_for_training_threshold_or_candidate_selection": False, "evaluation_status": "sealed until final model selection"} if final_summary else None),
        "sources": [
            {"id": CORE_SOURCE, "doi": "10.5281/zenodo.15235123", "license": "CC BY 4.0", "role": "core real/curated English"},
            {"id": "phishphage-safe-synthetic-v2", "license": "repository project license", "role": "core synthetic coverage", "safety": "reserved example domains only"},
            {"id": EXTERNAL_SOURCE, "doi": "10.5281/zenodo.13474746", "license": "CC BY 4.0", "role": "development benchmark; not the final untouched benchmark"},
            {"id": FINAL_BENCHMARK_SOURCE, "url": "https://www.kaggle.com/datasets/freshersstaff/contextual-email-deception-detection-dataset", "license": "CC0 1.0", "role": "sealed final external benchmark", "limitations": "synthetic and highly templated; spam_indicator is ignored and never mapped to phishing"},
        ],
    }
    audit_output.parent.mkdir(parents=True, exist_ok=True)
    audit_output.write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")
    return audit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-source", required=True)
    parser.add_argument("--external-source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--external-output", required=True)
    parser.add_argument("--audit-output", required=True)
    parser.add_argument("--final-benchmark-source")
    parser.add_argument("--final-benchmark-output")
    args = parser.parse_args()
    result = build(Path(args.core_source), Path(args.external_source), Path(args.output), Path(args.external_output), Path(args.audit_output), Path(args.final_benchmark_source) if args.final_benchmark_source else None, Path(args.final_benchmark_output) if args.final_benchmark_output else None)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
