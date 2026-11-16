# Academic Risky Email Dataset

Phishing and scam emails relevant to a college mailing community, filtered from public phishing/spam corpora. Built by [`../build_dataset.py`](../build_dataset.py).

## Files

| File | Rows | Contents |
|---|---|---|
| `academic_risky_emails.csv` | 1,033 | Risky emails with category, risk level and the evidence for each label |
| `academic_benign_emails.csv` | 6,185 | Legitimate emails with strong academic context (hard negatives) |
| `academic_emails_labeled.csv` | 7,218 | Both of the above, shuffled, with `is_risky` = 1 / 0 |
| `summary.json` | – | Counts by category, risk level and source |

## Categories

| Category | Rows | Risk | What it is |
|---|---|---|---|
| `credential_phishing` | 778 | high / critical | Webmail, LDAP, Outlook/Office 365 or IT-helpdesk lures: "mailbox quota exceeded", "password expires", "account will be deactivated", "re-validate your webmail". The same attack pattern as fake LDAP/AIMS password mails. `critical` = also explicitly addressed to faculty, staff or students. |
| `fake_degree` | 231 | low | Diploma-mill spam: "University degree in 4 weeks, no exams". |
| `scholarship_grant_scam` | 21 | low | Fake scholarship, financial-aid and "free government grant" offers. |
| `job_internship_scam` | 3 | medium | "College students: part-time work from home" money-mule style offers. |

Defined in the script but with no surviving matches in these corpora: `impersonation_bec` (gift-card requests from a "professor/HOD"), `fee_payment_scam`, `malicious_document` (fake timetable/result attachments) and `predatory_publishing`. The source corpora mostly predate these attack types.

## Columns (`academic_risky_emails.csv`)

| Column | Meaning |
|---|---|
| `id` | `ACAD-R-xxxxx` |
| `subject`, `body`, `sender` | Cleaned message (HTML, MIME parts, embedded headers removed). `subject`/`sender` are blank when the source didn't have them. |
| `category`, `secondary_categories` | Primary attack theme, plus any other themes that also matched |
| `risk_level` | `critical` > `high` > `medium` > `low` |
| `academic_context_score`, `academic_terms` | How many academic terms appear, and which ones (JSON) |
| `matched_cues` | The keyword cues that triggered each theme (JSON), useful for auditing labels |
| `has_url`, `num_urls`, `urls` | Extracted links |
| `sources` | Every corpus the message appeared in, separated by `;` |
| `near_duplicates` | How many near-identical copies (same template, different name/address) were merged into this row |

## How it was built

1. **Load** every message from Zenodo Merged (9 corpora), Figshare (Assassin, CEAS-08, Enron, Ling, TREC-05/06/07), Kaggle (CEAS_08, Enron, Ling, Nazario, Nigerian_Fraud, SpamAssassin) and EPVME (49,135 `.eml` files). This gives 547,059 rows. Kaggle's `phishing_email.csv` was excluded because it is a lowercased, stopword-stripped re-merge of the other Kaggle files.
2. **Deduplicate** on normalised subject+body. This leaves 390,557 unique messages. Messages whose label disagreed across corpora were dropped.
3. **Clean** HTML, MIME boundaries, quoted-printable encoding and the mail headers EPVME embeds in bodies.
4. **Score** each malicious message (label = 1) against an academic-context word list and the attack-theme cue lists. A theme fires only when several distinct cues match, for example "mailbox" + "quota exceeded" + "administrator".
5. **Filter out** spam that doesn't target a college: pharma, adult, stock pumps, mortgages, 419 scams, and bank/retail/courier brand phishing (PayPal, WaMu, AliExpress, DHL, …) unless it is clearly framed at a campus. Email addresses are ignored when scoring academic context, so a recipient list full of `.edu` addresses doesn't count.
6. **Near-dedupe** templates that differ only in name, number or address.
7. **Benign set**: legitimate emails (label = 0) with ≥ 3 academic terms from ≥ 2 groups (institution / people / activities).

## Quality and limitations

- **Precision:** a manual audit of 50 random `credential_phishing` rows found 48 correct. One was off-topic and one was mostly unreadable base64. Labels come from keyword rules, not human annotation; check `matched_cues` when a row looks wrong.
- **Generic vs. institution-specific:** most credential phishing addresses a generic "webmail user"; no public corpus has IITH-specific lures naming LDAP, AIMS or a specific portal.
- **Age:** the corpora are mostly from 2002–2021. Modern patterns such as QR-code phishing, MFA fatigue and fake Teams/Drive shares are under-represented.
- **Benign set:** leans toward technical academic mailing lists (R-help, Linguist List, UAI).
- **Not used:** Sting9. Its public GitHub dump currently contains only a licence file and its API endpoints didn't respond.

## Licences

Each row keeps its `sources`, so you can check the licence of the original corpus. Cite the original datasets when you publish: Zenodo 17314806 (Alhuzali et al., 2025), Figshare 25432108 (Seven Phishing Email Datasets), Kaggle naserabdullahalam/phishing-email-dataset, and EPVME (sunknighteric/EPVME-Dataset, research use).
