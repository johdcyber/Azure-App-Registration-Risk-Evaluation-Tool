# Azure App Registration Risk Evaluation Tool

This tool scans **Azure Active Directory** for all tenant-wide app registrations, evaluates their permissions, and generates a **risk report** in CSV, JSON, and interactive HTML formats. It also provides details on **certificate and secret** status, creation dates, and other key security indicators to help you quickly identify risky apps or those needing certificate/secret updates.

*Written by JohnDcyber*  
Website: [johndcyber.com](https://johndcyber.com)

---

## Value Proposition

1. **Security Visibility**
   - Quickly identifies high-risk permissions (e.g., `Application.ReadWrite.All`, `Directory.ReadWrite.All`).
   - Highlights expired or soon-to-expire certificates and secrets.

2. **Proactive Remediation**
   - Surfaces critical or expiring credentials, allowing teams to update them before they cause production issues or security breaches.
   - Pinpoints apps that haven’t been updated in a long time or that have overly broad permissions.

3. **Comprehensive Coverage**
   - Scans all app registrations, merging multiple sources of permission data and checking credential statuses.
   - Provides a consolidated view for security and IAM teams to act upon.

4. **Actionable Reports**
   - Offers machine-readable CSV and JSON outputs for automated processes.
   - Delivers an interactive HTML report with search, filter, and sorting capabilities.
   - Includes a risk distribution chart for quick, at-a-glance insights into overall risk posture.

Using this tool, Azure AD administrators and security teams can **improve compliance, reduce exposure**, and maintain better oversight of all registered apps, their permissions, and credential hygiene.


---

## Table of Contents
1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Scoring Methodology](#scoring-methodology)
4. [Output](#output)
5. [Output Details](#output-details)
6. [Technical Breakdown](#technical-breakdown)
7. [Value Proposition](#value-proposition)
8. [Usage Instructions](#usage-instructions)

---

## Features

1. **Tenant-Wide Scanning**
   - Uses pagination to retrieve *all* app registrations in your Azure AD tenant (not just the first page).

2. **Permission Mapping**
   - Combines a static dictionary of known permission GUIDs with dynamic data from the Microsoft Graph service principal and an optional external JSON file.
   - Converts permission GUIDs to friendly names for easier risk analysis.

3. **Risk Evaluation**
   - Summarizes permissions into a total risk and impact score.
   - Assigns each application a **Risk Category** (Critical, High, Medium, Low) and **Impact Rating** (Critical, High, Medium, Low).

4. **Certificate & Secret Analysis**
   - Identifies the earliest expiring credential (certificate or secret) and flags it as “Expired,” “Expiring soon,” or “Current” (or “None” if no credentials are present).

5. **Creation Date**
   - Displays each app’s creation date in a friendly format (MM/DD/YYYY).

6. **Comprehensive Reporting**
   - Generates CSV, JSON, and an interactive HTML report (with a DataTables-based table and a risk distribution chart).
   - The HTML report allows you to search, filter, and sort results to quickly find high-risk or soon-to-expire apps.

---

## How It Works

1. **Authentication**
   - Uses [AzureCliCredential](https://learn.microsoft.com/azure/developer/python/azure-sdk-authenticate?tabs=azure-cli) to authenticate to Azure.
   - Ensure you’ve logged in via `az login` or are running in Azure Cloud Shell.

2. **Data Retrieval**
   - Calls the `/applications` endpoint of Microsoft Graph, requesting fields such as `displayName`, `appId`, `createdDateTime`, `keyCredentials`, and `passwordCredentials`.
   - Uses pagination to collect more than 999 results if necessary.

3. **Permission Mapping**
   - Retrieves Microsoft Graph’s permission definitions from the `/servicePrincipals` endpoint (for the well-known appId `00000003-0000-0000-c000-000000000000`).
   - Merges these definitions with the static `PERMISSION_ID_MAP` and an optional external JSON file (`permission_mapping.json`).

4. **Risk Evaluation**
   - Resolves each permission in `requiredResourceAccess` to a friendly name.
   - Sums up the associated risk and impact scores (as defined in `PERMISSION_RISK_SCORES`) and categorizes the app’s overall risk.

5. **Certificate/Secret Expiration**
   - Inspects the earliest expiration date among `keyCredentials` (certificates) and `passwordCredentials` (secrets).
   - Labels them as `Expired`, `Expiring soon`, `Current`, or `None` based on the expiration status.

6. **Reporting**
   - Compiles the results into a list of dictionaries.
   - Converts the data into a `pandas` DataFrame for CSV, JSON, and HTML generation.
   - Creates a bar chart using `matplotlib` to visualize the distribution of risk categories.
   - The HTML report integrates DataTables for an interactive table experience.

---

## Scoring Methodology

1. **Risk & Impact Scores**
   - Each known permission has a numeric *risk score* and an *impact score* defined in the `PERMISSION_RISK_SCORES` dictionary.
   - *Example:* `"Application.ReadWrite.All"` might be defined as `(100, 120, "Critical")`, contributing +100 to risk and +120 to impact.

2. **Risk Category**
   - The summed `risk_score` determines the final category:
     - **Critical:** `risk_score >= 100`
     - **High:** `risk_score >= 90`
     - **Medium:** `risk_score >= 50`
     - **Low:** Otherwise

3. **Impact Rating**
   - The summed `impact_score` determines the final rating:
     - **Critical:** `impact_score >= 100`
     - **High:** `impact_score >= 60`
     - **Medium:** `impact_score >= 30`
     - **Low:** Otherwise

4. **Details**
   - A semicolon-separated string listing each permission that contributed to the risk score for transparency and debugging.

---

## Output

- The script creates a `reports/` directory with:
  - **CSV:** `app_risk_report_YYYYMMDD_HHMMSS.csv`
  - **JSON:** `app_risk_report_YYYYMMDD_HHMMSS.json`
  - **HTML:** `app_risk_report_YYYYMMDD_HHMMSS.html`
  - **PNG:** `risk_distribution_YYYYMMDD_HHMMSS.png` (embedded in the HTML)

---

## Output Details

1. **CSV & JSON**
   - **Columns/keys include:**
     - `name`: Display name of the app
     - `app_id`: Application (client) ID
     - `created_on`: Formatted creation date
     - `certs_secrets`: Certificate & secret status (*Expired*, *Expiring soon*, *Current*, *None*)
     - `risk_category`: (Critical, High, Medium, Low)
     - `risk_score`: Summed numeric score
     - `impact_score`: Summed numeric score
     - `impact_rating`: (Critical, High, Medium, Low)
     - `details`: Semicolon-separated list of matched permissions

2. **HTML**
   - **Risk Distribution Chart:** A bar chart showing how many apps fall into each risk category.
   - **Interactive Table:** A searchable, filterable, and sortable table (powered by DataTables) with columns matching those in the CSV.

---

## Technical Breakdown

1. **Authentication**
   - Uses `AzureCliCredential` from `azure.identity`, so you must be logged into Azure via `az login` or running in Cloud Shell.

2. **Pagination**
   - Calls `/applications` with `$top=999`. If an `@odata.nextLink` is present, it continues retrieving all apps.

3. **Permission Mapping**
   - Uses a static dictionary (`PERMISSION_ID_MAP`) with known GUID–friendly name mappings.
   - Retrieves dynamic definitions from the Microsoft Graph service principal (appId `00000003-0000-0000-c000-000000000000`).
   - Optionally loads an external JSON file (`permission_mapping.json`) and merges all mappings (using lowercased keys) to achieve near-complete coverage.

4. **Risk Evaluation**
   - Checks each permission in `requiredResourceAccess` for its type (Role or Scope).
   - Resolves GUIDs to friendly names, sums risk and impact scores, and classifies the app’s overall risk category and impact rating.

5. **Certificate/Secret Status**
   - Evaluates `keyCredentials` (certificates) and `passwordCredentials` (secrets) to find the earliest expiration date.
   - Compares expiration dates to the current UTC time (`datetime.now(timezone.utc)`) to determine status.

6. **Reporting**
   - Stores data as a list of dictionaries, converts it to a `pandas` DataFrame, and generates CSV, JSON, and HTML outputs.
   - Creates a risk distribution bar chart with `matplotlib` and embeds it in the HTML report.
   - Uses DataTables to enable an interactive table experience in the HTML report.



---

## Usage Instructions

### Prerequisites
- Python 3.7+
- Required libraries: `aiohttp`, `azure-identity`, `pandas`, `matplotlib`, `tqdm`, etc.
- Must be logged in with the Azure CLI (e.g., `az login`) or running in Azure Cloud Shell.

### Clone & Run

1. **Clone or Download the Script**

2. **Install Dependencies**
   ```bash
   pip install aiohttp azure-identity pandas matplotlib tqdm

3. **Run the script:**
  ```bash
   python3 AZ-APP-Reg-Risk-Eval-Tool.py
