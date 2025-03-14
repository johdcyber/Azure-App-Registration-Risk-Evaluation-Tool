# Azure App Registration Risk Evaluation Tool

This tool scans **Azure Active Directory** for all tenant-wide app registrations, evaluates their permissions, and generates a **risk report** in CSV, JSON, and interactive HTML formats. It also provides details on **certificate and secret** status, creation dates, and other key security indicators to help you quickly identify risky apps or those needing certificate/secret updates.

*Written by JohnDcyber*  
Website: [johndcyber.com](https://johndcyber.com)

---

## Table of Contents
1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Scoring Methodology](#scoring-methodology)
4. [Output Fields](#output-fields)
5. [Additional Fields](#additional-fields)
6. [Usage Instructions](#usage-instructions)
7. [Output Details](#output-details)
8. [Technical Breakdown](#technical-breakdown)
9. [Value Proposition](#value-proposition)

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
   - Writes output to CSV, JSON, and an interactive HTML file that includes a bar chart of risk distribution and a DataTables-based table for filtering.

---

## Scoring Methodology

1. **Risk & Impact Scores**
   - Each known permission has a numeric *risk score* and an *impact score* defined in the `PERMISSION_RISK_SCORES` dictionary.
   - Example: `"Application.ReadWrite.All"` might be defined as `(100, 120, "Critical")`, contributing +100 to risk and +120 to impact.
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
   - A semicolon-separated string listing each permission that contributed to the total, for transparency and debugging.

---

## Output Fields

The final CSV, JSON, and HTML outputs include the following fields, along with why they matter and how to interpret them:

- **name**
  - **What It Is:** The display name of the app registration.
  - **Why It’s Important:** Quickly identifies the application in the Azure portal.
  - **How To Interpret:** Investigate further if a suspicious or unknown name shows a high risk.
- **app_id**
  - **What It Is:** The Application (client) ID.
  - **Why It’s Important:** Unique identifier used to reference the app in Azure AD.
  - **How To Interpret:** Cross-check the app in the Azure AD “App Registrations” blade.
- **created_on**
  - **What It Is:** The creation date of the app registration (formatted as MM/DD/YYYY).
  - **Why It’s Important:** Indicates how old the app is.
  - **How To Interpret:** Older apps may be more prone to misconfiguration or stale credentials.
- **certs_secrets**
  - **What It Is:** A summarized status of the earliest expiring certificate or secret.  
    Possible values: **Expired**, **Expiring soon**, **Current**, **None**.
  - **Why It’s Important:** Indicates if credentials might break production or be vulnerable if not renewed.
  - **How To Interpret:**
    - **Expired:** Investigate and renew or remove immediately.
    - **Expiring soon:** Plan to rotate credentials promptly.
    - **Current:** No immediate action needed.
    - **None:** Could be normal or a red flag, depending on expectations.
- **risk_category**
  - **What It Is:** The app’s risk classification (Critical, High, Medium, Low) based on its `risk_score`.
  - **Why It’s Important:** Flags apps requiring urgent attention.
  - **How To Interpret:** Critical apps should be remediated or justified; high-risk apps should be verified.
- **risk_score**
  - **What It Is:** The numeric sum of risk values across all permissions.
  - **Why It’s Important:** Quantifies how dangerous the app’s permissions are.
  - **How To Interpret:** Higher scores indicate greater potential security issues.
- **impact_score**
  - **What It Is:** The numeric sum of impact values across all permissions.
  - **Why It’s Important:** Reflects the potential blast radius if the app is compromised.
  - **How To Interpret:** High scores may indicate broad directory write access or other potent capabilities.
- **impact_rating**
  - **What It Is:** A classification (Critical, High, Medium, Low) of the total impact score.
  - **Why It’s Important:** Provides another severity dimension focused on potential damage.
  - **How To Interpret:** A high impact rating may require extra scrutiny even if the risk score is moderate.
- **details**
  - **What It Is:** A semicolon-separated list of permissions contributing to the risk score.
  - **Why It’s Important:** Offers transparency into which permissions drive the risk.
  - **How To Interpret:** Review the permissions to ensure they are necessary; remove any that are not.

---

## Additional Fields

- **Created On**
  - Derived from the `createdDateTime` property.
  - Parsed to a user-friendly `MM/DD/YYYY` format (or “Not Available” if missing).
- **Certificates & Secrets**
  - Determines the earliest expiration date among all `keyCredentials` (certs) and `passwordCredentials` (secrets).
  - Status values:
    - **Expired:** If the earliest expiration is in the past.
    - **Expiring soon:** If within the next 30 days (configurable via `EXPIRING_SOON_THRESHOLD_DAYS`).
    - **Current:** Otherwise.
    - **None:** If no credentials are present.

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
