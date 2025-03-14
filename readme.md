Azure App Registration Risk Evaluation Tool
---
This tool scans **Azure Active Directory** for all tenant-wide app registrations, evaluates their permissions, and generates a **risk report** in CSV, JSON, and interactive HTML formats. It also provides details on **certificate and secret** status, creation dates, and other key security indicators. The report can help you quickly identify risky apps or those that need certificate/secret updates.

---

## Table of Contents:

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
    - The script uses [AzureCliCredential](https://learn.microsoft.com/azure/developer/python/azure-sdk-authenticate?tabs=azure-cli) to authenticate to Azure.
    - Ensure you’ve logged in via `az login` or are running in Azure Cloud Shell.
2. **Data Retrieval**
    - The script calls the `/applications` endpoint of Microsoft Graph, requesting fields such as `displayName`, `appId`, `createdDateTime`, `keyCredentials`, and `passwordCredentials`.
    - It uses pagination to collect more than 999 results if necessary.
3. **Permission Mapping**
    - Before evaluating each app, it retrieves Microsoft Graph’s permission definitions from the `/servicePrincipals` endpoint (for the well-known appId `00000003-0000-0000-c000-000000000000`).
    - Merges these with the static `PERMISSION_ID_MAP` and an optional external JSON file (`permission_mapping.json`).
4. **Risk Evaluation**
    - Each permission in `requiredResourceAccess` is resolved to a friendly name.
    - The script sums up the associated risk and impact scores (defined in `PERMISSION_RISK_SCORES`) and categorizes the app’s overall risk.
5. **Certificate/Secret Expiration**
    - For each app, the script inspects the earliest expiration date among `keyCredentials` (certificates) and `passwordCredentials` (secrets).
    - It labels them based on how soon they expire (`Expired`, `Expiring soon`, `Current`, or `None`).
6. **Reporting**
    - The results are compiled into a list of dictionaries and then written to CSV, JSON, and an interactive HTML file.
    - The HTML file includes a bar chart of risk distribution and a DataTables-based table for easy filtering.

---

## Scoring Methodology

1. **Risk & Impact Scores**
    - Each known permission has a numeric *risk score* and an *impact score* defined in the `PERMISSION_RISK_SCORES` dictionary.
    - For instance, `"Application.ReadWrite.All"` might have `(100, 120, "Critical")`, meaning it contributes +100 to risk and +120 to impact.
2. **Risk Category**
    - Summed `risk_score` determines the final category:
        - **Critical:** `risk_score >= 100`
        - **High:** `risk_score >= 90`
        - **Medium:** `risk_score >= 50`
        - **Low:** Otherwise
3. **Impact Rating**
    - Summed `impact_score` determines the final rating:
        - **Critical:** `impact_score >= 100`
        - **High:** `impact_score >= 60`
        - **Medium:** `impact_score >= 30`
        - **Low:** Otherwise
4. **Details**
    - A string listing each permission that contributed to the total, for transparency and debugging.

## Output Fields

Below are the fields in the final CSV, JSON, and HTML outputs, **why they matter**, and **how to interpret them**:

1. **name**
    - **What It Is**: The display name of the app registration.
    - **Why It’s Important**: Quickly identifies the application in the Azure portal.
    - **How To Interpret**: If you see a suspicious or unknown name with high risk, investigate further.
2. **app_id**
    - **What It Is**: The Application (client) ID.
    - **Why It’s Important**: Unique identifier to reference the app in Azure AD.
    - **How To Interpret**: Use it to cross-check the app in the Azure AD “App Registrations” blade.
3. **created_on**
    - **What It Is**: The date the app registration was created (formatted as MM/DD/YYYY).
    - **Why It’s Important**: Shows how old the app is.
    - **How To Interpret**: An older app that hasn’t been maintained could be more prone to misconfiguration or stale credentials.
4. **certs_secrets**
    - **What It Is**: A summarized status of the earliest expiring certificate or secret. Possible values: **Expired**, **Expiring soon**, **Current**, or **None**.
    - **Why It’s Important**: Expired or soon-to-expire credentials can break production or be exploited if not renewed.
    - **How To Interpret**:
        - **Expired**: Immediately investigate and renew or remove.
        - **Expiring soon**: Plan to rotate credentials promptly.
        - **Current**: No immediate action needed.
        - **None**: The app has no credentials, which might be normal for some apps or suspicious if you expect them to have credentials.
5. **risk_category**
    - **What It Is**: The final classification of the app’s risk, based on `risk_score` (Critical, High, Medium, Low).
    - **Why It’s Important**: Quickly flags apps that require urgent attention.
    - **How To Interpret**:
        - **Critical**: The app has powerful or broad permissions—remediate or justify.
        - **High**: Contains significant risk—verify it’s truly needed.
        - **Medium**: Possibly acceptable, but review if it’s truly necessary.
        - **Low**: Minimal risk, typically standard user-level permissions.
6. **risk_score**
    - **What It Is**: The summed numeric risk value across all permissions.
    - **Why It’s Important**: Gives a quantifiable measure of how potentially dangerous the app’s permissions are.
    - **How To Interpret**: The higher the score, the more likely the app could cause security issues if compromised.
7. **impact_score**
    - **What It Is**: The summed numeric impact value across all permissions.
    - **Why It’s Important**: Reflects how big a blast radius the app has if compromised.
    - **How To Interpret**: High impact often means broad directory write access or other potent capabilities.
8. **impact_rating**
    - **What It Is**: A classification of the total impact score (Critical, High, Medium, Low).
    - **Why It’s Important**: Another dimension of severity, focusing on potential damage.
    - **How To Interpret**: Even if an app’s risk score is moderate, a high impact rating might still require careful oversight.
9. **details**
    - **What It Is**: A semicolon-separated list of the permissions that contributed to the risk score.
    - **Why It’s Important**: Offers transparency into which permissions are pushing the app’s risk up.
    - **How To Interpret**: Check if these permissions are actually needed. If not, remove them.

---

---

## Additional Fields

1. **Created On**
    - Derived from the `createdDateTime` property.
    - Parsed to a user-friendly `MM/DD/YYYY` format (or “Not Available” if missing).
2. **Certificates & Secrets**
    - Determines the earliest expiration date among all `keyCredentials` (certs) and `passwordCredentials` (secrets).
    - Status is:
        - **Expired:** if the earliest expiration is in the past.
        - **Expiring soon:** if it’s within the next 30 days (configurable via `EXPIRING_SOON_THRESHOLD_DAYS`).
        - **Current:** otherwise.
        - **None:** if there are no credentials.

---

## Usage Instructions

1. **Prerequisites**
    - Python 3.7+
    - Required libraries: `aiohttp`, `azure-identity`, `pandas`, `matplotlib`, `tqdm`, etc.
    - Logged in with the Azure CLI (e.g., `az login`) or running in Azure Cloud Shell.
2. **Clone & Run**
    1. Clone or download the script.
    2. Install dependencies, for example:
        
        ```
        pip install aiohttp azure-identity pandas matplotlib tqdm
        
        ```
        

### 

Run the script:

```python
python3 app_risk_evaluation.py

```

**Output**

- The script creates a `reports/` directory with:
    - **CSV:** `app_risk_report_YYYYMMDD_HHMMSS.csv`
    - **JSON:** `app_risk_report_YYYYMMDD_HHMMSS.json`
    - **HTML:** `app_risk_report_YYYYMMDD_HHMMSS.html`
    - **PNG:** `risk_distribution_YYYYMMDD_HHMMSS.png` (embedded in the HTML)

---

## Output Details

1. **CSV & JSON**
    - Columns/keys include:
        - `name`: Display name of the app
        - `app_id`: Application (client) ID
        - `created_on`: Formatted creation date
        - `certs_secrets`: Certificate & secret status (Expired, Expiring soon, Current, None)
        - `risk_category`: (Critical, High, Medium, Low)
        - `risk_score`: Summed numeric score
        - `impact_score`: Summed numeric score
        - `impact_rating`: (Critical, High, Medium, Low)
        - `details`: Semicolon-separated list of matched permissions
2. **HTML**
    - **Risk Distribution Chart**: A bar chart of how many apps fall into each category.
    - **Interactive Table**: Searchable, filterable, and sortable table (using DataTables).
    - Columns match the CSV fields.

---

## Technical Breakdown

1. **Authentication**
    - Uses `AzureCliCredential` from `azure.identity`, so you must be logged into Azure via `az login` or running in Cloud Shell.
2. **Pagination**
    - The script calls `/applications` with `$top=999`. If there’s an `@odata.nextLink`, it keeps calling until all apps are retrieved.
3. **Permission Mapping**
    - A static dictionary (`PERMISSION_ID_MAP`) with known GUID–friendly name mappings.
    - Dynamically retrieved definitions from the Microsoft Graph service principal (appId `00000003-0000-0000-c000-000000000000`).
    - An external JSON file (`permission_mapping.json`) can be loaded if present.
    - All these mappings are merged into a single dictionary (lowercased keys) to handle near-complete coverage of permissions.
4. **Risk Evaluation**
    - For each permission in `requiredResourceAccess`, the script checks if it’s a “Role” or “Scope.”
    - Resolves the GUID to a friendly name if needed, then sums up risk/impact.
    - Classifies the final score into risk category and impact rating.
5. **Certificate/Secret Status**
    - Looks at `keyCredentials` (certificates) and `passwordCredentials` (secrets).
    - Finds the earliest expiration date, comparing it to the current UTC time (`datetime.now(timezone.utc)`), ensuring offset-aware comparisons.
6. **Reporting**
    - Data is stored in a list of dictionaries, then converted into a `pandas` DataFrame for CSV, JSON, and HTML generation.
    - A bar chart is created using `matplotlib` to visualize the distribution of risk categories.
    - The HTML report uses DataTables for an interactive table experience.

---

## Value Proposition

1. **Security Visibility**
    - Identifies high-risk permissions (like `Application.ReadWrite.All` or `Directory.ReadWrite.All`) quickly.
    - Highlights expired or soon-to-expire certificates and secrets.
2. **Proactive Remediation**
    - By surfacing critical or soon-to-expire credentials, teams can update them before they break production or cause security issues.
    - Pinpoints apps that haven’t been updated in a long time or have dangerously broad permissions.
3. **Comprehensive Coverage**
    - Loops through all app registrations, merges multiple sources of permission data, and checks certificates and secrets.
    - Provides a single consolidated view that security and IAM teams can act on.
4. **Actionable Reports**
    - CSV and JSON for machine-readable or programmatic consumption.
    - HTML with search, filter, and sorting for immediate human review.
    - Risk distribution chart for at-a-glance insight into the overall posture.

By using this script, Azure AD administrators and security teams can **improve compliance, reduce exposure**, and maintain better oversight of all registered apps, their permissions, and their credential hygiene.
