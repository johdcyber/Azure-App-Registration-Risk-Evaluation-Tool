import json
import asyncio
import aiohttp
import logging
import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timezone, timedelta
from tqdm import tqdm
from azure.identity import AzureCliCredential
import difflib
import sys

# Configure logging (suitable for Cloud Shell)
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ========== CONFIGURATION ==========

# How many days before expiration to treat a credential as "Expiring soon"?
EXPIRING_SOON_THRESHOLD_DAYS = 30

# Expanded Risk Categorization: (risk_score, impact_score, risk_label)
PERMISSION_RISK_SCORES = {
    # Critical Risk Permissions
    "Application.ReadWrite.OwnedBy": (100, 120, "Critical"),
    "Application.ReadWrite.All": (100, 120, "Critical"),
    "PrivilegedAccess.ReadWrite.AzureResources": (100, 120, "Critical"),
    "Policy.ReadWrite.ConditionalAccess": (100, 120, "Critical"),
    "AuditLog.ReadWrite.All": (100, 120, "Critical"),
    "SecurityEvents.ReadWrite.All": (100, 120, "Critical"),
    
    # High-Risk Permissions
    "Directory.ReadWrite.All": (90, 100, "High"),
    "User.ReadWrite.All": (90, 100, "High"),
    "AppRoleAssignment.ReadWrite.All": (90, 100, "High"),
    "RoleManagement.ReadWrite.Directory": (90, 100, "High"),
    "Device.ReadWrite.All": (90, 100, "High"),
    "Domain.ReadWrite.All": (90, 100, "High"),
    "AccessReview.ReadWrite.All": (90, 100, "High"),
    "Reports.ReadWrite.All": (90, 100, "High"),
    
    # Medium-Risk Permissions
    "Group.ReadWrite.All": (50, 60, "Medium"),
    "Directory.Read.All": (50, 60, "Medium"),
    "User.Read.All": (50, 60, "Medium"),
    "Files.ReadWrite.All": (50, 60, "Medium"),
    "Sites.ReadWrite.All": (50, 60, "Medium"),
    "MailboxSettings.ReadWrite": (50, 60, "Medium"),
    "Calendars.ReadWrite": (50, 60, "Medium"),
    "Tasks.ReadWrite": (50, 60, "Medium"),
    
    # Low-Risk Permissions
    "User.Read": (10, 20, "Low"),
    "Group.Read.All": (10, 20, "Low"),
    "Files.Read.All": (10, 20, "Low"),
    "Sites.Read.All": (10, 20, "Low"),
    "Calendars.Read": (10, 20, "Low"),
    "Tasks.Read": (10, 20, "Low"),
}

# Static mapping from permission GUIDs to friendly names.
PERMISSION_ID_MAP = {
    # Application Permissions
    "df021288-bdef-4463-88db-98f22de89214": "Application.ReadWrite.OwnedBy",
    "f1c3a2d8-1234-4567-89ab-1234567890ab": "Application.ReadWrite.All",
    
    # User and Directory Permissions
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d": "User.Read",
    "a1b2c3d4-1234-5678-90ab-abcdef123456": "User.Read.All",
    "06da0dbc-49e2-44d2-8312-53f166ab848a": "User.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "b2d3e4f5-6789-0123-4567-89abcdef0123": "Directory.Read.All",
    
    # Group Permissions
    "c3d4e5f6-7890-1234-5678-90abcdef1234": "Group.Read.All",
    "d4e5f678-9012-3456-7890-abcdef123456": "Group.ReadWrite.All",
    
    # Security & Audit Permissions
    "e5f67890-1234-5678-90ab-cdef12345678": "AuditLog.Read.All",
    "f6789012-3456-7890-abcd-ef1234567890": "SecurityEvents.Read.All",
    "01234567-89ab-cdef-0123-456789abcdef": "Reports.Read.All",
    "12345678-9abc-def0-1234-56789abcdef0": "Policy.ReadWrite.ConditionalAccess",
    # Add any additional static mappings as needed...
}

def load_external_mapping(filename="permission_mapping.json"):
    """Load additional mappings from an external JSON file if it exists."""
    if os.path.exists(filename):
        try:
            with open(filename, "r") as f:
                data = json.load(f)
                logging.info(f"Loaded {len(data)} external permission mappings from {filename}")
                return {k.lower(): v for k, v in data.items()}
        except Exception as e:
            logging.error(f"Error loading external mapping: {e}")
    return {}

async def get_ms_graph_permission_mapping(session, token, sp_app_id):
    """
    Retrieve a mapping of permission GUIDs to friendly names from a service principal.
    For Microsoft Graph, use sp_app_id '00000003-0000-0000-c000-000000000000'.
    """
    url = f"{BASE_URL}/servicePrincipals?$filter=appId eq '{sp_app_id}'"
    headers = {"Authorization": f"Bearer {token}"}
    mapping = {}
    async with session.get(url, headers=headers) as response:
        if response.status == 200:
            data = await response.json()
            if data.get("value"):
                sp = data["value"][0]
                for role in sp.get("appRoles", []):
                    role_id = role.get("id", "").lower()
                    role_value = role.get("value")
                    if role_id and role_value:
                        mapping[role_id] = role_value
                for scope in sp.get("oauth2PermissionScopes", []):
                    scope_id = scope.get("id", "").lower()
                    scope_value = scope.get("value")
                    if scope_id and scope_value:
                        mapping[scope_id] = scope_value
                logging.info(f"Retrieved {len(mapping)} permissions from service principal {sp_app_id}")
            else:
                logging.error(f"No service principal found for appId {sp_app_id}")
        else:
            text = await response.text()
            logging.error(f"Error retrieving service principal {sp_app_id}: {text}")
    return mapping

# Output directory for reports and plots
OUTPUT_DIR = "reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Azure authentication using Azure CLI
credential = AzureCliCredential()
BASE_URL = "https://graph.microsoft.com/v1.0"

async def get_token():
    """Retrieve an access token for Microsoft Graph API."""
    token = credential.get_token("https://graph.microsoft.com/.default").token
    logging.info("AzureCliCredential.get_token succeeded")
    return token

async def get_app_registrations(session, token):
    """
    Retrieve all tenant-level app registrations from Microsoft Graph using pagination.
    Request 'createdDateTime', 'displayName', 'appId', 'requiredResourceAccess',
    'keyCredentials', and 'passwordCredentials' for each application.
    """
    all_apps = []
    select_params = "createdDateTime,displayName,appId,requiredResourceAccess,keyCredentials,passwordCredentials"
    url = f"{BASE_URL}/applications?$top=999&$select={select_params}"
    headers = {"Authorization": f"Bearer {token}"}
    while url:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                apps = data.get("value", [])
                all_apps.extend(apps)
                url = data.get("@odata.nextLink")
            else:
                text = await response.text()
                logging.error(f"Error retrieving apps: {text}")
                break
    logging.info(f"Total app registrations retrieved: {len(all_apps)}")
    return {"value": all_apps}

def compute_cert_secret_status(app) -> str:
    """
    Analyze the earliest expiring credential (certificate or secret) to categorize the
    status as 'Expired', 'Expiring soon', or 'Current'. If no credentials, return 'None'.
    
    IMPORTANT: We now use offset-aware datetimes for comparisons.
    """
    # Use offset-aware "now"
    now = datetime.now(timezone.utc)
    threshold = now + timedelta(days=EXPIRING_SOON_THRESHOLD_DAYS)

    keyCreds = app.get("keyCredentials", [])
    pwdCreds = app.get("passwordCredentials", [])
    if not keyCreds and not pwdCreds:
        return "None"

    earliest_expiry = None

    # Combine all credentials and check 'endDateTime'
    all_creds = keyCreds + pwdCreds
    for cred in all_creds:
        end_str = cred.get("endDateTime")
        if not end_str:
            continue
        try:
            # fromisoformat requires replacing "Z" with "+00:00"
            dt_parsed = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            # dt_parsed is offset-aware if parsed successfully
            if earliest_expiry is None or dt_parsed < earliest_expiry:
                earliest_expiry = dt_parsed
        except Exception:
            pass

    if not earliest_expiry:
        # No valid endDateTime found
        return "None"

    if earliest_expiry < now:
        return "Expired"
    elif earliest_expiry < threshold:
        return "Expiring soon"
    else:
        return "Current"

async def evaluate_risk(app):
    """
    Evaluate the security risk of an app registration by summing risk and impact scores.
    Checks both "Role" and "Scope" types and uses the merged permission mapping
    to resolve permission GUIDs to friendly names.
    """
    permissions = app.get("requiredResourceAccess", [])
    risk_score = 0
    impact_score = 0
    details = []

    for resource in permissions:
        for perm in resource.get("resourceAccess", []):
            perm_type = perm.get("type", "")
            if perm_type in ["Role", "Scope"]:
                perm_name = perm.get("value")
                if not perm_name:
                    perm_id = perm.get("id", "unknown").lower()
                    perm_name = PERMISSION_ID_MAP.get(perm_id)
                if perm_name:
                    perm_name_norm = perm_name.lower()
                else:
                    perm_name_norm = "unknown"
                risk_data = None
                # Exact match using normalized keys from risk dictionary
                for key, value in PERMISSION_RISK_SCORES.items():
                    if key.lower() == perm_name_norm:
                        risk_data = value
                        break
                # Fuzzy matching if no exact match is found
                if not risk_data and perm_name:
                    matches = difflib.get_close_matches(
                        perm_name, list(PERMISSION_RISK_SCORES.keys()), n=1, cutoff=0.7
                    )
                    if matches:
                        risk_data = PERMISSION_RISK_SCORES.get(matches[0])
                if not risk_data:
                    logging.debug(f"No risk data found for permission: {perm_name}")
                if risk_data:
                    risk_score += risk_data[0]
                    impact_score += risk_data[1]
                    details.append(f"{risk_data[2]} risk permission: {perm_name}")

    risk_category = (
        "Critical" if risk_score >= 100 else
        "High" if risk_score >= 90 else
        "Medium" if risk_score >= 50 else
        "Low"
    )
    impact_rating = (
        "Critical" if impact_score >= 100 else
        "High" if impact_score >= 60 else
        "Medium" if impact_score >= 30 else
        "Low"
    )

    return {
        "risk_category": risk_category,
        "risk_score": risk_score,
        "impact_score": impact_score,
        "impact_rating": impact_rating,
        "details": "; ".join(details)
    }

async def process_app(app):
    """
    Process an app registration: 
      1) Evaluate risk,
      2) Determine 'Created On' date,
      3) Determine certificate & secret status.
    """
    risk_info = await evaluate_risk(app)

    created_dt_str = app.get("createdDateTime", "Not Available")
    # Attempt to parse a friendlier date
    created_on = "Not Available"
    if created_dt_str:
        try:
            parsed = datetime.fromisoformat(created_dt_str.replace("Z", "+00:00"))
            created_on = parsed.strftime("%m/%d/%Y")
        except Exception:
            pass

    cert_secret_status = compute_cert_secret_status(app)

    # Merge final data
    return {
        "name": app.get("displayName", "Unknown"),
        "app_id": app.get("appId", "Unknown"),
        "created_on": created_on,
        "certs_secrets": cert_secret_status,
        **risk_info
    }

def plot_risk_distribution(results, timestamp):
    """Generate and save a bar plot showing the distribution of app risk categories."""
    df = pd.DataFrame(results)
    if df.empty or "risk_category" not in df:
        logging.warning("No risk category data to plot.")
        return None
    category_counts = df["risk_category"].value_counts()
    plt.figure(figsize=(8, 6))
    category_counts.plot(kind='bar')
    plt.title("Distribution of App Registrations by Risk Category")
    plt.xlabel("Risk Category")
    plt.ylabel("Count")
    plt.tight_layout()
    plot_file = os.path.join(OUTPUT_DIR, f"risk_distribution_{timestamp}.png")
    plt.savefig(plot_file)
    plt.close()
    logging.info(f"Risk distribution plot saved: {plot_file}")
    return os.path.basename(plot_file)

def generate_html_report(results, timestamp, plot_filename):
    """Generate an interactive HTML report with search, filtering, and analytics."""
    html_file = os.path.join(OUTPUT_DIR, f"app_risk_report_{timestamp}.html")
    df = pd.DataFrame(results)
    total_apps = len(df)
    avg_risk_score = df["risk_score"].mean() if not df.empty else 0
    risk_counts = df["risk_category"].value_counts().to_dict() if "risk_category" in df else {}
    table_html = df.to_html(index=False, classes="table table-striped", border=0, table_id="riskTable")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Azure App Risk Report</title>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/v/bs4/dt-1.10.24/datatables.min.css"/>
  <style>
      body {{ padding: 20px; }}
      .summary-box {{ margin-bottom: 20px; }}
  </style>
</head>
<body>
<div class="container-fluid">
  <h1 class="mb-4">Azure App Risk Report (Tenant-wide)</h1>
  <div class="row summary-box">
    <div class="col-md-4">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Total Applications</h5>
          <p class="card-text">{total_apps}</p>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Average Risk Score</h5>
          <p class="card-text">{avg_risk_score:.2f}</p>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Risk Distribution</h5>
          <p class="card-text">
    """

    for category, count in risk_counts.items():
        html_content += f"{category}: {count}<br>"
    html_content += f"""          </p>
        </div>
      </div>
    </div>
  </div>
  <h2>Risk Distribution Chart</h2>
  <img src="{plot_filename}" alt="Risk Distribution Chart" class="img-fluid mb-4"/>
  <h2>Application Risk Details</h2>
  {table_html}
</div>

<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
<script type="text/javascript" src="https://cdn.datatables.net/v/bs4/dt-1.10.24/datatables.min.js"></script>
<script>
  $(document).ready(function() {{
      $('#riskTable').DataTable({{
          "paging": true,
          "searching": true,
          "responsive": true
      }});
  }});
</script>
</body>
</html>
"""

    with open(html_file, "w") as f:
        f.write(html_content)
    logging.info(f"HTML report generated: {html_file}")

def generate_reports(results):
    """Generate CSV, JSON, and HTML reports along with a risk distribution plot."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_file = os.path.join(OUTPUT_DIR, f"app_risk_report_{timestamp}.csv")
    json_file = os.path.join(OUTPUT_DIR, f"app_risk_report_{timestamp}.json")

    df = pd.DataFrame(results)
    df.to_csv(csv_file, index=False)
    df.to_json(json_file, indent=4)
    logging.info(f"CSV report generated: {csv_file}")
    logging.info(f"JSON report generated: {json_file}")

    plot_filename = plot_risk_distribution(results, timestamp)
    if plot_filename:
        generate_html_report(results, timestamp, plot_filename)

async def main():
    logging.info("Starting Azure App Risk Evaluation Tool (Tenant-wide)")
    results = []
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
        token = await get_token()

        # Retrieve Microsoft Graph permission definitions from its service principal
        ms_graph_sp_appid = "00000003-0000-0000-c000-000000000000"
        ms_graph_mapping = await get_ms_graph_permission_mapping(session, token, ms_graph_sp_appid)

        # Load external mappings from file (if present)
        external_mapping = load_external_mapping("permission_mapping.json")

        # Merge all mappings
        combined_mapping = {**{k.lower(): v for k, v in PERMISSION_ID_MAP.items()},
                            **{k.lower(): v for k, v in ms_graph_mapping.items()},
                            **external_mapping}
        PERMISSION_ID_MAP.update(combined_mapping)

        logging.info(f"Updated permission mapping now has {len(PERMISSION_ID_MAP)} entries")

        # Retrieve all app registrations
        apps = await get_app_registrations(session, token)
        app_list = apps.get("value", [])
        logging.info(f"Found {len(app_list)} app registrations for the tenant")

        # Evaluate risk and gather additional data (created_on, cert/secret status)
        tasks = [process_app(app) for app in app_list]
        results = await asyncio.gather(*tasks)

    generate_reports(results)
    logging.info("Risk evaluation completed.")

if __name__ == "__main__":
    asyncio.run(main())
