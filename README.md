# THE AI AND CLOUD PIPELINE HARDENING FRAMEWORK (ACPHF)
## Practical Log Navigation & Audit Guide (IAL v2.1)

---

### THE CORE PHILOSOPHY OF LOG VERIFICATION

Auditing a passwordless machine identity is completely different from auditing a human user. A human user exhibits unpredictable behavior across multiple devices and geolocations. A machine identity is a deterministic piece of software. It executes specific code, from a specific runner host, targeting a specific data asset.

Because we enforce the AI and Cloud Pipeline Hardening Framework (ACPHF), we do not waste energy hunting for random anomalies. Instead, we audit for binary alignment. We use cloud logs to verify that the runtime reality matches our structural engineering specifications.

There are only two core log management interfaces required to validate this framework:
* **The Microsoft Entra ID Sign-In Logs Portal:** The primary visual landing zone to verify the initial cryptographic handshake.
* **The Azure Log Analytics Workspace (Using Kusto Query Language / KQL):** The deep-dive query engine to trace long-term trends and catch silent, downstream data-plane authorization drops.

---

## SECTION 1: THE PORTAL SIGN-IN MATRIX (QUICK VISUAL AUDITS)

To trace passwordless token exchange handshakes visually in the Microsoft Entra ID Admin Center, navigate directly to:  
`Monitoring` ➔ `Sign-in logs` ➔ `Non-interactive user sign-ins`

When reviewing these line entries, you are validating the first three boundaries of the framework using plain talk:

### 1.1 The Inbound Coordinates Check
* **Telemetry Target:** Incoming Tenant ID and Application ID fields.
* **Plain Talk Meaning:** Did the external runner find your specific directory, or did it knock on the wrong door? If the Application ID is blank or unmapped, the runner is passing a coordinate that does not exist in your tenant.

### 1.2 The Conditional Trust Handshake
* **Telemetry Target:** Status: Success vs. Failure (ErrorCode: `AADSTS70021`, `AADSTS70022`, or `500121`).
* **Plain Talk Meaning:** This is where strict, case-sensitive Subject Claim validation happens. If an engineer typed `refs/heads/Main` with a capital M in GitHub, but the Entra ID Federated Credential policy expects a lowercase m (`refs/heads/main`), the portal will log a hard authentication failure right here (typically flagging `AADSTS70021`: *No matching federated identity record found*). The handshake drops dead at the perimeter.

### 1.3 The Token Volatility Lifetime
* **Telemetry Target:** Timestamp spacing between subsequent successful sign-ins from the exact same application identity.
* **Plain Talk Meaning:** Because our protocol strictly enforces a 60-minute Access Token ceiling and blocks Refresh Tokens entirely, a long-running pipeline or continuous AI workload must re-authenticate. If you see an identical application successfully logging in every 55 to 60 minutes on the dot, the script is successfully handling token volatility. If it logs in once and crashes exactly 60 minutes later, the script failed to loop back and re-authenticate.

##SECTION 2: LOG ANALYTICS DATA-PLANE TRACING (GATE 4 RUNBOOK)

To trace data-plane authorization and verify zero "Silent 403" access drops, navigate in the Azure Portal directly to:
Azure Portal ➔ Log Analytics Workspaces ➔ [Target Workspace] ➔ General ➔ Logs

##2.1 Operational Execution Path

**Step 1: Open the query editor for the Log Analytics workspace configured to ingest diagnostics from 'kv-compcode1-ai-vault'.

**Step 2: Execute the data-plane correlation query using Method A (Direct KQL Execution) or Method B (Universal AI Directive).

**[ Method A: Direct KQL Execution ]
KeyVaultRequests
| where TimeGenerated > ago(24h)
| where VaultName =~ "kv-compcode1-ai-vault"
| where IdentityCode == "22df9133-520e-4fd6-b456-e564190116fc" or AppId == "22df9133-520e-4fd6-b456-e564190116fc"
| project TimeGenerated, VaultName, OperationName, ResultSignature, HttpStatusCode, CallerIpAddress, IdentityCode
| sort by TimeGenerated desc

**[ Method B: Universal AI Intent Directive ]
Audit Circumstance: Correlating OIDC federated token issuance with data-plane Key Vault operations to detect unauthorized access outside execution windows.
AI Prompt Directive: "Inspect active Log Analytics schema. Query Key Vault data-plane logs for vault kv-compcode1-ai-vault and App ID 22df9133-520e-4fd6-b456-e564190116fc over the last 24 hours. Display the timestamp, operation name, result status, and HTTP status code."

##2.2 Telemetry Field Inspection Matrix

**Inspect the returned log telemetry against the required baseline values:

| Column Name | Baseline Value | Operational Verification Meaning |
| :--- | :--- | :--- |
| OperationName | SecretGet | Confirms the machine identity initiated a secret read action. |
| HttpStatusCode | 200 | Confirms the target vault validated the token and released the secret payload. |
| ResultSignature | OK | Confirms zero cryptographic or access control errors occurred during extraction. |
| IdentityCode / AppId | 22df9133-520e-4fd6-b456-e564190116fc | Confirms the access event belonged strictly to the target bot identity. |

##2.3 Audit Gate 4 Boolean Outcome Criteria

PASS: A log row exists containing OperationName == 'SecretGet' and HttpStatusCode == 200. Data-plane access is fully verified.
FAIL (Silent 403): A log row exists containing HttpStatusCode == 403 or ResultSignature == 'Unauthorized'. The identity successfully authenticated to the directory but lacks data-plane RBAC permissions on the vault asset.
FAIL (Orphan Run): Zero log entries exist within 5 minutes of a successful Entra ID sign-in event. The pipeline runner failed to connect to the vault endpoint entirely.



## SECTION 3: SYSTEM VALIDATOR & TROUBLESHOOTING CHECKLIST

This operational checklist acts as your live navigation map during an active deployment or system audit. Run through these four questions to instantly resolve any pipeline blockages:

### Audit Gate 1: Coordinate Check
* **Key Verification Question:** Is the external automation runner passing the exact, matching target Directory ID and Application ID?
* **Failure Symptom & Diagnostics:** Pipeline logs show immediate network routing errors or target subscription mapping faults. Unmapped AppIDs reflect non-existent tenant targets.

### Audit Gate 2: Character Check
* **Key Verification Question:** Does the string case in your external repository path match the Federated Credential configuration character-for-character?
* **Failure Symptom & Diagnostics:** Entra ID sign-in logs flag hard authentication failure (e.g., `AADSTS70021`) at the token exchange endpoint due to subject claim mismatch.

### Audit Gate 3: Clock Check
* **Key Verification Question:** Is the automated pipeline or AI agent loop attempting to run continuously for longer than 60 minutes without requesting a fresh token?
* **Failure Symptom & Diagnostics:** Script crashes with an expired token error because Refresh Tokens are natively blocked under short-lived access token policies.

### Audit Gate 4: Plane Check
* **Key Verification Question:** Did you assign the machine identity an infrastructure management role instead of a granular data-plane role?
* **Failure Symptom & Diagnostics:** Sign-in logs show explicit "Success," but downstream pipeline output throws immediate 403 Forbidden errors during asset access.
