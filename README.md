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

---

## SECTION 2: LOG ANALYTICS & KQL EMERGENCIES (DATA-PLANE TRACING)

The greatest vulnerability in machine identity architecture is the **"Silent 403."**

This occurs when the portal sign-in log shows a 100% Success state (the token handshake passed), but the automated runner still crashes because it cannot read the targeted digital vault or database. This happens because the identity was bound to an infrastructure Control-Plane management role instead of an explicit Data-Plane asset role.

To expose these downstream faults, you must stream your directory and asset telemetry into an Azure Log Analytics Workspace.

### 2.1 Key Log Tables Defined
* `AADNonInteractiveUserSignInLogs`: Tracks external OIDC passwordless token exchanges into the directory.
* `KeyVaultRequests` / `StorageBlobLogs` (Resource-Specific) or `AzureDiagnostics` (Legacy): Data-plane asset tables tracking actual transactions inside target resource vaults.

### 2.2 Plain Talk KQL Analysis & Time-Window Correlation
Instead of hunting through thousands of rows of raw JSON text, you can execute a streamlined Kusto query to instantly isolate identity failures. Note that Entra ID authentication correlation IDs do not natively flow into resource data-plane logs; therefore, queries correlate using Application/Service Principal IDs aligned within a narrow execution time window (5-10 minutes).

In plain speech, this query tells the cloud: *"Show me every non-human application identity that successfully authenticated to our directory, but experienced a downstream HTTP 403 access denial on an asset vault within 5 minutes of token issuance."*

#### Why "Commands & Circumstances" Superiority Works
Relying on hardcoded KQL snippets in a manual or ledger is increasingly outdated because of **schema drift**. Microsoft regularly updates table structures—for example, migrating from legacy `AzureDiagnostics` to resource-specific tables like `KeyVaultSecurityEvents` or changing column names across API versions. Hardcoded code breaks easily and lacks context.

Documenting the **Operational Circumstances** and **AI Intent Commands** instead of raw KQL is significantly better for three major reasons:
* **Schema Drift Immunity:** Azure or target platform log schemas change over time. An AI agent inspecting your live Log Analytics workspace can dynamically query table metadata and write syntactically correct KQL on the fly for whatever schema version is active today.
* **Universal Portability:** A static KQL query only works in Azure Log Analytics. If you ever need to run the same audit in Splunk, Datadog, or Microsoft Sentinel, static KQL is useless. An intent-based command allows AI to instantly generate the query in KQL, SPL, or SQL depending on where you paste it.
* **Focus on Security Logic over Syntax:** Auditors and engineers shouldn't be debugging missing commas or deprecated column names. Documenting the precise circumstances (the time delta, event IDs, and correlation keys) keeps the focus on the security verification logic rather than query syntax maintenance.

#### Comparison Example

❌ **The Old Way (Static KQL - Brittle):**
```kql
// Brittle: Breaks if table schemas change or columns are renamed
ServicePrincipalSignInLogs
| where TimeGenerated > ago(24h)
| where AppId == "22df9133-520e-4fd6-b456-e564190116fc"
| join kind=inner (
    AzureDiagnostics 
    | where Resource == "KV-COMPCODE1-AI-VAULT"
) on CorrelationId
```

✅ **The Modern Way (Circumstance & Intent Command):**
* **Audit Circumstance:** Correlating OIDC federated token issuance with data-plane Key Vault operations to detect unauthorized access outside execution windows.
* **AI Prompt Directive:** *"Inspect the active Log Analytics schema. Write a query that joins `ServicePrincipalSignInLogs` for App ID `22df9133-520e-4fd6-b456-e564190116fc` with Key Vault data-plane access logs (`AuditEvent` or resource-specific equivalent) for vault `kv-compcode1-ai-vault`. Group by 60-minute time buckets to highlight any clock skew or orphaned access events."*

By storing the Circumstance and the Prompt Directive, your write-ups become living, future-proof instructions that any AI assistant can execute across any log platform or schema version.

---

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
