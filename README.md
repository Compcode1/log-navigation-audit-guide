# The AI and Cloud Pipeline Hardening Framework (ACPHF)
## Practical Log Navigation & Audit Guide (IAL v2)

---

## The Core Philosophy of Log Verification 

Auditing a passwordless machine identity is completely different from auditing a human user. A human user exhibits unpredictable behavior across multiple devices and geolocations. A machine identity is a deterministic piece of software. It executes specific code, from a specific runner host, targeting a specific data asset.

Because we enforce the **AI and Cloud Pipeline Hardening Framework (ACPHF)**, we do not waste energy hunting for random anomalies. Instead, we audit for **binary alignment**. We use cloud logs to verify that the runtime reality matches our structural engineering specifications.

There are only two core log management interfaces required to validate this framework:
1. **The Microsoft Entra ID Sign-In Logs Portal:** The primary visual landing zone to verify the initial cryptographic handshake.
2. **The Azure Log Analytics Workspace (Using Kusto Query Language / KQL):** The deep-dive query engine to trace long-term trends and catch silent, downstream data-plane authorization drops.

---

## Section 1: The Portal Sign-In Matrix (Quick Visual Audits)

To trace passwordless token exchange handshakes visually in the Microsoft Entra ID Admin Center, navigate directly to:  
`Monitoring` ➔ `Sign-in logs` ➔ `Non-interactive user sign-ins`

When reviewing these line entries, you are validating the first three boundaries of the framework using plain talk:

### 1.1 The Inbound Coordinates Check
* **Telemetry Target:** Incoming `Tenant ID` and `Application ID` fields.
* **Plain Talk Meaning:** Did the external runner find your specific directory, or did it knock on the wrong door? If the Application ID is blank or unmapped, the runner is passing a coordinate that does not exist in your tenant.

### 1.2 The Conditional Trust Handshake & Error Code Glossary
* **Telemetry Target:** `Status: Success` vs. `Failure` (`ResultType` codes).
* **Plain Talk Meaning:** This is where strict, case-sensitive Subject Claim validation happens. If string casing or metadata identifiers do not align perfectly, Entra ID logs an explicit failure code.

| Entra ID Error Code | Root Cause Diagnostic | Plain Talk Meaning |
| :--- | :--- | :--- |
| **`AADSTS700213`** | Subject Claim Mismatch | The incoming OIDC token string does not match the Federated Credential policy. (Common with GitHub's immutable database claims or string casing errors). |
| **`AADSTS700211`** | Issuer URL Mismatch | The external runner's OIDC issuer authority URL is incorrect or untrusted by the identity directory. |
| **`AADSTS500121`** | Authentication / Policy Fault | General federation failure or block triggered during the initial token validation handshake. |

### 1.3 The Token Volatility Lifetime
* **Telemetry Target:** Timestamp spacing between subsequent successful sign-ins from the exact same application identity.
* **Plain Talk Meaning:** Because our protocol strictly enforces a 60-minute Access Token ceiling and blocks Refresh Tokens entirely, a long-running pipeline or continuous AI workload must re-authenticate. If you see an identical application successfully logging in every 55 to 60 minutes on the dot, the script is successfully handling token volatility. If it logs in once and crashes exactly 60 minutes later, the script failed to loop back and re-authenticate.

---

## Section 2: Log Analytics & KQL Emergencies (Data-Plane Tracing)

The greatest vulnerability in machine identity architecture is the **"Silent 403."** This occurs when the portal sign-in log shows a 100% Success state (the token handshake passed), but the automated runner still crashes because it cannot read the targeted digital vault or database. This happens because the identity was bound to an infrastructure Control-Plane management role instead of an explicit Data-Plane asset role.

To expose these downstream faults, you must stream your directory and asset telemetry into an Azure Log Analytics Workspace.

### 2.1 Key Telemetry Log Tables
* `AADNonInteractiveUserSignInLogs`: The raw directory table tracking external OIDC passwordless token exchanges.
* `KeyVaultRequests` / `StorageBlobLogs` / `AzureDiagnostics`: The data-plane asset tables tracking raw access attempts inside the resource vault post-authentication.

### 2.2 Deep-Dive KQL Diagnostic Query
Instead of hunting through thousands of rows of raw JSON text, execute this unified Kusto query to correlate directory sign-ins directly with downstream resource access drops across `CorrelationId`:

```kql
// ACPHF Universal Data-Plane Failure Diagnostic
let FailedDataPlaneAccess = 
    union 
    (
        KeyVaultRequests
        | where ResultSignature == "Forbidden" or httpStatusCode_d == 403
        | project TimeGenerated, CorrelationId, Resource = ResourceId, OperationName, httpStatusCode_d
    ),
    (
        StorageBlobLogs
        | where StatusCode == 403
        | project TimeGenerated, CorrelationId, Resource = _ResourceId, OperationName, httpStatusCode_d = StatusCode
    ),
    (
        AzureDiagnostics
        | where httpStatusCode_d == 403
        | project TimeGenerated, CorrelationId, Resource = ResourceId, OperationName, httpStatusCode_d
    );
AADNonInteractiveUserSignInLogs
| where ResultType == 0 // Successful directory sign-in
| project SigninTime = TimeGenerated, AppId, ServicePrincipalName, CorrelationId
| join kind=inner FailedDataPlaneAccess on CorrelationId
| project SigninTime, AppId, ServicePrincipalName, OperationName, Resource, httpStatusCode_d, CorrelationId
```

**Analyzing Results:** If this query returns rows, your token handshake passed but your RBAC policy is broken. You must immediately bypass control-plane roles (`Contributor`, `Owner`) and explicitly assign the Service Principal to a data-plane role like **Key Vault Secrets User** or **Storage Blob Data Reader**.

---

## Section 3: System Validator & Troubleshooting Checklist

This operational checklist acts as your live navigation map during an active deployment or system audit. Run through these four gates to isolate and remediate any pipeline blockages:

> **[ AUDIT GATE 1 ] Coordinate Check**  
> **Question:** Is the external automation runner passing the exact, matching target Directory ID?  
> **Diagnostic Telemetry:** Pipeline logs show network routing or tenant mapping errors.  
> **Remediation Action:** Update the `AZURE_TENANT_ID` environment variable in the runner configuration with the correct global Tenant GUID.

> **[ AUDIT GATE 2 ] Character Check**  
> **Question:** Does the string case in your external repository path match the Federated Credential configuration character-for-character?  
> **Diagnostic Telemetry:** Entra ID Sign-In Logs display error `AADSTS700213`.  
> **Remediation Action:** Switch the Federated Credential scenario in Entra ID to **Other Issuer** and manually paste the exact case-sensitive subject string emitted by the OIDC provider.

> **[ AUDIT GATE 3 ] Clock Check**  
> **Question:** Is the automated pipeline or AI agent loop attempting to run continuously for longer than 60 minutes without requesting a fresh token?  
> **Diagnostic Telemetry:** Script terminates exactly 60 minutes after execution with an expired token exception.  
> **Remediation Action:** Insert an explicit re-authentication loop into the pipeline script before the 55-minute runtime threshold.

> **[ AUDIT GATE 4 ] Plane Check**  
> **Question:** Did you assign the machine identity an infrastructure management role instead of a granular data role?  
> **Diagnostic Telemetry:** Sign-in log displays `Success` (`ResultType 0`), but downstream execution logs return `403 Forbidden`.  
> **Remediation Action:** Open the target resource container's Access Control (IAM) blade and grant the Service Principal direct Data-Plane permissions (e.g., *Key Vault Secrets User*).
