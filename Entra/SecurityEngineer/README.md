# Full Security Engineer access scripts

PowerShell scripts that grant the Full Security Engineer access set across
Entra ID, Defender XDR, Intune, Azure / Microsoft Sentinel and Purview.

| Script | Grants roles to | Use when |
|---|---|---|
| `Grant-SecurityEngineerGroupAccess.ps1` | One role-assignable group (`SG-Full-Security-Engineers`); people become PIM-eligible members | **Recommended.** One PIM activation gives all roles. |
| `Grant-FullSecurityEngineerAccess.ps1` | Each user directly (PIM-eligible) | You don't want a shared group. |

Roles: Entra Security Reader, Security Operator, Conditional Access Administrator;
Defender XDR custom Security Operator (manual portal step, printed by the script);
Intune Endpoint Security Manager; Azure Security Reader; Microsoft Sentinel Contributor;
Purview Audit Reader.

## Run (PowerShell 7 on your PC)

```powershell
Unblock-File .\Grant-SecurityEngineerGroupAccess.ps1
Set-ExecutionPolicy -Scope Process RemoteSigned

# Preview (no changes)
.\Grant-SecurityEngineerGroupAccess.ps1 -Members user@yourdomain.com -SentinelAtSubscription -WhatIf

# Apply
.\Grant-SecurityEngineerGroupAccess.ps1 -Members user@yourdomain.com -SentinelAtSubscription
```

See `Get-Help .\<script>.ps1 -Full` for all parameters.

The CSV report each run writes contains user names and tenant IDs. Don't commit it.
