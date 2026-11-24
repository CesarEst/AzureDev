<#
.SYNOPSIS
    Builds one "Full Security Engineers" security group that holds all the
    Security Engineer roles, then (optionally) makes people PIM-eligible
    members of it.

.DESCRIPTION
    Roles are assigned to the GROUP, not to users:

      #  Access                                   System              Assigned to the group as
      -  ---------------------------------------  ------------------  -------------------------------
      1  Security Reader                          Entra ID role       Active directory role assignment
      2  Security Operator                        Entra ID role       Active directory role assignment
      3  Conditional Access Administrator         Entra ID role       Active directory role assignment
      4  Defender XDR custom Security Operator    Defender URBAC      Manual, in the Defender portal (steps printed)
      5  Endpoint Security Manager                Intune RBAC         Intune role assignment
      6  Microsoft Sentinel Contributor           Azure RBAC          Azure role assignment (Sentinel RG or subscription)
      7  Security Reader                          Azure RBAC          Azure role assignment (subscription)
      8  Audit Reader                             Purview role group  Role group member

    People get access by being a member of the group. With -Members, each
    person is made a PIM-ELIGIBLE member (PIM for Groups): they activate the
    membership once in PIM and get all 8 roles for the activation window.

    IMPORTANT
      * The group is created as ROLE-ASSIGNABLE (required for Entra roles).
        This can only be set when the group is created, not later.
      * Anyone added to the group as a normal (permanent) member has all 8
        roles permanently. Add people through PIM (this script's -Members)
        instead of in the group's Members page.
      * Only Global Admins, Privileged Role Admins and the group owners can
        manage a role-assignable group's membership.

    Run with -WhatIf first. Preview mode uses read-only permissions.

    Permissions needed by the person running it:
      * Entra: Privileged Role Administrator (or Global Administrator)
      * Intune: Intune Administrator
      * Azure: Owner or User Access Administrator on the subscription
      * Purview: Organization Management (or Global Administrator)

.PARAMETER GroupName
    Default SG-Full-Security-Engineers. Created if it does not exist.

.PARAMETER Members
    Optional. UPNs to make eligible (or active) members of the group.

.PARAMETER MembershipType
    Eligible (default): members activate the group in PIM when needed.
    Active: members are in the group for the whole duration.

.PARAMETER DurationDays
    How long each membership lasts. Default 180.

.PARAMETER NoExpiration
    Permanent memberships. Not recommended.

.PARAMETER SubscriptionId / SentinelResourceGroup
    Optional. Found automatically if empty.

.PARAMETER SentinelAtSubscription
    Grant Sentinel Contributor on the whole subscription (use when no
    Sentinel workspace exists yet).

.PARAMETER SkipIntune / SkipAzure / SkipPurview
    Skip that part.

.EXAMPLE
    .\Grant-SecurityEngineerGroupAccess.ps1 -Members jane@contoso.com -SentinelAtSubscription -WhatIf

.EXAMPLE
    .\Grant-SecurityEngineerGroupAccess.ps1 -Members jane@contoso.com,raj@contoso.com -SentinelAtSubscription

.EXAMPLE
    .\Grant-SecurityEngineerGroupAccess.ps1 -Members new.hire@contoso.com -SkipIntune -SkipAzure -SkipPurview

    Later: only add a new engineer to the existing group (the roles are already there).
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $GroupName = 'SG-Full-Security-Engineers',

    [string[]] $Members,

    [ValidateSet('Eligible', 'Active')]
    [string] $MembershipType = 'Eligible',

    [ValidateRange(1, 3650)]
    [int] $DurationDays = 180,

    [switch] $NoExpiration,

    [string] $SubscriptionId,

    [string] $SentinelResourceGroup,

    [switch] $SentinelAtSubscription,

    [string[]] $IntuneScopeGroupIds,

    [string] $PurviewRoleGroup = 'AuditReader',

    [switch] $SkipIntune,

    [switch] $SkipAzure,

    [switch] $SkipPurview,

    [switch] $IncludeOptionalRoles,

    [switch] $UseDeviceCode,

    [string] $Justification = 'Full Security Engineer access',

    [string] $ReportPath = ".\Security-Engineer-Group-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
)

$ErrorActionPreference = 'Stop'

$IsPreview        = [bool]$WhatIfPreference
$WhatIfPreference = $false
$Cmdlet           = $PSCmdlet

# =====================================================================
# ROLE IDS (the same in every tenant)
# =====================================================================

$EntraRoles = [ordered]@{
    'Security Reader'                  = '5d6b6bb7-de71-4623-b4af-96380a352509'
    'Security Operator'                = '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f'
    'Conditional Access Administrator' = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'
}
if ($IncludeOptionalRoles) {
    $EntraRoles['Security Administrator']              = '194ae4cb-b126-40b2-bd5b-6091b380977d'
    $EntraRoles['Authentication Policy Administrator'] = '0526716b-113d-4c15-b2c8-68e3c22b9f80'
    $EntraRoles['Cloud App Security Administrator']    = '892c5842-a9a6-463a-8041-72aa08ca3cf6'
}

$AzureRoleIds = @{
    'Security Reader'                = '39bc4728-0917-49c7-9d2c-d95423bc2eb4'
    'Microsoft Sentinel Contributor' = 'ab8e14d6-4a74-4a29-9ba8-549422addade'
}

$IntuneRoleName = 'Endpoint Security Manager'

# =====================================================================
# HELPERS
# =====================================================================

$Report = [System.Collections.Generic.List[object]]::new()
$ExpiryText = if ($NoExpiration) { 'Never' } else { (Get-Date).AddDays($DurationDays).ToString('yyyy-MM-dd') }

function Add-ReportRow {
    param($Target, $Item, $System, $Status, $Detail = '')
    $Report.Add([PSCustomObject]@{
        Target = $Target
        Item   = $Item
        System = $System
        Status = $Status
        Detail = $Detail
    })
}

function Confirm-Change {
    param($Target, $Action)
    if ($IsPreview) {
        Write-Host "PREVIEW: would $Action -> $Target" -ForegroundColor Cyan
        return $false
    }
    return $Cmdlet.ShouldProcess($Target, $Action)
}

function Get-NotDoneStatus { if ($IsPreview) { 'Preview Only' } else { 'Skipped by user' } }

function Write-Section($Title) { Write-Host "`n---------- $Title ----------" -ForegroundColor Magenta }

function Get-GraphAll($Uri) {
    $items = @()
    while ($Uri) {
        $resp  = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        $items += $resp.value
        $Uri   = $resp.'@odata.nextLink'
    }
    return $items
}

# =====================================================================
# MODULES
# =====================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Groups'
    'Microsoft.Graph.Identity.Governance'
)
if (-not $SkipAzure)   { $RequiredModules += 'Az.Accounts', 'Az.Resources' }
if (-not $SkipPurview) { $RequiredModules += 'ExchangeOnlineManagement' }

foreach ($m in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing module $m ..." -ForegroundColor Yellow
        Install-Module $m -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -Confirm:$false
    }
    Import-Module $m
}

# =====================================================================
# GRAPH SCOPES
# =====================================================================

if ($IsPreview) {
    $Scopes = @('User.Read.All', 'Group.Read.All', 'RoleManagement.Read.Directory',
                'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAssignmentSchedule.Read.AzureADGroup')
    if (-not $SkipIntune) { $Scopes += 'DeviceManagementRBAC.Read.All' }
}
else {
    $Scopes = @('User.Read.All', 'Group.ReadWrite.All', 'RoleManagement.ReadWrite.Directory')
    $Scopes += if ($MembershipType -eq 'Eligible') { 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup' }
               else { 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' }
    if (-not $SkipIntune) { $Scopes += 'DeviceManagementRBAC.ReadWrite.All' }
}

# =====================================================================
# MAIN
# =====================================================================

$ConnectParams = @{ Scopes = $Scopes; NoWelcome = $true }
if ($UseDeviceCode) { $ConnectParams.UseDeviceCode = $true }
Connect-MgGraph @ConnectParams

$AzConnected = $false
$IppsConnected = $false

try {
    Write-Host '=================================================='
    Write-Host 'FULL SECURITY ENGINEERS GROUP'
    Write-Host '=================================================='
    if ($IsPreview) { Write-Host 'Mode: PREVIEW (no changes)' -ForegroundColor Cyan }

    # =================================================================
    # GROUP
    # =================================================================
    Write-Section "Group $GroupName"

    $found = @(Get-MgGroup -Filter "displayName eq '$GroupName'" -All -Property Id, DisplayName, SecurityEnabled, IsAssignableToRole)
    if ($found.Count -gt 1) { throw "More than one group is named '$GroupName'. Remove the duplicates." }

    $GroupId = $null
    if ($found.Count -eq 1) {
        $g = $found[0]
        if (-not $g.SecurityEnabled)    { throw "Group '$GroupName' is not a security group." }
        if (-not $g.IsAssignableToRole) {
            throw "Group '$GroupName' exists but is not role-assignable, so Entra roles can't be given to it. This can't be changed on an existing group. Use another -GroupName."
        }
        $GroupId = $g.Id
        Write-Host "Group exists: $GroupName ($GroupId)" -ForegroundColor Green
        Add-ReportRow $GroupName 'Role-assignable security group' 'Entra ID' 'Already Exists' $GroupId
    }
    elseif (Confirm-Change $GroupName 'create role-assignable security group') {
        $nick = $GroupName -replace '[^A-Za-z0-9\-]', ''
        $g = New-MgGroup -DisplayName $GroupName -MailNickname $nick -MailEnabled:$false -SecurityEnabled `
            -IsAssignableToRole:$true -Description 'Holds all Full Security Engineer roles. Add people via PIM for Groups only.'
        $GroupId = $g.Id
        Write-Host "Group created: $GroupName ($GroupId)" -ForegroundColor Green
        Add-ReportRow $GroupName 'Role-assignable security group' 'Entra ID' 'Created' $GroupId
        Write-Host 'Waiting 30 seconds for the new group to replicate...'
        Start-Sleep -Seconds 30
    }
    else {
        Add-ReportRow $GroupName 'Role-assignable security group' 'Entra ID' (Get-NotDoneStatus) 'Would create the group'
    }

    $GroupExists = [bool]$GroupId

    # =================================================================
    # 1-3. ENTRA ROLES -> GROUP
    # =================================================================
    Write-Section 'Entra ID roles'

    $existingEntra = @()
    if ($GroupExists) {
        $existingEntra = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$GroupId'" -All |
            Where-Object DirectoryScopeId -eq '/' | ForEach-Object RoleDefinitionId)
        $existingEntra += @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$GroupId'" -All |
            Where-Object DirectoryScopeId -eq '/' | ForEach-Object RoleDefinitionId)
    }

    foreach ($RoleName in $EntraRoles.Keys) {
        $TemplateId = $EntraRoles[$RoleName]
        if ($existingEntra -contains $TemplateId) {
            Write-Host "Already assigned: $RoleName" -ForegroundColor Green
            Add-ReportRow $GroupName $RoleName 'Entra ID' 'Already Assigned'
            continue
        }
        if (-not $GroupExists) {
            Confirm-Change $GroupName "assign Entra role '$RoleName'" | Out-Null
            Add-ReportRow $GroupName $RoleName 'Entra ID' 'Preview Only' 'Would assign to the new group'
            continue
        }
        if (-not (Confirm-Change $GroupName "assign Entra role '$RoleName' (active, tenant-wide)")) {
            Add-ReportRow $GroupName $RoleName 'Entra ID' (Get-NotDoneStatus)
            continue
        }
        try {
            New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $GroupId -RoleDefinitionId $TemplateId -DirectoryScopeId '/' | Out-Null
            Write-Host "Assigned: $RoleName" -ForegroundColor Green
            Add-ReportRow $GroupName $RoleName 'Entra ID' 'Successfully Assigned'
        }
        catch {
            Write-Warning "Failed: $RoleName - $($_.Exception.Message)"
            Add-ReportRow $GroupName $RoleName 'Entra ID' 'Failed' $_.Exception.Message
        }
    }

    # =================================================================
    # 5. INTUNE ENDPOINT SECURITY MANAGER -> GROUP
    # =================================================================
    Write-Section 'Intune Endpoint Security Manager'
    if ($SkipIntune) {
        Add-ReportRow $GroupName 'Intune Endpoint Security Manager' 'Intune' 'Skipped' '-SkipIntune'
    }
    else {
        try {
            $roleDef = Get-GraphAll 'https://graph.microsoft.com/beta/deviceManagement/roleDefinitions' |
                Where-Object { $_.displayName -eq $IntuneRoleName -and $_.isBuiltIn } | Select-Object -First 1
            if (-not $roleDef) { throw "Intune role '$IntuneRoleName' not found" }

            $groupHasRole = $false
            if ($GroupExists) {
                foreach ($ra in (Get-GraphAll "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions/$($roleDef.id)/roleAssignments")) {
                    $full = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/beta/deviceManagement/roleAssignments/$($ra.id)"
                    if ($full.members -contains $GroupId) { $groupHasRole = $true; break }
                }
            }

            if ($groupHasRole) {
                Write-Host 'Already assigned.' -ForegroundColor Green
                Add-ReportRow $GroupName 'Intune Endpoint Security Manager' 'Intune' 'Already Assigned'
            }
            else {
                $scopeText = if ($IntuneScopeGroupIds) { 'scope groups ' + ($IntuneScopeGroupIds -join ', ') } else { 'all devices and all licensed users' }
                $action = "assign Intune role '$IntuneRoleName' ($scopeText)"
                if ($GroupExists -and (Confirm-Change $GroupName $action)) {
                    $raBody = @{
                        '@odata.type'               = '#microsoft.graph.deviceAndAppManagementRoleAssignment'
                        displayName                 = "$GroupName - $IntuneRoleName"
                        description                 = 'Created by Grant-SecurityEngineerGroupAccess.ps1'
                        members                     = @($GroupId)
                        'roleDefinition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions/$($roleDef.id)"
                        scopeType                   = if ($IntuneScopeGroupIds) { 'resourceScope' } else { 'allDevicesAndLicensedUsers' }
                        resourceScopes              = @($IntuneScopeGroupIds | Where-Object { $_ })
                    }
                    Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/roleAssignments' `
                        -Body ($raBody | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
                    Write-Host 'Assigned.' -ForegroundColor Green
                    Add-ReportRow $GroupName 'Intune Endpoint Security Manager' 'Intune' 'Successfully Assigned' $scopeText
                }
                else {
                    if (-not $GroupExists) { Confirm-Change $GroupName $action | Out-Null }
                    Add-ReportRow $GroupName 'Intune Endpoint Security Manager' 'Intune' (Get-NotDoneStatus) $action
                }
            }
        }
        catch {
            Write-Warning "Intune failed: $($_.Exception.Message)"
            Add-ReportRow $GroupName 'Intune Endpoint Security Manager' 'Intune' 'Failed' $_.Exception.Message
        }
    }

    # =================================================================
    # 6-7. AZURE RBAC -> GROUP
    # =================================================================
    Write-Section 'Azure RBAC'
    if ($SkipAzure) {
        Add-ReportRow $GroupName 'Microsoft Sentinel Contributor' 'Azure' 'Skipped' '-SkipAzure'
        Add-ReportRow $GroupName 'Azure Security Reader' 'Azure' 'Skipped' '-SkipAzure'
    }
    else {
        $azParams = @{ WarningAction = 'SilentlyContinue' }
        if ($UseDeviceCode) { $azParams.UseDeviceAuthentication = $true }
        Connect-AzAccount @azParams | Out-Null
        $AzConnected = $true

        # Find Sentinel if needed
        if (-not $SentinelResourceGroup -and -not $SentinelAtSubscription) {
            Write-Host 'Looking for Microsoft Sentinel workspaces...'
            $subs = if ($SubscriptionId) { Get-AzSubscription -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue }
                    else { Get-AzSubscription -WarningAction SilentlyContinue | Where-Object State -eq 'Enabled' }
            $foundWs = @()
            foreach ($sub in $subs) {
                Set-AzContext -SubscriptionId $sub.Id -WarningAction SilentlyContinue | Out-Null
                Get-AzResource -ResourceType 'Microsoft.OperationalInsights/workspaces' -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $ws = $_
                        $r = Invoke-AzRestMethod -Method GET -Path "$($ws.ResourceId)/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" -ErrorAction SilentlyContinue
                        if ($r -and $r.StatusCode -eq 200) {
                            $foundWs += [PSCustomObject]@{ SubscriptionName = $sub.Name; SubscriptionId = $sub.Id; ResourceGroup = $ws.ResourceGroupName; Workspace = $ws.Name }
                        }
                    }
            }
            $pick = $null
            if ($foundWs.Count -eq 1) { $pick = $foundWs[0] }
            elseif ($foundWs.Count -gt 1) {
                for ($i = 0; $i -lt $foundWs.Count; $i++) {
                    Write-Host ("  [{0}] {1} / {2} / {3}" -f ($i + 1), $foundWs[$i].SubscriptionName, $foundWs[$i].ResourceGroup, $foundWs[$i].Workspace)
                }
                do { $n = Read-Host 'Type the number of the Sentinel workspace to use' }
                until ($n -as [int] -and [int]$n -ge 1 -and [int]$n -le $foundWs.Count)
                $pick = $foundWs[[int]$n - 1]
            }
            if ($pick) {
                $SubscriptionId = $pick.SubscriptionId
                $SentinelResourceGroup = $pick.ResourceGroup
                Write-Host "Sentinel: $($pick.SubscriptionName) / $($pick.ResourceGroup) / $($pick.Workspace)" -ForegroundColor Green
            }
            else {
                Write-Warning 'No Microsoft Sentinel workspace found.'
            }
        }

        if (-not $SubscriptionId) { $SubscriptionId = (Get-AzContext).Subscription.Id }
        Set-AzContext -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue | Out-Null
        $SubScope = "/subscriptions/$SubscriptionId"

        $targets = @()
        if ($SentinelAtSubscription)   { $targets += @{ Item = 'Microsoft Sentinel Contributor'; Role = 'Microsoft Sentinel Contributor'; Scope = $SubScope } }
        elseif ($SentinelResourceGroup) { $targets += @{ Item = 'Microsoft Sentinel Contributor'; Role = 'Microsoft Sentinel Contributor'; Scope = "$SubScope/resourceGroups/$SentinelResourceGroup" } }
        else { Add-ReportRow $GroupName 'Microsoft Sentinel Contributor' 'Azure' 'Failed' 'No Sentinel workspace found. Re-run with -SentinelAtSubscription.' }
        $targets += @{ Item = 'Azure Security Reader'; Role = 'Security Reader'; Scope = $SubScope }

        foreach ($t in $targets) {
            $roleGuid = $AzureRoleIds[$t.Role]
            try {
                $has = $false
                if ($GroupExists) {
                    $has = [bool](Get-AzRoleAssignment -ObjectId $GroupId -Scope $t.Scope -ErrorAction Stop |
                        Where-Object { $_.RoleDefinitionId -match $roleGuid })
                }
                if ($has) {
                    Write-Host "Already assigned: $($t.Item)" -ForegroundColor Green
                    Add-ReportRow $GroupName $t.Item 'Azure' 'Already Assigned' $t.Scope
                    continue
                }
                $action = "assign Azure role '$($t.Role)' at $($t.Scope)"
                if ($GroupExists -and (Confirm-Change $GroupName $action)) {
                    New-AzRoleAssignment -ObjectId $GroupId -RoleDefinitionId $roleGuid -Scope $t.Scope | Out-Null
                    Write-Host "Assigned: $($t.Item)" -ForegroundColor Green
                    Add-ReportRow $GroupName $t.Item 'Azure' 'Successfully Assigned' $t.Scope
                }
                else {
                    if (-not $GroupExists) { Confirm-Change $GroupName $action | Out-Null }
                    Add-ReportRow $GroupName $t.Item 'Azure' (Get-NotDoneStatus) $action
                }
            }
            catch {
                Write-Warning "Failed: $($t.Item) - $($_.Exception.Message)"
                Add-ReportRow $GroupName $t.Item 'Azure' 'Failed' $_.Exception.Message
            }
        }
    }

    # =================================================================
    # 8. PURVIEW AUDIT READER -> GROUP
    # =================================================================
    Write-Section "Purview $PurviewRoleGroup"
    if ($SkipPurview) {
        Add-ReportRow $GroupName "Purview $PurviewRoleGroup" 'Purview' 'Skipped' '-SkipPurview'
    }
    else {
        try {
            Connect-IPPSSession -ShowBanner:$false
            $IppsConnected = $true

            $want = $PurviewRoleGroup -replace '\s', ''
            $rg = Get-RoleGroup -ResultSize Unlimited | Where-Object {
                ($_.Name -replace '\s', '') -eq $want -or ($_.DisplayName -replace '\s', '') -eq $want
            } | Select-Object -First 1
            if (-not $rg) { throw "Purview role group '$PurviewRoleGroup' not found." }

            $already = $false
            if ($GroupExists) {
                $already = [bool](Get-RoleGroupMember -Identity $rg.Identity -ResultSize Unlimited |
                    Where-Object { $_.ExternalDirectoryObjectId -eq $GroupId -or $_.Name -eq $GroupName -or $_.DisplayName -eq $GroupName })
            }

            if ($already) {
                Write-Host 'Group is already a member.' -ForegroundColor Green
                Add-ReportRow $GroupName "Purview $($rg.Name)" 'Purview' 'Already Assigned'
            }
            elseif ($GroupExists -and (Confirm-Change $GroupName "add group to Purview role group '$($rg.Name)'")) {
                Add-RoleGroupMember -Identity $rg.Identity -Member $GroupId -Confirm:$false
                Write-Host 'Added.' -ForegroundColor Green
                Add-ReportRow $GroupName "Purview $($rg.Name)" 'Purview' 'Successfully Assigned'
            }
            else {
                if (-not $GroupExists) { Confirm-Change $GroupName "add group to Purview role group '$($rg.Name)'" | Out-Null }
                Add-ReportRow $GroupName "Purview $($rg.Name)" 'Purview' (Get-NotDoneStatus) "Add group to $($rg.Name)"
            }
        }
        catch {
            Write-Warning "Purview failed: $($_.Exception.Message)"
            Add-ReportRow $GroupName "Purview $PurviewRoleGroup" 'Purview' 'Failed' $_.Exception.Message
        }
    }

    # =================================================================
    # MEMBERS (PIM for Groups)
    # =================================================================
    Write-Section 'Members'
    foreach ($upn in $Members) {
        try {
            $u = Get-MgUser -UserId $upn -Property Id, UserPrincipalName -ErrorAction Stop
        }
        catch {
            Write-Warning "User not found: $upn"
            Add-ReportRow $upn 'Group membership' 'PIM for Groups' 'Failed' 'User not found'
            continue
        }

        $how = @()
        if ($GroupExists) {
            if (Get-MgGroupMember -GroupId $GroupId -All | Where-Object Id -eq $u.Id) { $how += 'Active member' }
            if (Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -All `
                    -Filter "groupId eq '$GroupId' and principalId eq '$($u.Id)'" -ErrorAction SilentlyContinue) {
                $how += 'Eligible member'
            }
        }
        if ($how) {
            Write-Host "$upn already: $($how -join ', ')" -ForegroundColor Green
            Add-ReportRow $upn 'Group membership' 'PIM for Groups' 'Already Assigned' ($how -join ', ')
            continue
        }

        $action = "make $MembershipType member of '$GroupName' (expires: $ExpiryText)"
        if (-not ($GroupExists -and (Confirm-Change $upn $action))) {
            if (-not $GroupExists) { Confirm-Change $upn $action | Out-Null }
            Add-ReportRow $upn 'Group membership' 'PIM for Groups' (Get-NotDoneStatus) $action
            continue
        }

        $body = @{
            AccessId      = 'member'
            Action        = 'adminAssign'
            PrincipalId   = $u.Id
            GroupId       = $GroupId
            Justification = $Justification
            ScheduleInfo  = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString('o')
                Expiration    = if ($NoExpiration) { @{ Type = 'noExpiration' } }
                                else { @{ Type = 'afterDuration'; Duration = "P$($DurationDays)D" } }
            }
        }
        try {
            $req = if ($MembershipType -eq 'Eligible') {
                New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $body
            } else {
                New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $body
            }
            Write-Host "$upn -> $MembershipType member [status: $($req.Status)]" -ForegroundColor Green
            Add-ReportRow $upn 'Group membership' 'PIM for Groups' 'Successfully Assigned' "$MembershipType until $ExpiryText"
        }
        catch {
            Write-Warning "Failed: $upn - $($_.Exception.Message)"
            Add-ReportRow $upn 'Group membership' 'PIM for Groups' 'Failed' $_.Exception.Message
        }
    }
    if (-not $Members) { Write-Host 'No -Members given. Add people later with -Members.' }

    # ---------------- REPORT ----------------
    $Report | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Host "`n=================================================="
    Write-Host 'SUMMARY'
    Write-Host '=================================================='
    $Report | Format-Table Target, Item, System, Status, Detail -AutoSize -Wrap
    Write-Host "Report saved: $ReportPath" -ForegroundColor Cyan

    Write-Host @"

ONE MANUAL STEP (first time only) - Defender XDR custom role (#4):
  1. Open https://security.microsoft.com
  2. System > Permissions > Microsoft Defender XDR > Roles > Create custom role
  3. Name: Security Operator - Custom
  4. Permissions:
       Security operations:        Security data basics (Read), Alerts (Manage),
                                   Response (Manage), Basic live response
       Security posture:           Vulnerability management (Read), Secure Score (Read)
       Authorization and settings: Core security settings (Read), Detection tuning (Manage)
  5. Assignments > Add assignment: group '$GroupName', Data sources: All
  6. Permissions > Microsoft Defender XDR > Workloads settings:
     turn unified RBAC ON for Defender for Endpoint and the other workloads you use.
  Skip this if you already did it.

HOW ENGINEERS GET ACCESS:
  Entra admin center > Identity Governance > Privileged Identity Management
  > My roles > Groups > '$GroupName' > Activate. All 8 roles apply after activation
  (Azure and Defender can take a few minutes to pick it up).
"@ -ForegroundColor Yellow
}
finally {
    if ($IppsConnected) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    if ($AzConnected)   { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null }
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
