<#
.SYNOPSIS
    Grants the full "Security Engineer" access set across Entra ID, Defender XDR,
    Intune, Azure / Microsoft Sentinel and Purview. PIM-eligible by default.

.DESCRIPTION
    Access granted (each part can be skipped):

      #  Access                                   System              How
      -  ---------------------------------------  ------------------  ------------------------------------------
      1  Security Reader                          Entra ID role       PIM eligibility (or active) - Graph
      2  Security Operator                        Entra ID role       PIM eligibility (or active) - Graph
      3  Conditional Access Administrator         Entra ID role       PIM eligibility (or active) - Graph
      4  Defender XDR custom Security Operator    Defender URBAC      PIM for Groups membership of
                                                                      SG-Defender-SecurityOperator
      5  Endpoint Security Manager                Intune RBAC         PIM for Groups membership of
                                                                      SG-Intune-EndpointSecurityManager
                                                                      (+ assigns the Intune role to that group)
      6  Microsoft Sentinel Contributor           Azure RBAC          Azure PIM eligibility on the Sentinel RG
      7  Security Reader                          Azure RBAC          Azure PIM eligibility on the subscription
      8  Audit Reader                             Purview role group  Direct membership (Purview has no PIM)

    Defender XDR and Intune roles can only be given to groups, so the user is
    made an eligible member of a group (PIM for Groups). When they activate
    that membership in PIM, they get the role.

    EVERYTHING IS AUTOMATIC except one portal step:
      * The two security groups are found by name, or created if missing.
      * The Sentinel subscription and resource group are found automatically
        (if there are several, you pick from a numbered list).
      * ONE MANUAL STEP (first time only): in the Defender portal, create the
        custom "Security Operator - Custom" role and assign it to the group
        SG-Defender-SecurityOperator. The script prints the exact steps.
        There is no supported API for Defender XDR custom roles.

    Run with -WhatIf first. Preview mode connects with read-only permissions
    and changes nothing.

    Your PIM policies may cap how long an eligible or active assignment can
    last, or forbid permanent ones. If -DurationDays or -NoExpiration goes
    beyond them, the request is rejected and the report shows the error.

    Permissions needed by the person running it:
      * Entra: Privileged Role Administrator (or Global Administrator)
      * Intune: Intune Administrator (to create the Intune role assignment)
      * Azure: Owner or User Access Administrator on the subscription
      * Purview: Organization Management in Purview (or Global Administrator)

.PARAMETER UserPrincipalName
    UPN of the user who gets the access.

.PARAMETER AssignmentType
    Eligible (default): the user activates each role in PIM when needed.
    Active: access is granted immediately for the whole duration.

.PARAMETER DurationDays
    How long assignments last. Default 180 days.

.PARAMETER NoExpiration
    Permanent assignments (ignores -DurationDays). Not recommended.

.PARAMETER DefenderGroupName
    Group for the Defender XDR custom role. Default SG-Defender-SecurityOperator.
    Created if it does not exist.

.PARAMETER IntuneGroupName
    Group for Intune Endpoint Security Manager. Default SG-Intune-EndpointSecurityManager.
    Created if it does not exist.

.PARAMETER IntuneScopeGroupIds
    Optional. Group IDs that limit which users/devices the Intune role applies to.
    Default: all devices and all licensed users.

.PARAMETER SubscriptionId
    Optional. Azure subscription for Security Reader and Sentinel. Found automatically if empty.

.PARAMETER SentinelResourceGroup
    Optional. Resource group of the Sentinel workspace. Found automatically if empty.

.PARAMETER SentinelAtSubscription
    Grant Microsoft Sentinel Contributor on the whole subscription instead of
    the Sentinel resource group. Use it when no workspace exists yet, or to
    cover every workspace in the subscription.

.PARAMETER SkipDefender / SkipIntune / SkipAzure
    Skip items 4 / 5 / 6-7.

.PARAMETER PurviewRoleGroup
    Purview role group for audit access. Default "AuditReader" (display name "Audit Reader").

.PARAMETER SkipPurview
    Skip item 8.

.PARAMETER IncludeOptionalRoles
    Also make Security Administrator, Authentication Policy Administrator and
    Cloud App Security Administrator eligible in Entra.

.PARAMETER UseDeviceCode
    Sign in to Graph and Azure with a device code (use in Azure Cloud Shell).

.EXAMPLE
    .\Grant-FullSecurityEngineerAccess.ps1 -UserPrincipalName jane@contoso.com -WhatIf

    Preview everything. No changes.

.EXAMPLE
    .\Grant-FullSecurityEngineerAccess.ps1 -UserPrincipalName jane@contoso.com

    Grant all 8, PIM-eligible for 180 days. Prompts before each change.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $UserPrincipalName,

    [ValidateSet('Eligible', 'Active')]
    [string] $AssignmentType = 'Eligible',

    [ValidateRange(1, 3650)]
    [int] $DurationDays = 180,

    [switch] $NoExpiration,

    [string] $DefenderGroupName = 'SG-Defender-SecurityOperator',

    [string] $IntuneGroupName = 'SG-Intune-EndpointSecurityManager',

    [switch] $SkipDefender,

    [switch] $SkipIntune,

    [switch] $SkipAzure,

    # Grant Sentinel Contributor on the whole subscription instead of one resource group
    [switch] $SentinelAtSubscription,

    [string[]] $IntuneScopeGroupIds,

    [string] $SubscriptionId,

    [string] $SentinelResourceGroup,

    [string] $PurviewRoleGroup = 'AuditReader',

    [switch] $SkipPurview,

    [switch] $IncludeOptionalRoles,

    [switch] $UseDeviceCode,

    [string] $Justification = 'Full Security Engineer access',

    [string] $ReportPath = ".\Full-Security-Engineer-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
)

$ErrorActionPreference = 'Stop'

# Remember whether this is a preview, then turn -WhatIf off for everything else
# (sign-in, module install, CSV export). Changes are gated by Confirm-Change below.
$IsPreview      = [bool]$WhatIfPreference
$WhatIfPreference = $false
$Cmdlet         = $PSCmdlet

# =====================================================================
# ROLE IDS (fixed IDs, the same in every tenant)
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

$DoDefender = -not $SkipDefender
$DoIntune   = -not $SkipIntune
$DoAzure    = -not $SkipAzure
$DoPurview  = -not $SkipPurview

# =====================================================================
# HELPERS
# =====================================================================

$Report = [System.Collections.Generic.List[object]]::new()
$ExpiryText = if ($NoExpiration) { 'Never' } else { (Get-Date).AddDays($DurationDays).ToString('yyyy-MM-dd') }
$StartUtc   = (Get-Date).ToUniversalTime().ToString('o')

$GraphScheduleInfo = @{
    StartDateTime = $StartUtc
    Expiration    = if ($NoExpiration) { @{ Type = 'noExpiration' } }
                    else { @{ Type = 'afterDuration'; Duration = "P$($DurationDays)D" } }
}

function Add-ReportRow {
    param($Item, $System, $Status, $Detail = '', $Type = $AssignmentType, $Expires = $ExpiryText)
    $Report.Add([PSCustomObject]@{
        User    = $UserPrincipalName
        Item    = $Item
        System  = $System
        Type    = $Type
        Expires = $Expires
        Status  = $Status
        Detail  = $Detail
    })
}

# Returns $true only when the change should really happen.
function Confirm-Change {
    param($Target, $Action)
    if ($IsPreview) {
        Write-Host "PREVIEW: would $Action -> $Target" -ForegroundColor Cyan
        return $false
    }
    return $Cmdlet.ShouldProcess($Target, $Action)
}

function Write-Section($Title) {
    Write-Host "`n---------- $Title ----------" -ForegroundColor Magenta
}

# Graph GET that follows paging
function Get-GraphAll($Uri) {
    $items = @()
    while ($Uri) {
        $resp  = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        $items += $resp.value
        $Uri   = $resp.'@odata.nextLink'
    }
    return $items
}

# Finds a security group by name, or creates it. Returns its ID, or $null in preview
# when the group does not exist yet.
function Resolve-SecurityGroup {
    param([string] $Name, [string] $Description)

    $found = @(Get-MgGroup -Filter "displayName eq '$Name'" -All -Property Id, DisplayName, SecurityEnabled)
    if ($found.Count -gt 1) { throw "More than one group is named '$Name'. Remove the duplicates." }
    if ($found.Count -eq 1) {
        if (-not $found[0].SecurityEnabled) { throw "Group '$Name' exists but is not a security group." }
        Write-Host "Group: $Name ($($found[0].Id))"
        return $found[0].Id
    }

    if (-not (Confirm-Change $Name 'create security group')) { return $null }

    $nick = $Name -replace '[^A-Za-z0-9\-]', ''
    $g = New-MgGroup -DisplayName $Name -Description $Description -MailEnabled:$false -MailNickname $nick -SecurityEnabled
    Write-Host "Group created: $Name ($($g.Id))" -ForegroundColor Green
    Start-Sleep -Seconds 15   # give Entra time to replicate the new group
    return $g.Id
}

# Makes the user an eligible (or active) member of a group via PIM for Groups
function Grant-PimGroupMembership {
    param($Item, $System, $GroupId, $UserId)

    try {
        $group = Get-MgGroup -GroupId $GroupId -Property Id, DisplayName, SecurityEnabled -ErrorAction Stop
    }
    catch {
        Add-ReportRow $Item $System 'Failed' "Group $GroupId not found"
        Write-Warning "Group not found: $GroupId"
        return
    }
    Write-Host "Group: $($group.DisplayName)"

    # Already an active member (direct or nested)?
    $isMember = Get-MgUserTransitiveMemberOf -UserId $UserId -All |
        Where-Object { $_.Id -eq $GroupId }

    $eligible = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -All `
        -Filter "groupId eq '$GroupId' and principalId eq '$UserId'" -ErrorAction SilentlyContinue

    if ($isMember -or $eligible) {
        $how = @()
        if ($isMember) { $how += 'Active member' }
        if ($eligible) { $how += 'Eligible member (PIM)' }
        Write-Host "Already has access: $($how -join ', ')" -ForegroundColor Green
        Add-ReportRow $Item $System 'Already Assigned' "$($how -join ', ') of $($group.DisplayName)"
        return
    }

    $action = "make $AssignmentType member of group '$($group.DisplayName)' (expires: $ExpiryText)"
    if (-not (Confirm-Change $UserPrincipalName $action)) {
        Add-ReportRow $Item $System ($(if ($IsPreview) { 'Preview Only' } else { 'Skipped by user' })) $action
        return
    }

    $body = @{
        AccessId      = 'member'
        Action        = 'adminAssign'
        PrincipalId   = $UserId
        GroupId       = $GroupId
        Justification = $Justification
        ScheduleInfo  = $GraphScheduleInfo
    }

    try {
        if ($AssignmentType -eq 'Eligible') {
            $req = New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $body
        }
        else {
            $req = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $body
        }
        Write-Host "Done: $Item [status: $($req.Status)]" -ForegroundColor Green
        Add-ReportRow $Item $System 'Successfully Assigned' "Group $($group.DisplayName), request $($req.Id), status $($req.Status)"
    }
    catch {
        Write-Warning "Failed: $Item - $($_.Exception.Message)"
        Add-ReportRow $Item $System 'Failed' $_.Exception.Message
    }
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
if ($DoAzure)   { $RequiredModules += 'Az.Accounts', 'Az.Resources' }
if ($DoPurview) { $RequiredModules += 'ExchangeOnlineManagement' }

foreach ($m in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing module $m ..." -ForegroundColor Yellow
        Install-Module $m -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -Confirm:$false
    }
    Import-Module $m
}

# =====================================================================
# GRAPH SCOPES (least privilege)
# =====================================================================

$Scopes = @('User.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory')

if ($DoDefender -or $DoIntune) {
    $Scopes += 'PrivilegedEligibilitySchedule.Read.AzureADGroup'
}
if ($DoIntune) {
    $Scopes += 'DeviceManagementRBAC.Read.All'
}

if (-not $IsPreview) {
    if ($AssignmentType -eq 'Eligible') {
        $Scopes += 'RoleEligibilitySchedule.ReadWrite.Directory'
        if ($DoDefender -or $DoIntune) { $Scopes += 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup' }
    }
    else {
        $Scopes += 'RoleAssignmentSchedule.ReadWrite.Directory'
        if ($DoDefender -or $DoIntune) { $Scopes += 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' }
    }
    if ($DoIntune) { $Scopes += 'DeviceManagementRBAC.ReadWrite.All' }
    if ($DoDefender -or $DoIntune) { $Scopes += 'Group.ReadWrite.All' }
}

# =====================================================================
# MAIN
# =====================================================================

$ConnectParams = @{ Scopes = $Scopes; NoWelcome = $true }
if ($UseDeviceCode) { $ConnectParams.UseDeviceCode = $true }
Connect-MgGraph @ConnectParams

$AzConnected = $false
$IppsConnected = $false
$DefenderNote = $false

try {
    # ---------------- USER ----------------
    try {
        $user = Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName, UserPrincipalName -ErrorAction Stop
    }
    catch {
        throw "User not found: $UserPrincipalName ($($_.Exception.Message))"
    }

    Write-Host '=================================================='
    Write-Host 'FULL SECURITY ENGINEER ACCESS'
    Write-Host '=================================================='
    Write-Host "User:     $($user.DisplayName) <$($user.UserPrincipalName)>"
    Write-Host "Type:     $AssignmentType"
    Write-Host "Expires:  $ExpiryText"
    if ($IsPreview) { Write-Host 'Mode:     PREVIEW (no changes)' -ForegroundColor Cyan }

    # =================================================================
    # 1-3. ENTRA ID ROLES
    # =================================================================
    Write-Section 'Entra ID roles'

    # The user plus any role-assignable groups they are in
    $Principals = @{ $user.Id = 'Direct' }
    Get-MgUserTransitiveMemberOf -UserId $user.Id -All |
        Where-Object {
            $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' -and
            $_.AdditionalProperties.isAssignableToRole -eq $true
        } |
        ForEach-Object { $Principals[$_.Id] = "Group: $($_.AdditionalProperties.displayName)" }

    $Existing = @{}
    foreach ($principalId in $Principals.Keys) {
        $via = $Principals[$principalId]
        foreach ($a in (Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$principalId'" -All)) {
            if ($a.DirectoryScopeId -eq '/') { $Existing[$a.RoleDefinitionId] += @("Active ($via)") }
        }
        foreach ($e in (Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$principalId'" -All)) {
            if ($e.DirectoryScopeId -eq '/') { $Existing[$e.RoleDefinitionId] += @("Eligible ($via)") }
        }
    }

    foreach ($RoleName in $EntraRoles.Keys) {
        $TemplateId = $EntraRoles[$RoleName]
        Write-Host "`nProcessing: $RoleName" -ForegroundColor Yellow

        if ($Existing[$TemplateId]) {
            $how = ($Existing[$TemplateId] | Select-Object -Unique) -join '; '
            Write-Host "Already has role: $how" -ForegroundColor Green
            Add-ReportRow $RoleName 'Entra ID' 'Already Assigned' $how
            continue
        }

        $action = "create $AssignmentType Entra role assignment (expires: $ExpiryText)"
        if (-not (Confirm-Change "$UserPrincipalName / $RoleName" $action)) {
            Add-ReportRow $RoleName 'Entra ID' ($(if ($IsPreview) { 'Preview Only' } else { 'Skipped by user' })) $action
            continue
        }

        $body = @{
            Action           = 'adminAssign'
            PrincipalId      = $user.Id
            RoleDefinitionId = $TemplateId
            DirectoryScopeId = '/'
            Justification    = $Justification
            ScheduleInfo     = $GraphScheduleInfo
        }

        try {
            if ($AssignmentType -eq 'Eligible') {
                $req = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $body
            }
            else {
                $req = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $body
            }
            Write-Host "Done: $RoleName [status: $($req.Status)]" -ForegroundColor Green
            Add-ReportRow $RoleName 'Entra ID' 'Successfully Assigned' "Request $($req.Id), status $($req.Status)"
        }
        catch {
            Write-Warning "Failed: $RoleName - $($_.Exception.Message)"
            Add-ReportRow $RoleName 'Entra ID' 'Failed' $_.Exception.Message
        }
    }

    # =================================================================
    # 4. DEFENDER XDR CUSTOM SECURITY OPERATOR (via group)
    # =================================================================
    Write-Section 'Defender XDR custom Security Operator'
    if ($DoDefender) {
        try {
            $DefenderGroupId = Resolve-SecurityGroup $DefenderGroupName 'Members get the Defender XDR custom Security Operator role (PIM for Groups).'
            if ($DefenderGroupId) {
                Grant-PimGroupMembership 'Defender XDR custom Security Operator' 'Defender XDR' $DefenderGroupId $user.Id
            }
            else {
                Add-ReportRow 'Defender XDR custom Security Operator' 'Defender XDR' 'Preview Only' "Would create group $DefenderGroupName and add user"
            }
            $DefenderNote = $true
        }
        catch {
            Write-Warning "Defender group failed: $($_.Exception.Message)"
            Add-ReportRow 'Defender XDR custom Security Operator' 'Defender XDR' 'Failed' $_.Exception.Message
        }
    }
    else {
        Write-Host 'Skipped (-SkipDefender).'
        Add-ReportRow 'Defender XDR custom Security Operator' 'Defender XDR' 'Skipped' '-SkipDefender' '' ''
    }

    # =================================================================
    # 5. INTUNE ENDPOINT SECURITY MANAGER (via group)
    # =================================================================
    Write-Section 'Intune Endpoint Security Manager'
    $IntuneGroupId = $null
    if ($DoIntune) {
        try {
            $IntuneGroupId = Resolve-SecurityGroup $IntuneGroupName 'Members get the Intune Endpoint Security Manager role (PIM for Groups).'
        }
        catch {
            Write-Warning "Intune group failed: $($_.Exception.Message)"
            Add-ReportRow 'Intune Endpoint Security Manager' 'Intune' 'Failed' $_.Exception.Message
            $DoIntune = $false
        }
        if ($DoIntune -and -not $IntuneGroupId) {
            Add-ReportRow 'Intune Endpoint Security Manager' 'Intune' 'Preview Only' "Would create group $IntuneGroupName, assign the Intune role to it and add user"
            $DoIntune = $false
        }
    }
    if ($DoIntune) {
        $IntuneOk = $true
        try {
            # 5a. Make sure the Intune role is assigned to the group
            $roleDef = Get-GraphAll 'https://graph.microsoft.com/beta/deviceManagement/roleDefinitions' |
                Where-Object { $_.displayName -eq $IntuneRoleName -and $_.isBuiltIn } |
                Select-Object -First 1
            if (-not $roleDef) { throw "Intune role '$IntuneRoleName' not found" }

            $assignments = Get-GraphAll "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions/$($roleDef.id)/roleAssignments"
            $groupHasRole = $false
            foreach ($ra in $assignments) {
                $full = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                    -Uri "https://graph.microsoft.com/beta/deviceManagement/roleAssignments/$($ra.id)"
                if ($full.members -contains $IntuneGroupId) { $groupHasRole = $true; break }
            }

            if ($groupHasRole) {
                Write-Host "Group already has the Intune '$IntuneRoleName' role." -ForegroundColor Green
            }
            else {
                $scopeText = if ($IntuneScopeGroupIds) { "scope groups: $($IntuneScopeGroupIds -join ', ')" } else { 'scope: all devices and all licensed users' }
                $action = "create Intune role assignment '$IntuneRoleName' for group $IntuneGroupId ($scopeText)"
                if (Confirm-Change $IntuneGroupId $action) {
                    $raBody = @{
                        '@odata.type'                = '#microsoft.graph.deviceAndAppManagementRoleAssignment'
                        displayName                  = "Security Engineers - $IntuneRoleName"
                        description                  = 'Created by Grant-FullSecurityEngineerAccess.ps1'
                        members                      = @($IntuneGroupId)
                        'roleDefinition@odata.bind'  = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions/$($roleDef.id)"
                    }
                    if ($IntuneScopeGroupIds) {
                        $raBody.scopeType      = 'resourceScope'
                        $raBody.resourceScopes = @($IntuneScopeGroupIds)
                    }
                    else {
                        $raBody.scopeType      = 'allDevicesAndLicensedUsers'
                        $raBody.resourceScopes = @()
                    }
                    Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/roleAssignments' `
                        -Body ($raBody | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
                    Write-Host 'Intune role assignment created.' -ForegroundColor Green
                }
                elseif (-not $IsPreview) {
                    $IntuneOk = $false
                    Add-ReportRow 'Intune Endpoint Security Manager' 'Intune' 'Skipped by user' $action
                }
            }
        }
        catch {
            $IntuneOk = $false
            Write-Warning "Intune role assignment failed: $($_.Exception.Message)"
            Add-ReportRow 'Intune Endpoint Security Manager' 'Intune' 'Failed' $_.Exception.Message
        }

        # 5b. Make the user an eligible member of the group
        if ($IntuneOk) {
            Grant-PimGroupMembership 'Intune Endpoint Security Manager' 'Intune' $IntuneGroupId $user.Id
        }
    }
    elseif ($SkipIntune) {
        Write-Host 'Skipped (-SkipIntune).'
        Add-ReportRow 'Intune Endpoint Security Manager' 'Intune' 'Skipped' '-SkipIntune' '' ''
    }

    # =================================================================
    # 6-7. AZURE: SENTINEL CONTRIBUTOR + SECURITY READER
    # =================================================================
    Write-Section 'Azure RBAC (Sentinel Contributor, Security Reader)'
    if ($DoAzure) {
        $azParams = @{ WarningAction = 'SilentlyContinue' }
        if ($UseDeviceCode) { $azParams.UseDeviceAuthentication = $true }
        Connect-AzAccount @azParams | Out-Null
        $AzConnected = $true

        # Find the Sentinel subscription + resource group if not given
        if (-not $SentinelResourceGroup -and -not $SentinelAtSubscription) {
            Write-Host 'Looking for Microsoft Sentinel workspaces...'
            $subs = if ($SubscriptionId) { Get-AzSubscription -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue }
                    else { Get-AzSubscription -WarningAction SilentlyContinue | Where-Object State -eq 'Enabled' }
            $found = @()
            foreach ($sub in $subs) {
                Set-AzContext -SubscriptionId $sub.Id -WarningAction SilentlyContinue | Out-Null
                Get-AzResource -ResourceType 'Microsoft.OperationsManagement/solutions' -ErrorAction SilentlyContinue |
                    Where-Object Name -like 'SecurityInsights*' |
                    ForEach-Object {
                        $found += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            ResourceGroup    = $_.ResourceGroupName
                            Workspace        = ($_.Name -replace '^SecurityInsights\(', '' -replace '\)$', '')
                        }
                    }

                # Fallback: workspaces onboarded to Sentinel without the classic "SecurityInsights" solution resource
                Get-AzResource -ResourceType 'Microsoft.OperationalInsights/workspaces' -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $ws = $_
                        if ($found | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.Workspace -eq $ws.Name }) { return }
                        $r = Invoke-AzRestMethod -Method GET -Path "$($ws.ResourceId)/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" -ErrorAction SilentlyContinue
                        if ($r -and $r.StatusCode -eq 200) {
                            $found += [PSCustomObject]@{
                                SubscriptionName = $sub.Name
                                SubscriptionId   = $sub.Id
                                ResourceGroup    = $ws.ResourceGroupName
                                Workspace        = $ws.Name
                            }
                        }
                    }
            }

            if ($found.Count -eq 1) {
                $pick = $found[0]
            }
            elseif ($found.Count -gt 1) {
                Write-Host 'More than one Sentinel workspace found:' -ForegroundColor Yellow
                for ($i = 0; $i -lt $found.Count; $i++) {
                    Write-Host ("  [{0}] {1} / {2} / {3}" -f ($i + 1), $found[$i].SubscriptionName, $found[$i].ResourceGroup, $found[$i].Workspace)
                }
                do { $n = Read-Host 'Type the number of the workspace to use' }
                until ($n -as [int] -and [int]$n -ge 1 -and [int]$n -le $found.Count)
                $pick = $found[[int]$n - 1]
            }
            else {
                $pick = $null
            }

            if ($pick) {
                $SubscriptionId        = $pick.SubscriptionId
                $SentinelResourceGroup = $pick.ResourceGroup
                Write-Host "Sentinel: $($pick.SubscriptionName) / $($pick.ResourceGroup) / $($pick.Workspace)" -ForegroundColor Green
            }
            else {
                Write-Warning 'No Microsoft Sentinel workspace found in the subscriptions you can see.'
            }
        }

        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzContext).Subscription.Id
            Write-Host "Using current subscription for Azure Security Reader: $SubscriptionId"
        }
        Set-AzContext -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue | Out-Null

        $AzureTargets = [System.Collections.Generic.List[object]]::new()
        $SubScope = "/subscriptions/$SubscriptionId"
        if ($SentinelAtSubscription) {
            $AzureTargets.Add(@{ Item = 'Microsoft Sentinel Contributor'; Role = 'Microsoft Sentinel Contributor'; Scope = $SubScope })
        }
        elseif ($SentinelResourceGroup) {
            $AzureTargets.Add(@{ Item = 'Microsoft Sentinel Contributor'; Role = 'Microsoft Sentinel Contributor'; Scope = "$SubScope/resourceGroups/$SentinelResourceGroup" })
        }
        else {
            Add-ReportRow 'Microsoft Sentinel Contributor' 'Azure' 'Failed' 'No Sentinel workspace found. Re-run with -SentinelAtSubscription, or with -SubscriptionId and -SentinelResourceGroup.' '' ''
        }
        $AzureTargets.Add(@{ Item = 'Azure Security Reader'; Role = 'Security Reader'; Scope = $SubScope })

        foreach ($t in $AzureTargets) {
            Write-Host "`nProcessing: $($t.Item) on $($t.Scope)" -ForegroundColor Yellow
            $roleGuid = $AzureRoleIds[$t.Role]
            $roleDefId = "$SubScope/providers/Microsoft.Authorization/roleDefinitions/$roleGuid"

            try {
                # Active (direct, via groups, or inherited from a parent scope)
                $active = Get-AzRoleAssignment -ObjectId $user.Id -ExpandPrincipalGroups -ErrorAction Stop |
                    Where-Object {
                        $_.RoleDefinitionId -match $roleGuid -and
                        ($t.Scope -eq $_.Scope -or $t.Scope.StartsWith("$($_.Scope)/") -or $_.Scope -eq '/')
                    }
                # Eligible (direct)
                $elig = Get-AzRoleEligibilitySchedule -Scope $t.Scope -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.RoleDefinitionId -match $roleGuid }

                if ($active -or $elig) {
                    $how = @()
                    if ($active) { $how += "Active at $($active[0].Scope)" }
                    if ($elig)   { $how += "Eligible at $($elig[0].Scope)" }
                    Write-Host "Already has role: $($how -join '; ')" -ForegroundColor Green
                    Add-ReportRow $t.Item 'Azure' 'Already Assigned' ($how -join '; ')
                    continue
                }

                $action = "create $AssignmentType Azure role '$($t.Role)' (expires: $ExpiryText)"
                if (-not (Confirm-Change "$UserPrincipalName @ $($t.Scope)" $action)) {
                    Add-ReportRow $t.Item 'Azure' ($(if ($IsPreview) { 'Preview Only' } else { 'Skipped by user' })) "$action at $($t.Scope)"
                    continue
                }

                $req = @{
                    Name                      = [guid]::NewGuid().ToString()
                    Scope                     = $t.Scope
                    PrincipalId               = $user.Id
                    RoleDefinitionId          = $roleDefId
                    RequestType               = 'AdminAssign'
                    Justification             = $Justification
                    ScheduleInfoStartDateTime = $StartUtc
                }
                if ($NoExpiration) {
                    $req.ExpirationType = 'NoExpiration'
                }
                else {
                    $req.ExpirationType     = 'AfterDuration'
                    $req.ExpirationDuration = "P$($DurationDays)D"
                }

                if ($AssignmentType -eq 'Eligible') {
                    $r = New-AzRoleEligibilityScheduleRequest @req
                }
                else {
                    $r = New-AzRoleAssignmentScheduleRequest @req
                }
                Write-Host "Done: $($t.Item) [status: $($r.Status)]" -ForegroundColor Green
                Add-ReportRow $t.Item 'Azure' 'Successfully Assigned' "Scope $($t.Scope), status $($r.Status)"
            }
            catch {
                Write-Warning "Failed: $($t.Item) - $($_.Exception.Message)"
                Add-ReportRow $t.Item 'Azure' 'Failed' $_.Exception.Message
            }
        }
    }
    else {
        Write-Host 'Skipped (-SkipAzure).'
        Add-ReportRow 'Microsoft Sentinel Contributor' 'Azure' 'Skipped' '-SkipAzure' '' ''
        Add-ReportRow 'Azure Security Reader' 'Azure' 'Skipped' '-SkipAzure' '' ''
    }

    # =================================================================
    # 8. PURVIEW AUDIT READER
    # =================================================================
    Write-Section "Purview $PurviewRoleGroup"
    if ($DoPurview) {
        try {
            Connect-IPPSSession -ShowBanner:$false
            $IppsConnected = $true

            # Purview role groups have an internal Name (often without spaces, e.g. "AuditReader")
            # and a DisplayName. Match either, ignoring spaces.
            $want = $PurviewRoleGroup -replace '\s', ''
            $allGroups = Get-RoleGroup -ResultSize Unlimited
            $rg = $allGroups | Where-Object {
                ($_.Name -replace '\s', '') -eq $want -or ($_.DisplayName -replace '\s', '') -eq $want
            } | Select-Object -First 1

            if (-not $rg) {
                $similar = ($allGroups | Where-Object { $_.Name -like '*Audit*' -or $_.DisplayName -like '*Audit*' } |
                    ForEach-Object { if ($_.DisplayName) { $_.DisplayName } else { $_.Name } }) -join ', '
                throw "Purview role group '$PurviewRoleGroup' not found. Audit-related role groups in this tenant: $similar. Re-run with -PurviewRoleGroup '<name>'."
            }
            Write-Host "Role group: $($rg.Name)"
            $members = Get-RoleGroupMember -Identity $rg.Identity -ResultSize Unlimited
            $already = $members | Where-Object {
                $_.PrimarySmtpAddress -eq $user.UserPrincipalName -or
                $_.WindowsLiveID     -eq $user.UserPrincipalName -or
                $_.ExternalDirectoryObjectId -eq $user.Id
            }

            if ($already) {
                Write-Host 'Already a member.' -ForegroundColor Green
                Add-ReportRow "Purview $PurviewRoleGroup" 'Purview' 'Already Assigned' 'Direct member' 'Permanent' 'Never'
            }
            else {
                $action = "add to Purview role group '$PurviewRoleGroup' (permanent: Purview role groups have no PIM)"
                if (Confirm-Change $UserPrincipalName $action) {
                    Add-RoleGroupMember -Identity $rg.Identity -Member $user.UserPrincipalName -Confirm:$false
                    Write-Host "Added to $PurviewRoleGroup." -ForegroundColor Green
                    Add-ReportRow "Purview $PurviewRoleGroup" 'Purview' 'Successfully Assigned' 'Direct member' 'Permanent' 'Never'
                }
                else {
                    Add-ReportRow "Purview $PurviewRoleGroup" 'Purview' ($(if ($IsPreview) { 'Preview Only' } else { 'Skipped by user' })) $action 'Permanent' 'Never'
                }
            }
        }
        catch {
            Write-Warning "Purview failed: $($_.Exception.Message)"
            Add-ReportRow "Purview $PurviewRoleGroup" 'Purview' 'Failed' $_.Exception.Message 'Permanent' 'Never'
        }
    }
    else {
        Write-Host 'Skipped (-SkipPurview).'
        Add-ReportRow "Purview $PurviewRoleGroup" 'Purview' 'Skipped' '-SkipPurview' '' ''
    }

    # ---------------- REPORT ----------------
    $Report | Export-Csv -Path $ReportPath -NoTypeInformation

    Write-Host "`n=================================================="
    Write-Host 'SUMMARY'
    Write-Host '=================================================='
    $Report | Format-Table Item, System, Type, Expires, Status, Detail -AutoSize -Wrap
    Write-Host "Report saved: $ReportPath" -ForegroundColor Cyan

    if ($DefenderNote) {
        Write-Host @"

ONE MANUAL STEP (first time only) - Defender XDR custom role:
  1. Open https://security.microsoft.com
  2. System > Permissions > Microsoft Defender XDR > Roles > Create custom role
  3. Name: Security Operator - Custom
  4. Permissions:
       Security operations:        Security data basics (Read), Alerts (Manage),
                                   Response (Manage), Basic live response
       Security posture:           Vulnerability management (Read), Secure Score (Read)
       Authorization and settings: Core security settings (Read), Detection tuning (Manage)
  5. Assignments > Add assignment: group '$DefenderGroupName', Data sources: All
  6. Permissions > Microsoft Defender XDR > Workloads settings:
     turn unified RBAC ON for Defender for Endpoint and the other workloads you use.
  Skip this if you already did it.
"@ -ForegroundColor Yellow
    }
}
finally {
    if ($IppsConnected) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    if ($AzConnected)   { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null }
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
