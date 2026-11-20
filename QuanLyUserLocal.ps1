#requires -Version 5.1
# Local Windows account manager (Windows 10/11)
# Run with Administrator privileges. The script will request elevation if needed.

$ErrorActionPreference = 'Stop'
$script:UserListRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$script:AdminGroup = $null

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-ElevatedCopy {
    $quotedScript = '"' + $PSCommandPath + '"'
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File ' + $quotedScript

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $powerShellExe = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    }
    else {
        $powerShellExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    Start-Process -FilePath $powerShellExe -Verb RunAs -ArgumentList $arguments
}

function Get-AdminSidSet {
    $sidSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $members = Get-LocalGroupMember -Group $script:AdminGroup.Name -ErrorAction Stop
    foreach ($member in $members) {
        if ($null -ne $member.SID) {
            [void]$sidSet.Add($member.SID.Value)
        }
    }
    return ,$sidSet
}

function Get-UserVisibility {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not (Test-Path -LiteralPath $script:UserListRegPath)) {
        return 'Visible'
    }

    $item = Get-ItemProperty -LiteralPath $script:UserListRegPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return 'Visible'
    }

    $property = $item.PSObject.Properties[$Name]
    if ($null -ne $property -and [int]$property.Value -eq 0) {
        return 'Hidden'
    }
    return 'Visible'
}

function Set-UserVisibility {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Hidden', 'Visible')][string]$Visibility
    )

    if ($Visibility -eq 'Hidden') {
        New-Item -Path $script:UserListRegPath -Force | Out-Null
        New-ItemProperty -LiteralPath $script:UserListRegPath -Name $Name -PropertyType DWord -Value 0 -Force | Out-Null
    }
    else {
        # Removing the override restores Windows' default visibility behavior.
        if (Test-Path -LiteralPath $script:UserListRegPath) {
            Remove-ItemProperty -LiteralPath $script:UserListRegPath -Name $Name -ErrorAction SilentlyContinue
        }
    }
}

function Wait-ForEnter {
    [void](Read-Host 'Press Enter to continue')
}

function Get-LocalUsersSorted {
    return @(Get-LocalUser | Sort-Object -Property Name)
}

function Show-LocalUsers {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' LOCAL WINDOWS USERS' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan

    try {
        $users = Get-LocalUsersSorted
        $adminSids = Get-AdminSidSet

        $rows = foreach ($user in $users) {
            if ($adminSids.Contains($user.SID.Value)) {
                $role = 'Administrator'
            }
            else {
                $role = 'Standard'
            }

            [pscustomobject]@{
                Username = $user.Name
                Enabled  = [string]$user.Enabled
                Role     = $role
                SignIn   = Get-UserVisibility -Name $user.Name
                SID      = $user.SID.Value
            }
        }

        $rows | Format-Table -AutoSize
        Write-Host 'Note: Hidden only hides the account from the normal sign-in user list.' -ForegroundColor DarkGray
    }
    catch {
        Write-Host ('Could not read local users: ' + $_.Exception.Message) -ForegroundColor Red
    }

    Wait-ForEnter
}

function Convert-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][Security.SecureString]$SecureValue)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Add-LocalUserInteractive {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' CREATE LOCAL USER' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host 'Use 1-20 characters: A-Z, a-z, 0-9, dot, underscore or hyphen.'
    Write-Host 'Example: userprint'
    Write-Host ''

    $name = (Read-Host 'New username (blank = cancel)').Trim()
    if ([string]::IsNullOrWhiteSpace($name)) { return }

    if ($name.Length -gt 20 -or $name -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        Write-Host 'Invalid username. Use only A-Z, a-z, 0-9, dot, underscore or hyphen; max 20 characters.' -ForegroundColor Red
        Wait-ForEnter
        return
    }

    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
        Write-Host ('User already exists: ' + $name) -ForegroundColor Yellow
        Wait-ForEnter
        return
    }

    Write-Host ''
    Write-Host '[1] Administrator'
    Write-Host '[2] Standard User'
    $roleChoice = (Read-Host 'Choose role').Trim()
    if ($roleChoice -notin @('1', '2')) {
        Write-Host 'Invalid role selection.' -ForegroundColor Red
        Wait-ForEnter
        return
    }

    Write-Host ''
    Write-Host '[1] Hidden from sign-in screen'
    Write-Host '[2] Visible using Windows default behavior'
    $visibilityChoice = (Read-Host 'Choose visibility').Trim()
    if ($visibilityChoice -notin @('1', '2')) {
        Write-Host 'Invalid visibility selection.' -ForegroundColor Red
        Wait-ForEnter
        return
    }

    Write-Host ''
    Write-Host 'Enter the password twice. Input is not displayed.' -ForegroundColor Yellow
    $password1 = Read-Host 'Password' -AsSecureString
    $password2 = Read-Host 'Confirm password' -AsSecureString
    $plain1 = $null
    $plain2 = $null
    $passwordsMatch = $false

    try {
        $plain1 = Convert-SecureStringToPlainText -SecureValue $password1
        $plain2 = Convert-SecureStringToPlainText -SecureValue $password2
        $passwordsMatch = ($plain1 -ceq $plain2)
    }
    catch {
        if ($null -ne $password1) { $password1.Dispose() }
        Write-Host ('Could not validate password input: ' + $_.Exception.Message) -ForegroundColor Red
        Wait-ForEnter
        return
    }
    finally {
        $plain1 = $null
        $plain2 = $null
        if ($null -ne $password2) { $password2.Dispose() }
    }

    if (-not $passwordsMatch) {
        if ($null -ne $password1) { $password1.Dispose() }
        Write-Host 'Passwords do not match. No user was created.' -ForegroundColor Red
        Wait-ForEnter
        return
    }

    try {
        New-LocalUser -Name $name -Password $password1 -Description 'Local account for network scan / SMB' -ErrorAction Stop | Out-Null
        Enable-LocalUser -Name $name -ErrorAction Stop
    }
    catch {
        Write-Host ('Could not create/enable user: ' + $_.Exception.Message) -ForegroundColor Red
        Wait-ForEnter
        return
    }
    finally {
        if ($null -ne $password1) { $password1.Dispose() }
    }

    $roleSucceeded = $true
    if ($roleChoice -eq '1') {
        try {
            Add-LocalGroupMember -Group $script:AdminGroup.Name -Member $name -ErrorAction Stop
        }
        catch {
            $roleSucceeded = $false
            Write-Host ('User was created, but could not be added to Administrators: ' + $_.Exception.Message) -ForegroundColor Red
        }
    }

    try {
        if ($visibilityChoice -eq '1') {
            Set-UserVisibility -Name $name -Visibility 'Hidden'
            $visibilityText = 'Hidden'
        }
        else {
            Set-UserVisibility -Name $name -Visibility 'Visible'
            $visibilityText = 'Visible (Windows default)'
        }
    }
    catch {
        $visibilityText = 'Could not change visibility: ' + $_.Exception.Message
    }

    Write-Host ''
    if ($roleChoice -eq '1' -and $roleSucceeded) {
        Write-Host ('Created Administrator user: ' + $name) -ForegroundColor Green
    }
    elseif ($roleChoice -eq '1') {
        Write-Host ('Created user, but role is currently Standard: ' + $name) -ForegroundColor Yellow
    }
    else {
        Write-Host ('Created Standard user: ' + $name) -ForegroundColor Green
    }
    Write-Host ('Sign-in visibility: ' + $visibilityText)
    Write-Host 'The account remains enabled even when hidden.'
    Write-Host 'For SMB scan, grant this account both Share and NTFS Modify/Write permissions on the scan folder.' -ForegroundColor Cyan
    Wait-ForEnter
}

function Select-LocalUser {
    param([Parameter(Mandatory = $true)][string]$Prompt)

    $users = Get-LocalUsersSorted
    if ($users.Count -eq 0) {
        Write-Host 'No local users found.' -ForegroundColor Yellow
        return $null
    }

    Write-Host ''
    for ($i = 0; $i -lt $users.Count; $i++) {
        Write-Host ('[{0}] {1} (Enabled={2})' -f ($i + 1), $users[$i].Name, $users[$i].Enabled)
    }
    Write-Host '[Enter] Cancel'

    $raw = (Read-Host $Prompt).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    $number = 0
    if (-not [int]::TryParse($raw, [ref]$number) -or $number -lt 1 -or $number -gt $users.Count) {
        Write-Host 'Invalid selection.' -ForegroundColor Red
        return $null
    }

    return $users[$number - 1]
}

function Remove-LocalUserInteractive {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' DELETE LOCAL USER' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host 'Built-in/system accounts and the account running this script are protected.'
    Write-Host 'Deleting a user does NOT delete its C:\Users profile folder.'

    try {
        $user = Select-LocalUser -Prompt 'Select user number to delete'
        if ($null -eq $user) { Wait-ForEnter; return }

        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($user.SID.Value -eq $currentSid) {
            Write-Host 'Refused: cannot delete the account currently running this script.' -ForegroundColor Red
            Wait-ForEnter
            return
        }

        if ($user.SID.Value -match '-(500|501|503|504)$' -or $user.Name -in @('DefaultAccount', 'WDAGUtilityAccount', 'defaultuser0')) {
            Write-Host 'Refused: this is a protected built-in Windows account.' -ForegroundColor Red
            Wait-ForEnter
            return
        }

        $adminSids = Get-AdminSidSet
        $allUsers = Get-LocalUsersSorted
        $enabledAdminUsers = @($allUsers | Where-Object { $_.Enabled -and $adminSids.Contains($_.SID.Value) })

        if ($adminSids.Contains($user.SID.Value) -and $user.Enabled -and $enabledAdminUsers.Count -le 1) {
            Write-Host 'Refused: this would remove the last enabled local Administrator account.' -ForegroundColor Red
            Wait-ForEnter
            return
        }

        Write-Host ''
        Write-Host ('Selected: ' + $user.Name) -ForegroundColor Yellow
        Write-Host ('Enabled:  ' + $user.Enabled)
        Write-Host ('SID:      ' + $user.SID.Value)
        Write-Host 'This operation removes the account only; its profile/data folder is left in place.'
        $confirmation = Read-Host ('Type the exact username to confirm deletion (' + $user.Name + ')')
        if ($confirmation -cne $user.Name) {
            Write-Host 'Cancelled. No changes made.' -ForegroundColor Yellow
            Wait-ForEnter
            return
        }

        Remove-LocalUser -InputObject $user -Confirm:$false -ErrorAction Stop
        if (Test-Path -LiteralPath $script:UserListRegPath) {
            Remove-ItemProperty -LiteralPath $script:UserListRegPath -Name $user.Name -ErrorAction SilentlyContinue
        }
        Write-Host ('Deleted local user: ' + $user.Name) -ForegroundColor Green
    }
    catch {
        Write-Host ('Delete failed: ' + $_.Exception.Message) -ForegroundColor Red
    }

    Wait-ForEnter
}

function Change-UserVisibilityInteractive {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' HIDE / SHOW LOCAL USER ON SIGN-IN SCREEN' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan

    try {
        $user = Select-LocalUser -Prompt 'Select user number'
        if ($null -eq $user) { Wait-ForEnter; return }

        $current = Get-UserVisibility -Name $user.Name
        Write-Host ('Current setting: ' + $current)
        Write-Host '[1] Hide user'
        Write-Host '[2] Show user (restore Windows default behavior)'
        $choice = (Read-Host 'Choose 1 or 2').Trim()

        if ($choice -eq '1') {
            Set-UserVisibility -Name $user.Name -Visibility 'Hidden'
            Write-Host ('User hidden: ' + $user.Name) -ForegroundColor Green
        }
        elseif ($choice -eq '2') {
            Set-UserVisibility -Name $user.Name -Visibility 'Visible'
            Write-Host ('Visibility override removed: ' + $user.Name) -ForegroundColor Green
        }
        else {
            Write-Host 'Invalid selection. No changes made.' -ForegroundColor Yellow
        }

        Write-Host 'This does not disable the account or prevent SMB authentication.' -ForegroundColor Cyan
    }
    catch {
        Write-Host ('Could not update visibility: ' + $_.Exception.Message) -ForegroundColor Red
    }

    Wait-ForEnter
}

# Relaunch in 64-bit PowerShell if started from a 32-bit host on 64-bit Windows.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    try {
        Start-ElevatedCopy
    }
    catch {
        Write-Host ('Could not start 64-bit PowerShell: ' + $_.Exception.Message) -ForegroundColor Red
        Wait-ForEnter
    }
    exit
}

if (-not (Test-IsAdministrator)) {
    try {
        Write-Host 'Administrator permission is required. Requesting UAC elevation...' -ForegroundColor Yellow
        Start-ElevatedCopy
    }
    catch {
        Write-Host ('Elevation was cancelled or failed: ' + $_.Exception.Message) -ForegroundColor Red
        Wait-ForEnter
    }
    exit
}

try {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $script:AdminGroup = Get-LocalGroup -SID $adminSid -ErrorAction Stop
}
catch {
    Write-Host 'This script requires the Windows LocalAccounts PowerShell module (Windows 10/11).' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Wait-ForEnter
    exit 1
}

while ($true) {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host '       LOCAL WINDOWS USER MANAGER' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ('Computer : ' + $env:COMPUTERNAME)
    Write-Host ('Run as   : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Write-Host ''
    Write-Host '[1] List local users'
    Write-Host '[2] Create user (Administrator / Standard, Hidden / Visible)'
    Write-Host '[3] Delete local user'
    Write-Host '[4] Change user visibility (Hidden / Visible)'
    Write-Host '[0] Exit'
    Write-Host ''

    $menuChoice = (Read-Host 'Choose an option').Trim()
    switch ($menuChoice) {
        '1' { Show-LocalUsers }
        '2' { Add-LocalUserInteractive }
        '3' { Remove-LocalUserInteractive }
        '4' { Change-UserVisibilityInteractive }
        '0' { break }
        default {
            Write-Host 'Invalid selection.' -ForegroundColor Red
            Wait-ForEnter
        }
    }

    if ($menuChoice -eq '0') { break }
}
