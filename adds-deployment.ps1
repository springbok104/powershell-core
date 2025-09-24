<#
.SYNOPSIS
    Deploy ADDS on a Windows Server
.DESCRIPTION
    This automates the installation and config of ADDS
    Installs the role, promotes the server to domain controller
    Works with interactive prompts
.EXAMPLE
    PS C:\Scripts> .\ad-deployment.ps1
.NOTES
    Tested on Server 2025, requires Powershell 7+
.CONFIGURABLE VARIABLES
    DeployType          Enter one of 3 modes:
                            -NewForest      Creates a new forest & domain in AD
                            -NewChild       Creates a subdomain for an existing authority
                            -AdditionalDC   Deploys an additional DC for an existing domain. 
    DomainName          FQDN Domain name where your AD is going to be (eg "test.local")
    subdomainName       The prefix of an FQDN that you want to create an additional AD for (eg "corp")
    DSRMPassword        (! Avoid hardcoding password) Recovery password for ADDS | Leave blank for inputting your own
    ForestMode          Forest level you want to create (eg "Win2025")
    DatabasePath        NTDS directory
    SysvolPath          SYSVOL directory
    LogPath             NTDS directory

    AdministratorUser   Local/Domain Administrator
    AdministratorPass   (! Avoid hardcoding password) Password for Administrator | Leave blank for inputting your own

    precheck            If $true - checks password complexity, computer name, DNS resolution, Administrator account, DHCP is disabled
    reboot              If $true - reboots after installation of ADDS
    interactive         If $true - prompts you for input and confirmation
    transcriptOn        If $true - Starts a transcript log
    transcriptPath      Set path for transcript log


#>
####
#Deployment Variables:
$DeployType = "NewChild" 
$DomainName = "domain.local"
$SubdomainName = "ad"
$DSRMPassword = ''
$ForestMode = "Win2025"
$DatabasePath = "C:\Windows\NTDS"
$SysvolPath = "C:\Windows\SYSVOL"
$LogPath = "C:\Windows\NTDS"
$AdministratorUser = "Administrator"
$AdministratorPass = ""

#Script Variables:
$precheck = $true
$Reboot = $false
$interactive = $true
$transcriptOn = $true
$transcriptPath = '.\'

####

$RequiredVars = @('DeployType', 'DomainName', 'DSRMPassword', 'ForestMode', 'SubDomainName', 'AdministratorPass', 'AdministratorUser')

#CheckPassword checks the inputted password passes Windows password complexity. Outputs to secure string
function CheckPassword {
    param(
        [string]$initialPass,
        [string]$reason
    )
    
    $pass = $initialPass

    $passLength = $pass.Length -ge 15
    $passHasDigit = $pass -match '\d'
    $passHasLower = $pass -cmatch '[a-z]'
    $passHasUpper = $pass -cmatch '[A-Z]'

    while (-not ($passLength -and $passHasDigit -and $passHasLower -and $passHasUpper)) {
        Write-Host "Password does not meet complexity requirements. Please try again."
        Write-Host "Length >= 15 characters: $($passLength)"
        Write-Host "Contains a digit: $($passHasDigit)"
        Write-Host "Contains a lowercase letter: $($passHasLower)"
        Write-Host "Contains an uppercase letter: $($passHasUpper)"
        
        $pass = Read-Host -interactive "Enter Password for $($reason)" -MaskInput

        $passLength = $pass.Length -ge 15
        $passHasDigit = $pass -match '\d'
        $passHasLower = $pass -cmatch '[a-z]'
        $passHasUpper = $pass -cmatch '[A-Z]'
    }

    Write-Host "Password meets complexity requirements."
    return $pass | ConvertTo-SecureString -AsPlainText -Force
}

if ($transcriptOn){
    Start-Transcript -Path $transcriptPath
}

foreach ($i in $RequiredVars){
    #Check if there are any blank spaces in the require variables
    if ([string]::IsNullOrWhiteSpace((Get-Variable $i -ValueOnly -ErrorAction SilentlyContinue))) {
        write-host "One or more variables are missing values. Please input where interactiveed."

        if ($i -eq 'DSRMPassword'){
            Set-Variable $i -Value $(CheckPassword -reason "DSRM Password")
        }
        elseif ($i -eq 'AdministratorPass'){
            Set-Variable $i -Value $(CheckPassword -reason "Local/Domain Administrator Password")
        }
        else {
            Set-Variable $i -Value $(read-host "Enter value for $i")
        }
    }
}

if ($precheck) {
    #Check if DSRM and admin passwords are valid. Prompts users for passwords if not
    $DSRMPassword = CheckPassword $DSRMPassword -reason "DSRM Password"
    $AdministratorPass = CheckPassword $AdministratorPass -reason "Local/Domain Administrator Password"
    $features = Get-WindowsFeature -Name "AD-Domain-Services" #Retrieve status of ADDS role

    if ($features.InstallState -eq "Installed"){
        $installedADDS = $true 
    }
    elseif ($features.InstallState -ne "Available") {
        write-host "Feature is not available for installation."
        exit 1
    }

    if (-not (Resolve-DnsName $DomainName -ErrorAction SilentlyContinue)) {
        Write-Host "DNS resolution failed for $DomainName"
        return
    }

    #Checks if server is already a domain controller
    if ($DeployType -eq 'NewChild' -and ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq '2')) {
       throw "This server is already promoted. Cannot create a child domain from an existing DC."
       exit 1
    }

    #Checks if there is a local user that matches the username in the variables
    $getLocalUsers = Get-LocalUser -name $AdministratorUser
        if ($getLocalUsers){
            if ($interactive){
                $setLocalUser = read-host "Would you like to set the $($getLocalUsers.name) password? (y/n)"
                if ($setLocalUser -match "y|yes"){
                    Set-LocalUser -name $getLocalUsers.Name -Password $AdministratorPass
                    write-host "Local administrator account password has been set"
                }
                else{
                    write-host "Local administrator account left untouched."
                }
            }
            else{
                Set-LocalUser -name $getLocalUsers.Name -Password $AdministratorPass
            }
        }
        else{
            throw "No Administrator account found with the name $AdministratorUser"
        }

    $currentName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name

    #Check if server has a generic WIN name.
    if ($currentName -like "WIN-*") {
        $newName = Read-Host -interactive "The current name '$currentName' is generic. Enter a new server name:"
        Rename-Computer -NewName $newName -PassThru -Force
        Write-Host "Server has been renamed to '$newName'. A restart is required. Please restart the server and re-run this script."
        pause 
    }

    #Change DNS to localhost and cloudflare if server is to be a new domain controller with new forest
    if ($DeployType -eq "NewForest") {
        $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).ifIndex).ServerAddresses
        if ($dnsServers -notcontains "127.0.0.1") {
            Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).ifIndex -ServerAddresses ("127.0.0.1", "1.1.1.1")
        }
    }

    #Check if DHCP is enabled on the primary network adapter
    $primaryAdapter = Get-NetIPConfiguration | Where {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -eq "Up"
    }

    if ($primaryAdapter.NetIPv4Interface.DHCP -ne "Disabled") {
        write-host "DHCP is enabled. Set a static IP first."
        return
    }
}

try{
    #Install ADDS role if it was marked as not installed earlier
    if (-not $installedADDS){
        write-host "Installing AD Domain Services..."
        $installWF = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction stop

        if (-not $installWF.Success) {
            write-host "Failed to install AD Domain Services"
            throw "Feature installation failed. Exit code: $($installWF.ExitCode)"
        }
    }
}
catch {
    Write-Warning "Feature installation failed. Exit code: $($installWF.ExitCode)"
}

$params = @{}
$testCmdlet = $null
$installCmdlet = $null

#Switch the commands/parameters depending on $DeployType
switch ($DeployType) {
    'NewForest' {
        $testCmdlet = 'Test-ADDSForestInstallation'
        $installCmdlet = 'Install-ADDSForest'
        $params = @{
            DomainName                    = $DomainName
            SafeModeAdministratorPassword = $DSRMPassword
            ForestMode                    = $ForestMode
            DatabasePath                  = $DatabasePath
            SysvolPath                    = $SysvolPath
            LogPath                       = $LogPath
            InstallDns                    = $true
            NoRebootOnCompletion          = if (-not ($reboot)) {$true} else {$false}
        }
    }

    'NewChild' {
        $testCmdlet = 'Test-ADDSDomainInstallation'
        $installCmdlet = 'Install-ADDSDomain'

        #Filter out anything with a . Just get the prefix
        if ($SubdomainName -match "\.") {
            $SubdomainName = $SubdomainName.Split('.')[0]
        }
        $params = @{
            NewDomainName                 = $SubdomainName
            ParentDomainName              = $DomainName
            SafeModeAdministratorPassword = $DSRMPassword
            DomainType                    = 'ChildDomain'
            DatabasePath                  = $DatabasePath
            SysvolPath                    = $SysvolPath
            LogPath                       = $LogPath
            InstallDns                    = $true
            CreateDnsDelegation           = $false
            NoRebootOnCompletion          = if (-not ($reboot)) {$true} else {$false}
        }
    }

    'AdditionalDC' {
        $testCmdlet = 'Test-ADDSDomainControllerInstallation'
        $installCmdlet = 'Install-ADDSDomainController'
        $params = @{
            DomainName                    = $DomainName
            SafeModeAdministratorPassword = $DSRMPassword
            DatabasePath                  = $DatabasePath
            SysvolPath                    = $SysvolPath
            LogPath                       = $LogPath
            InstallDns                    = $true
            NoRebootOnCompletion          = if (-not ($reboot)) {$true} else {$false}
        }
    }
    default {
        throw "Unknown deployment type: $DeployType"
    }
}

#add -force if interactive is $false to bypass prompts by the ADDS installation
if (-not $interactive) {
    $params.Add('Force', $true)
}

try{
    write-host "Testing the installation for $DeployType"
    $ProgressPreference = 'SilentlyContinue'
    $result = & $testCmdlet @params -ErrorAction stop
    $ProgressPreference = 'continue'
    if (-not ($result.Status -eq "Success")){
        write-host "Test failed to complete: $($result.context)"
        return
    }
}
catch {
    write-host "Test failed to complete Error: $($_.Exception.Message)"
}

Write-host "`nHere are the settings for the install:`n"
write-host "Test install was a $($result.status)"
Write-host "Mode: $DeployType"
write-host "Hostname: $((Get-CimInstance -ClassName Win32_ComputerSystem).Name)"
$params.GetEnumerator() | Format-Table -AutoSize 

if ($interactive){
    #Prompt to proceed with the above settings
    $interactiveCont = read-host -interactive "Would you like to proceed? (y/n)" 
}

if ($interactiveCont -match "y|yes" -or $interactive -eq $false){
    write-host "Proceeding to install"
    try{
        #Run the installation command with the parameters and store the result
        $result = & $installCmdlet @params -ErrorAction stop

        if ($result.Status -eq "Success"){
            write-host "ADDS has been installed"
            write-host "Please restart the server"
            }
        else{
            write-host "Failed to install/create, reason $_"
        }
    }
    catch{
        throw "Failed to install Error: $($_.Exception.Message)"
        exit 1
    }
}
Stop-Transcript