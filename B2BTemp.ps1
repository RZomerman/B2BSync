Param (
    [parameter()]
    $Provision,
    [parameter()]
    $Automated,
    [parameter()]
    $ApplicationId,
    [parameter()]
    $Login
)  

If ($ApplicationId) {
    $Automated = $true
}
#Settings standards
#Please change the following settings to map to your own environment
    $Ou='OU=EXTERNAL USERS,DC=MYDOMAIN,DC=local'
    $SamAccountPrefix="G"

#Cosmetic stuff
write-host ""
write-host ""
write-host "                               _____        __                                " -ForegroundColor Green
write-host "     /\                       |_   _|      / _|                               " -ForegroundColor Yellow
write-host "    /  \    _____   _ _ __ ___  | |  _ __ | |_ _ __ __ _   ___ ___  _ __ ___  " -ForegroundColor Red
write-host "   / /\ \  |_  / | | | '__/ _ \ | | | '_ \|  _| '__/ _' | / __/ _ \| '_ ' _ \ " -ForegroundColor Cyan
write-host "  / ____ \  / /| |_| | | |  __/_| |_| | | | | | | | (_| || (_| (_) | | | | | |" -ForegroundColor DarkCyan
write-host " /_/    \_\/___|\__,_|_|  \___|_____|_| |_|_| |_|  \__,_(_)___\___/|_| |_| |_|" -ForegroundColor Magenta
write-host "     "
write-host "This script copies B2B users in your AAD to AD users in order for Kerberos Constraint Delegation to work (based on UPN)" -ForegroundColor Green


#Importing the functions module and primary modules for AAD and AD
Import-Module .\AADADB2BSync.psm1
If (!((LoadModule -name AzureAD))){
    Write-host "AzureAD Module was not found - cannot continue - please install the module with Install-Module AzureAD"
    Exit
}
If (!((LoadModule -name ActiveDirectory))){
    Write-host "ActiveDirectory Module was not found - cannot continue - please install the module using server manager"
    Exit
}


#Generating and activating standard Log file
    $date=(Get-Date).ToString("d-M-y-h.m.s")
    $logname = ("AadAdB2B-" + $date + ".log")
    $workingDirectory=$PSScriptRoot
    #New-Item -Path $workingDirectory -Value $LogName -ItemType File
    $LogFilePathName=$workingDirectory + "\" + $LogName
    ActivateLogFile -LogFilePath $LogFilePathName


    #ProvisionAADServiceAccount
If ($Provision) {
    #Need to catch if powershell is open in admin mode (as script provisions Certificates in local machine and scheduled task)
    if (!([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))){
        Write-host "Please start powershell in admin mode for provisioning mode"
        exit
    }
    Write-Host "Login to Azure AD with Global Admin Account"
    If ($Login){Connect-AzureAD} 
    $tenant = Get-AzureADTenantDetail

    #Cleaning up existing certs
    $certold=Get-ChildItem cert:\localmachine\my | where {$_.Subject -eq 'CN=B2BSyncScript'} | Remove-Item

    #cleaning old application
    If ($ExistingApplication=Get-AzureADApplication |where {$_.DisplayName -eq 'B2BSyncScript'}) {
        WriteLog -Path $LogFilePathName -Value ("Existing application found - removing application")
        Remove-AzureADApplication -ObjectId $ExistingApplication.ObjectId
        Write-Host "Removed old application, need to pause for 10 seconds"
        sleep 10

    }

    #Cleaning Scheduled Tasks
    if (Get-ScheduledTask -TaskName 'AADtoADB2BSync' -ErrorAction SilentlyContinue){
        Unregister-ScheduledTask -TaskName 'AADtoADB2BSync' -Confirm:$false
    }

    # Create the self signed cert
    Write-Host "Generating Certificate"
    $currentDate = Get-Date
    $endDate  = $currentDate.AddYears(1)
    $notAfter  = $endDate.AddYears(1)
    $pwd  = GeneratePassword2
    $thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\localmachine\my -Subject "B2BSyncScript" -DnsName $tenant.ObjectId -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
    $pwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText
    Export-PfxCertificate -cert "cert:\localmachine\my\$thumb" -FilePath ($workingDirectory + "\B2BCert.pfx") -Password $pwd

    # Load the certificate
    $cert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate(($workingDirectory + "\B2BCert.pfx"), $pwd)
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())


    # Create the Azure Active Directory Application
    Write-Host "Creating Service Principle"
    $application = New-AzureADApplication -DisplayName "B2BSyncScript"
    

    New-AzureADApplicationKeyCredential -ObjectId $application.ObjectId -CustomKeyIdentifier "B2BSyncScript" -StartDate $currentDate -EndDate $endDate -Type AsymmetricX509Cert -Usage Verify -Value $keyValue

    # Create the Service Principal and connect it to the Application
    $sp = New-AzureADServicePrincipal -AppId $application.AppId -DisplayName B2BSyncScript

    # Give the Service Principal Reader access to the current tenant (Get-AzureADDirectoryRole)
    Write-host "Provining Read access to SP in AAD"
    $NewRole = $null
    $Retries = 0;
    write-host "waiting 15 for service principal to have finished creating"
    Sleep 15
    $DirectoryReaders=Get-AzureADDirectoryRole | where {$_.DisplayName -eq 'Directory Readers'}
    While ($NewRole -eq $null -and $Retries -le 6)
    {
        # Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
        Add-AzureADDirectoryRoleMember -ObjectId $DirectoryReaders.ObjectId -RefObjectId $sp.ObjectId | Write-Verbose -ErrorAction SilentlyContinue
        $NewRole = ((Get-AzureADDirectoryRoleMember -ObjectId $DirectoryReaders.ObjectId).objectID -contains $sp.ObjectId)
        $Retries++;
        write-host "waiting for SP to be added to group"                
        Sleep 15

     }
    

    # Get Tenant Detail

    # Now you can login to Azure PowerShell with your Service Principal and Certificate
    #Register a scheduled task
    Write-Host $application.AppId
    $AppID=$application.AppId
    $arguments=" -NoProfile -command & '$workingDirectory + \AADADB2BSync.ps1' -ApplicationId $AppID"
    Write-host "Creating Scheduled Task with Arguments:"
    write-host $arguments


    

    $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $arguments
    $trigger =  New-ScheduledTaskTrigger -Daily -At 3am
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AADtoADB2BSync" -Description "Synchronizes B2B accounts daily to AD for Kerberos Constraint Applications to be accessible to B2B accounts based on UPN only"
}
#END OF AUTOMATED PROVISIONING 


#IF running automated, the stored certificate will be used to authenicate and get the AAD Tenant. The variable -ApplicationID is used for the Service Principal.
If ($Automated) {
    #If using service principal, need to login with SP
    
    If (!($ApplicationId)){
        Write-host "No ApplicationID found - exit"
        Exit
    }
    $cert=Get-ChildItem cert:\localmachine\my | where {$_.Subject -eq 'CN=B2BSyncScript'}
    $thumb = $cert.Thumbprint
    $tenantObjectID=$cert.DnsNameList.unicode
    Connect-AzureAD -TenantId $tenantObjectID -ApplicationId $ApplicationId -CertificateThumbprint $thumb
    $login=$false
}


#ActualStartOfScript
#Creating the two arrays to be used
$AADUPN = New-Object System.Collections.ArrayList
$ADUPN = New-Object System.Collections.ArrayList

If ($Login) {AZConnect}

#Login to the local AD - and retrieve the users from the specified OU - based on GC (to make the query faster)
#Next retrieve all B2B / guest users from AAD

$ADUsers=GetADGuestUsers -OU $ou 
$AADUsers=ReadGuestUsers

WriteLog -Path $LogFilePathName -Value ("  AD B2B Users: " + $ADUsers.count)
WriteLog -Path $LogFilePathName -Value (" AAD B2B Users: " + $AADUsers.count)

#Extracting the UPN from the AAD Guest Users and AD users and validing the 2 arrays for differences
#From there, we split the array in Tobe created users and tobe deleted users
ForEach ($UPN in $AADUsers) {
    $void=$AADUPN.add($UPN.UserPrincipalName)
}
ForEach ($UPN2 in $ADUsers) {
    $void2=$ADUPN.add($UPN2.UserPrincipalName)
}

#As one of the two arrays could be empty, we also need to add workarounds in case that is so.. 
#The result of this part is two new arrays (or one depending on scenario) with objects: object.InputObject  == UPN
If ($ADUsers -and $AADUsers){
    [array]$UserSyncStatus = Compare-Object -ReferenceObject ($ADUPN) -DifferenceObject ($AADUPN)
    [array]$usersToDelete=$UserSyncStatus | where {$_.SideIndicator -eq '<='}
    [array]$usersToCreate=$UserSyncStatus | where {$_.SideIndicator -eq '=>'}
}elseif ($ADUsers -and (!($AADUsers))) {
    #AD UPN's found, no AAD UPN's full delete
    write-host "Full delete"
    $usersToDelete = New-Object System.Collections.ArrayList
    ForEach ($B2buserUPN in $ADUPN) {
        $user=@{
            InputObject=$B2buserUPN
        }
        $supress=$usersToDelete.Add($user)
    }
}elseif ($AADUsers -and (!($ADUsers))) {
    #AAD UPN's found, and no AD UPN's, full create
    write-host "Full create"
    $usersToCreate = New-Object System.Collections.ArrayList
    ForEach ($B2buserUPN in $AADUPN) {
        $user=@{
            InputObject=$B2buserUPN
        }
        $supress=$usersToCreate.Add($user)
    }   
}


#ACTUAL CREATION & DELETION OF ACCOUNTS 

If ($usersToCreate) {
    WriteLog -Path $LogFilePathName -Value ("Need to create " + $usersToCreate.count + " B2B users")
    ForEach ($UserUPN in $usersToCreate) {
        WriteLog -Path $LogFilePathName -Value (" Creating " + $UserUPN.InputObject)
        #Get The original object from AADUsers array - to be able to extract all required info
        $UserObject=$AADUsers | where {$_.UserPrincipalName -eq $UserUPN.InputObject}
        $GeneratedSamAccountName=GenerateSamAccountName -Prefix $SamAccountPrefix
        $Password = GeneratePassword2 -Length 40
        $SecurePassword=($Password |ConvertTo-SecureString -AsPlainText -Force)
        $validate = $true
        While ($Validate) {
            $Validate=SearchExistingUser -samAccountName $GeneratedSamAccountName
        }
        $validate=$false
        
        WriteLog -Path $LogFilePathName -Value ("Creating user as:")
        WriteLog -Path $LogFilePathName -Value (" Name: " + $userobject.DisplayName)
        WriteLog -Path $LogFilePathName -Value (" samAccountname: " +  $GeneratedSamAccountName)
        WriteLog -Path $LogFilePathName -Value (" UserPrincipalName: " + $UserObject.UserPrincipalName)
        WriteLog -Path $LogFilePathName -Value (" OU: " + $ou)
        WriteLog -Path $LogFilePathName -Value (" Password: " + $SecurePassword) 
        WriteLog -Path $LogFilePathName -Value (" ")

        CreateUser -OU $ou -UserObject $UserObject -Password $SecurePassword -SamAccountName $GeneratedSamAccountName

    Write-host "Next user" -ForegroundColor Green
    Write-host ""
    }
}

If ($usersToDelete) {
    WriteLog -Path $LogFilePathName -Value ("Need to delete " + $usersToDelete.count + " B2B users from AD")
    ForEach ($UserUPN in $usersToDelete) {
        WriteLog -Path $LogFilePathName -Value (" Deleting " + $UserUPN.InputObject)
        #Get The original object from ADUsers array - to be able to extract all required info
        $UserObject=$ADUsers | where {$_.UserPrincipalName -eq $UserUPN.InputObject}
        #write-host ("Deleting users from AD without B2B account in OU " + $ou)
        write-host "$UserObject"
        if ($UserObject) {
            DeleteUser -UserObject $userobject
        }
        WriteLog -Path $LogFilePathName -Value " "
    }
}
write-host ""
write-host ""
write-host ""

