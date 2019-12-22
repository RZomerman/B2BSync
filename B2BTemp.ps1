#Settings standards
#Please change the following settings to map to your own environment
    $Ou='OU=EXTERNAL USERS,DC=FORESTROOT,DC=local.Name'
    $SamAccountPrefix="G"

#Importing the functions module
Import-Module .\AADADB2BSync.psm1

#Generating and activating standard Log file
    $date=(Get-Date).ToString("d-M-y-h.m.s")
    $logname = ("AadAdB2B-" + $date + ".log")
    New-Item -Path $pwd.path -Value $LogName -ItemType File
    $LogFilePathName=$pwd.path + "\" + $LogName
    ActivateLogFile -LogFilePath $LogFilePathName


Try {
	Import-Module AzuserAD
	}
	catch {
    	Write-Host 'AzureAD Module not available - exiting' -ForegroundColor Red
	Exit
}

#ProvisionAADServiceAccount
If ($Provision) {
    Write-Host "Login to Azure AD PowerShell With Admin Account"
    Connect-AzureAD 
    $tenant = Get-AzureADTenantDetail

    # Create the self signed cert
    Write-Host "Generating Certificate"
    $currentDate = Get-Date
    $endDate  = $currentDate.AddYears(1)
    $notAfter  = $endDate.AddYears(1)
    $pwd  = GeneratePassword2
    $thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\localmachine\my -Subject "B2BSyncScript" -DnsName $tenant.ObjectId -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
    $pwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText
    Export-PfxCertificate -cert "cert:\localmachine\my\$thumb" -FilePath c:\temp\examplecert.pfx -Password $pwd

    # Load the certificate
    $cert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate("C:\temp\examplecert.pfx", $pwd)
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())


    # Create the Azure Active Directory Application
    Write-Host "Creating Service Principle"
    $application = New-AzureADApplication -DisplayName "B2BSyncScript" -IdentifierUris "https://blog.azureinfra.com"
    New-AzureADApplicationKeyCredential -ObjectId $application.ObjectId -CustomKeyIdentifier "B2BSyncScript" -StartDate $currentDate -EndDate $endDate -Type AsymmetricX509Cert -Usage Verify -Value $keyValue

    # Create the Service Principal and connect it to the Application
    $sp = New-AzureADServicePrincipal -AppId $application.AppId -DisplayName B2BSyncScriptSP

    # Give the Service Principal Reader access to the current tenant (Get-AzureADDirectoryRole)
    Write-host "Provining Read access to SP in AAD"
    Add-AzureADDirectoryRoleMember -ObjectId 5997d714-c3b5-4d5b-9973-ec2f38fd49d5 -RefObjectId $sp.ObjectId

    # Get Tenant Detail

    # Now you can login to Azure PowerShell with your Service Principal and Certificate

}

If ($Automated) {
    #If using service principal, need to login with SP
    #NEED TO ADD SERVICE PRINCIPAL APPID INTO THE CERT TO REUSE IT
    $cert=Get-ChildItem cert:\localmachine\my | where {$_.Subject -eq 'CN=B2BSyncScript'}
    $thumb = $cert.Thumbprint
    $tenantObjectID=$cert.DnsNameList.unicodeS
    $sp = Get-AzADServicePrincipal -DisplayName B2BSyncScriptSP
    

    Connect-AzureAD -TenantId $tenantObjectID -ApplicationId $sp.AppId -CertificateThumbprint $thumb
}
#Creating the two arrays to be used
$AADUPN = New-Object System.Collections.ArrayList
$ADUPN = New-Object System.Collections.ArrayList




If (-not ($Login)) {AZConnect}

#Login to the local AD - and retrieve the users from the specified OU - based on GC (to make the query faster)
#Next retrieve all B2B / guest users from AAD
$ADUsers=GetADGuestUsers -OU $ou -GC $true -domain $domain
$AADUsers=ReadGuestUsers

#Extracting the UPN from the AAD Guest Users and AD users and validing the 2 arrays for differences
#From there, we split the array in Tobe created users and tobe deleted users
ForEach ($UPN in $AADUsers) {
    $AADUPN.add($UPN.UserPrincipalName)
}
ForEach ($UPN2 in $ADUsers) {
    $ADUPN.add($UPN2.UserPrincipalName)
}

[array]$UserSyncStatus = Compare-Object -ReferenceObject ($ADUPN) -DifferenceObject ($AADUPN)
[array]$usersToDelete=$UserSyncStatus | where {$_.SideIndicator -eq '<='}
[array]$usersToCreate=$UserSyncStatus | where {$_.SideIndicator -eq '=>'}


If ($usersToCreate) {
    ForEach ($UserUPN in $usersToCreate) {
        #Get The original object from AADUsers array - to be able to extract all required info
        $UserObject=$AADUsers | where {$_.UserPrincipalName -eq $UserUPN.InputObject}
        $Password = GeneratePassword2 -Length 40
        $GeneratedSamAccountName=GenerateSamAccountName -Prefix $SamAccountPrefix
        $SecurePassword=($Password |ConvertTo-SecureString -AsPlainText -Force)
        write-host "Creating user as:"
        write-host (" Name: " + $userobject.DisplayName)
        write-host (" samAccountname: " +  $GeneratedSamAccountName)
        write-host (" UserPrincipalName: " + $UserObject.UserPrincipalName)
        write-host (" OU: " + $ou)
        write-host (" Password: " + $SecurePassword) 

        if (!(SearchExistingUser)){
            CreateUser -OU $ou -UserObject $UserObject 
        }
    }
}

If ($usersToDelete) {
    ForEach ($UserUPN in $usersToDelete) {
     #Get The original object from ADUsers array - to be able to extract all required info
        $UserObject=$ADUsers | where {$_.UserPrincipalName -eq $UserUPN.InputObject}
        write-host ("Deleting users from AD without B2B account in OU " + $ou)
        write-host "$UserObject"
        if ($UserObject) {
            DeleteUser -UserObject $userobject
        }
    }
}