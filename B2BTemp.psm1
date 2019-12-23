#ReadGuestUsers
#ValidateArrayAgainstAD-GC-RemoveExisting
#RemoveAccountsFromADNotExisting
#CreateNewAccounts

Function WriteDebug{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$true)][string]$Value)
    Process{
        #If ($Debug) {
        Write-host $Value
        #}
    }
}

Function ActivateLogfile(){
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$true)][string]$LogFilePath)
    Add-Content -Path $LogFilePath -Value "***************************************************************************************************"
    Add-Content -Path $LogFilePath -Value "Started processing at [$([DateTime]::Now)]."
    Add-Content -Path $LogFilePath -Value "***************************************************************************************************"
    Add-Content -Path $LogFilePath -Value ""
    Write-Host ("Logfile: " + $LogFilePath)
}


Function WriteLog{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Path
    )
    Process{
        write-host $Value
        Add-Content -Path $Path -Value $Value
    }
}

Function ReadGuestUsers{
    $GuestUsers=Get-AzureADUser | where {$_.usertype -eq "Guest"}
    If ($GuestUsers.count -eq 0) {
        WriteDebug -Value "No Guest Users Found"
        return $false
    }else{
        WriteDebug -Value ("Found " + $GuestUsers.count + " AAD guest users")
        return $GuestUsers
    }
}

Function ValidateGuestAgainstAD{
    Param (
        [parameter()]
        $GuestUsers,
        [parameter()]
        $DCInfo
    )   
    Foreach ($user in $GuestUsers) {
        $mail=$user.$mail

    }
}

Function ValidateADConnection{
    Param (
        [parameter()]
        $Domain,
        [parameter()]
        $OU,
        [parameter()]
        $DC
    )   
    #Function validates access to GC - get RootDSE
    #Function validates access to OU and write permissions

}

Function CreateUser{
    Param (
        [parameter()]
            $OU,
        [parameter()]
            $UserObject,
        [parameter()]
            $SamAccountName,
        [parameter()]
            [SecureString] $Password

    ) 
    #NeedToGenerateSamAccountName and validate uniqueness
    $GeneratedSamAccountName=GenerateSamAccountName
    New-ADUser -Name $UserObject.DisplayName -SamAccountName $SamAccountName -UserPrincipalName $UserObject.UserPrincipalName -Path $OU -AccountPassword $Password -Enabled $true
}


Function DeleteUser{
    Param (
        [parameter()]
            $UserObject
    ) 
    $User=Remove-ADUser -Identity $UserObject.DistinguishedName -Confirm:$false
}

Function GenerateSamAccountName{
    Param (
        [parameter()]
            $Prefix
    ) 
    #SamAccountName = G<numbers-10>
    do {
        $SamAccount=($Prefix + (get-random -maximum 9000000 -minimum 100000))
        $result=SamAccountNameCheck -SamAccountName $SamAccount
        WriteDebug -Value ("Generated SAMAccountName" + $SamAccount)
        WriteDebug -Value ("SamAccountNameCheck Result is: " + $result)
    } until ($result -ne $true)
    
    WriteDebug -Value ("Final Generated SamAccount: " + $SamAccount)
    return $SamAccount
}

Function GeneratePassword2{
    Param (
        [int]$Length = 40
    )
    Add-Type -AssemblyName System.Web
    $CharSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{]+-[*=@:)}$^%;(_!&#?>/|.'.ToCharArray()
    #Index1s 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456
    #Index10s 0 1 2 3 4 5 6 7 8   
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($Length)
    $rng.GetBytes($bytes)
    $rawPass = New-Object char[]($Length)
    For ($i = 0 ; $i -lt $Length ; $i++){
        $rawPass[$i] = $CharSet[$bytes[$i]%$CharSet.Length]
    }
    $Return=(-join $rawPass)
    #WriteDebug -Value (-join $rawPass)
    Return ( $Return)
}
Function GetADGuestUsers{
        Param (
        [parameter()]
            $OU,
        [parameter()]
            $GC,
        [parameter()]
            $domain
    ) 
    If ($GC -eq $true) {
        $PSDefaultParameterValues = @{
        "*-AD*:Server" = ($domain + ":3268")
        }
    }
    [array]$ADUsers=Get-ADUser -Filter * -SearchBase $OU 
    
    #Return the results, if any
    If (($ADUsers.count -eq 0) -or (!($ADUsers))) {
        WriteDebug -Value "No existing users found"
        return $false
    }else{
        WriteDebug -Value ("Found " + $ADUsers.count + " existing AD Users")
        return $ADUsers
    }
}

Function SearchExistingUser{
#function searches for a UPN in the domain specified and returns $true if a user is found
#Function uses the GC optionally 
    Param (
        [parameter()]
        $Domain,
        [parameter()]
        $samAccountName,
        [parameter()]
        $GC
    )   

    If ($GC -eq $true) {
        $PSDefaultParameterValues = @{
            "*-AD*:Server" = ($domain + ":3268")
        }
    }
    [array]$Results=Get-ADUser -Filter {samAccountName -like $samAccountName}
    If ($Results.count -eq 0) {
        WriteDebug -Value "No users found - need to create"
        return $false
    }elseif ($results.Count -eq 1) {
        #single user found - returning single user
        return $Results[0]
    }else{
        #multiple users found
        WriteDebug -Value "Existing users found - no need to do anything"
        return $false
    }
}

Function SamAccountNameCheck{
    #function searches for a UPN in the domain specified and returns $true if a user is found
    #Function uses the GC optionally 
        Param (
            [parameter()]
            $Domain,
            [parameter()]
            $sAMAccountName,
            [parameter()]
            $GC
        )   
    
        If ($GC -eq $true) {
            $PSDefaultParameterValues = @{
                "*-AD*:Server" = ($domain + ":3268")
            }
        }
        [array]$Results=Get-ADUser -Filter "samAcountName -eq '$($sAMAccountName)'"
        WriteDebug -Value ("samcccountname search" +$Results)
        If ($Results.count -eq 0) {
            WriteDebug "No users found - need to create"
            return $false
        }else{
            #multiple users found
            WriteDebug -Value "Existing users found"
            return $true
        }
    }
Function AZConnect {
    Connect-AzureAD
}

Function LoadModule
{
    param (
        [parameter(Mandatory = $true)][string] $name
    )

    $retVal = $true
    if (!(Get-Module -Name $name))
    {
        $retVal = Get-Module -ListAvailable | where { $_.Name -eq $name }
        if ($retVal)
        {
            try
            {
                Import-Module $name -ErrorAction SilentlyContinue
            }
            catch
            {
                $retVal = $false
            }
        }
    }
    return $retVal
}


