<#
    Some certificate tools for Powershell

    https://github.com/magnuswatn/cert-tools
#>

#region helperfunctions

Function Get-CertificateFromHost($host) {
    <# Gets a certificate from a host listening on TLS #>
    $parsedHost = $host.split(":")

    $url = "https://$($parsedHost[0])"

    $port = $parsedHost[1]
    if ($port) {
        $url += ":$($port)"
    }
    
    # Activate all SSL/TLS protocols, so that we can connect to as many sites as possible
    $oldtlsprotocols = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = 'ssl3', "tls", "tls11", "tls12"

    $request = [System.Net.HttpWebRequest]::Create($url)

    $request.AllowAutoRedirect = $false

    try {
        $request.GetResponse().Dispose()
    } catch {
        # Ignoring errors silently, might come of non-200 code or trust error. We only care if we got a certificate
        $error = $_
    }

    # Setting the TLS protocols back to whatever it was
    [Net.ServicePointManager]::SecurityProtocol = $oldtlsprotocols
        
    if ($request.ServicePoint.Certificate -ne $null) {
        return New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $request.ServicePoint.Certificate
    } else {
        # We didn't get a certificate :-( throwing the error from the request
        throw $error
    }
}

Function Show-PEM($certificate) {
    <# Prints a certificate in PEM format #>
    $b64cert = [System.Convert]::ToBase64String($certificate.RawData)
    $pemcert = "-----BEGIN CERTIFICATE-----`r`n"
    $i = 0
    foreach($char in $b64cert.ToCharArray()) {
        if($i -eq 64){ 
            $pemcert += "`r`n$char" 
            $i = 0
        } else { 
            $pemcert += $char 
        }
        $i += 1
    }
    $pemcert += "`r`n-----END CERTIFICATE-----"

    "[PEM format]"
    "$pemcert `r`n"
}

Function Show-HEX($data) {
    <# Print base64 encoded data as HEX #>
    $hexdump=""
    $rawdata = [System.Convert]::FromBase64String($data)
    foreach($byte in $rawdata) {
        $hexdump+="{0:X2}:" -f $byte
    }
    return $hexdump.Substring(0,$hexdump.Length-1)
}

Function Get-CertificateFromFile($path) {
    <# Loads a certificate from file #>
    $pathtocert=(Resolve-Path -Path $path).path
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($pathtocert)
    return $cert
}

Function Open-Certificate($cert) {
    <# Opens a certificate in the Windows Certificate dialog #>
    $tempfil = ([System.IO.Path]::GetTempFileName() + ".cer")
    [io.file]::WriteAllBytes($tempfil, $cert.Export("cert"))
    & $tempfil
}

Function Show-CertificateInfo($id, $cert) {
    <# Prints information about a certificate #>
    $serialnumberINT = $([bigint]::Parse($cert.GetSerialNumberString(), [System.Globalization.NumberStyles]::HexNumber))
    "#####################$($id)#####################"
    "$cert"
    "[Key Usages]"
    "  $($cert.Extensions.KeyUsages) `r`n"
    "[Serial Number in INT]"
    "  $serialnumberINT `r`n"
    "[DNS names]"
    $cert.DnsNameList.UniCode | foreach { " $_" }
    "`r`n[Is trusted]"
    "  $($cert.verify()) `r`n"
}

Function Show-CertificateStatus($cert) {
    <# Prints information about the trust status of a certificate #>
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain

    "[Certificate status]"
    if($chain.Build($cert)) {
        " OK`r`n"
    } else {
        " $($chain.ChainStatus.StatusInformation)`r`n"
    }
}

#endregion


#region cmdlets

Function Get-CertFromLDAP {
    <#
    .Synopsis
       Downloads certificates from an ldap url
    .DESCRIPTION
       Downloads certificates from an ldap url and displays relevant information, and optionally opens the certificate in the Windows certificate dialog or 
       prints them in PEM format.

       Buypass has a limit of 20 certificates, so if the query returns 20 certificates, a new search will be done with the current results excluded.
       This will repeat max five times (can be raised with MaxRetries).

    .EXAMPLE
       Get-CertFromLDAP "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20CA%203?usercertificate;binary?sub?(pssuniqueidentifier=1323527)"
       Downloads the certificate and display relevant information
    .EXAMPLE
       Get-CertFromLDAP "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20CA%203?usercertificate;binary?sub?(serialnumber=983163327)" -OnlyValid
       Downloads the certificates and display relevant information about the valid ones
    .EXAMPLE
       Get-CertFromLDAP "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20CA%203?usercertificate;binary?sub?(pssuniqueidentifier=1323527)" -Open
       Downloads the certificate and opens it in the Windows Certificate dialog
    .EXAMPLE
       Get-CertFromLDAP "ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20CA%203?usercertificate;binary?sub?(pssuniqueidentifier=1323527)" -PrintPEM
       Downloads the certificate and prints it out in PEM format
    .INPUTS
       LDAP url (RFC1959). Must return certificates as "usercertificate;binary".
    .OUTPUTS
       Certificate information
    .NOTES
       Example urls for Norwegian qualified certificates:

        Buypass PROD:
            ldap://ldap.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20CA%203?usercertificate;binary?sub?(serialnumber=983163327)

        Buypass TEST4:
            ldap://ldap.test4.buypass.no/dc=Buypass,dc=no,CN=Buypass%20Class%203%20Test4%20CA%203?usercertificate;binary?sub?(serialnumber=983163327)

        Commfides PROD Person High:
            ldap://ldap.commfides.com/ou=Person-High,dc=commfides,dc=com?usercertificate;binary?sub?(cn=Mr Milk)

        Commfides PROD Enterprise:
            ldap://ldap.commfides.com/ou=Enterprise,dc=commfides,dc=com?usercertificate;binary?sub?(serialNumber=988312495)

        Commfides TEST Person High:
            ldap://ldap.test.commfides.com/ou=Person-High,dc=commfides,dc=com?usercertificate;binary?sub?(cn=Mr Milk)

        Commfides TEST Enterprise:
            ldap://ldap.test.commfides.com/ou=Enterprise,dc=commfides,dc=com?usercertificate;binary?sub?(serialNumber=988312495)
    #>
    [cmdletbinding()]
    Param([Parameter(mandatory=$true)][System.Uri]$ldapstring,
          [Parameter(mandatory=$false)][Switch]$Open,
          [Parameter(mandatory=$false)][Switch]$PrintPEM,
          [Parameter(mandatory=$false)][Switch]$Status,
          [Parameter(mandatory=$false)][Switch]$OnlyValid,
          [Parameter(mandatory=$false)][Int]$MaxRetries=5)
    
    $ErrorActionPreference = "Stop"
    Add-Type -AssemblyName System.DirectoryServices.Protocols

    if ($ldapstring.scheme -eq "ldap") {
        $secure = $false
    } elseif ($ldapstring.Scheme -eq "ldaps") {
        $secure = $true
    } else {
        throw "Unknown protocol. LDAP(S) only."
    }

    $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection "$($ldapstring.Host):$($ldapstring.Port)"
    $ldapConnection.SessionOptions.SecureSocketLayer = $secure
    $ldapConnection.SessionOptions.ProtocolVersion = 3
    $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous

    $basedn = $ldapstring.Segments[1]

    # Parsing the query string according to rfc1959. The syntax is: ? <attributes> ? <scope> ? <filter>
    $parsetstring = $ldapstring.query.split("?")
    $attributes = $parsetstring[1]
    if ($parsetstring[3] -ne "") {
        $filter = [System.Uri]::UnescapeDataString($parsetstring[3]) #.NET url encodes the string automagically, so we need to decode it
    } else {
        $filter = "(objectClass=*)" # rfc1959: If <filter> is omitted, a filter of "(objectClass=*)" is assumed.
    }

    switch ($parsetstring[2]) {
        "sub" { $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree }
        "one" { $scope = [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
        "base" { $scope = [System.DirectoryServices.Protocols.SearchScope]::Base }
        default { $scope = [System.DirectoryServices.Protocols.SearchScope]::Base } # rfc1959: If <scope> is omitted, a scope of "base" is assumed.
    }

    DO {
        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList $basedn,$filter,$scope,$attributes
        $searchResponse = $ldapConnection.SendRequest($searchRequest)

        if ($searchResponse.Entries.Count -ne 0) {
            "Got $($searchResponse.Entries.Count) results from the query:"
        } else {
            "Didn't get any results, check the query"
        }

        $DNarray = @()
        foreach ($i in $searchResponse.Entries)
        {
            $certarray = $i.Attributes.'usercertificate;binary'
            if ($certarray) {
                $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert.Import($certarray[0])
                $DNarray += $($i.DistinguishedName).split(",")[0]

                if ($OnlyValid) {
                    if (!(($cert.NotBefore -le (get-date)) -and ($cert.NotAfter -ge (get-date)))) {
                        continue
                    }
                }

                Show-CertificateInfo $i.DistinguishedName $cert

                if ($Status) {
                    Show-CertificateStatus($cert)
                }
                if ($PrintPEM) {
                    Show-PEM($cert)
                }
                if ($open) {
                    Open-Certificate($cert)
                }
            } else {
                Write-Warning "This result didn't contain any certificates. Was usercertificate;binary in the attribute list?"
            }
        }
        if ($searchResponse.Entries.Count -eq 20) {
            $retries += 1
            if ($retries -le $MaxRetries) {
                Write-Warning "Got exactly 20 certificates from server, this may indicate an limit on the server. Will try to exclude these results and do another search"
                Sleep(2)

                foreach ($DN in $DNarray) {
                    $excludedresults += "(!($DN))"
                }
                $filter = "(&$filter$excludedresults)"
            } else {
                Write-Warning ("Got exactly 20 certificates from server, this may indicate an limit on the server. But will not try again, as the retry count is exceeded. " +
                               "Try again with higher retry count or a more narrow filter.")
            }
        } else {
            $retries = $MaxRetries + 1
        }
    } While ($retries -le $MaxRetries)

    $ldapConnection.Dispose()
}


Function Submit-CertToCT {
    <#
    .Synopsis
       Submits a certificate to Certificate Transparency logs.
    .DESCRIPTION
       Takes a certificate from a web site, or file, and submits it to a CT log. If no logs are specified, it will be submittet to the following logs:

       Google 'Pilot' log (https://ct.googleapis.com/pilot)
       Google 'Rocketeer' log (https://ct.googleapis.com/rocketeer)
       Comodo Dodo (https://dodo.ct.comodo.com)

    .EXAMPLE
       Submit-CertToCT -url https://example.com
       Get the certificate from example.com and submit it to the default logs
    .EXAMPLE
       Submit-CertToCT -url https://example.com-logg https://ct.googleapis.com/pilot
       Get the certificate from example.com and submit it to Googles PILOT log
    .EXAMPLE
       Submit-CertToCT -cert ./cert.cer
       Submit the specified certificate to the default logs
    .EXAMPLE
       Submit-CertToCT -cert ./cert.cer -logg https://ct.googleapis.com/pilot
       Submit the specified certificate to the Google PILOT log
    .INPUTS
       A certificate, or a URL presenting a certificate, and optionally a URL to an CT log
    .OUTPUTS
       The response from the logs
    .NOTES
       See RFC 6962 for more information about Certificate Transparency.
    #>
    [cmdletbinding()]
    Param([Parameter(ParameterSetName='fromHost')][System.Uri]$host,
          [Parameter(ParameterSetName='fromCERT')][System.String]$cert,
          [Parameter(mandatory=$false)][System.String]$log)

    $ErrorActionPreference = "Stop"

    # Default logs
    $logs = @{
	    'pilot' =     [System.Uri]"https://ct.googleapis.com/pilot";
	    'rocketeer' = [System.Uri]"https://ct.googleapis.com/rocketeer";
	    'comodo-dodo' = [System.Uri]"https://dodo.ct.comodo.com"
    }

    $oldtlsprotocols = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = 'tls12' # if the log don't support TLSv1.2 it's not worth submitting to

    if ($log) {
        $logs = @{'user-specified' = [System.Uri]$log }
    }

    if ($cert) {
        $certificate = Get-CertificateFromFile($cert)
    } else {
        $certificate = Get-CertificateFromHost($host)
    }

    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain

    # Deactivating revocation check on the certificate chain, so that we can submit revoked certificates
    # Not something that should be copied without understanding what it does
    $chain.ChainPolicy.RevocationMode = 'NoCheck'

    if(!($chain.Build($certificate))) {
        throw $chain.ChainStatus.StatusInformation
    }

    $certchain= @()
    $numberinchain = 1
    $chain.ChainElements | ForEach-Object `
    {
        "Certificate number $numberinchain in the chain is issued to: $($_.Certificate.Subject)"
        $certchain += [System.Convert]::ToBase64String($_.Certificate.GetRawCertData())
        $numberinchain += 1
    }

    $logs.GetEnumerator() | ForEach-Object {

        $logurl = $_.Value

        $thebegnning = Get-Date 1/1/1970

        $addurl = "$($logurl)/ct/v1/add-chain" -replace "(?<!:)\/\/", "/" # ugly hack to avoid double slashes

        try {
            $loganswer = Invoke-RestMethod -Method POST -Uri $addurl -Body (ConvertTo-Json -InputObject @{'chain'=$certchain}) -ContentType "application/json"
        } catch {
            Write-Warning "Could not submit the cert to the log $($logurl): $($_)"
            return 
        }

        "`r`n#####################$($logurl)#####################"
        "[SCT version]"
        " $($loganswer.sct_version)`r`n"
        "[Log ID]"
        " $(Show-HEX($loganswer.id))`r`n"
        "[Timestamp]"
        " $(Get-Date $thebegnning.AddMilliseconds($loganswer.timestamp) -format s)`r`n"
        "[Extensions]"
        " $($loganswer.extensions)`r`n"
        "[Signature]"
        " $($loganswer.signature)`r`n"
    }

    [Net.ServicePointManager]::SecurityProtocol = $oldtlsprotocols
}

Function Get-CertFromCT {
    <#
    .Synopsis
       Gets certificates from the CT logs, via the Cert Spotter API
    .DESCRIPTION
       Gets the certificates for the specified domain from the CT logs, via the Cert Spotter API (https://sslmate.com/certspotter)
    .EXAMPLE
       Get-CertFromCT watn.no
       The information about the certificates for the domain watn.no is printed
    .EXAMPLE
       Get-CertFromCT watn.no -open
       The information about the certificates for the domain watn.no is printed, and the certificates is opened in the Windows certificate dialog
    .EXAMPLE
       Get-CertFromCT watn.no -PrintPEM
       The information about the certificates for the domain watn.no is printed, and the certificates is printed in PEM format  
    .INPUTS
       A domain to query
    .OUTPUTS
       Information about the certificates
    .NOTES
       See RFC 6962 for more information about Certificate Transparency.
    #>
    [cmdletbinding()]
    Param([Parameter(mandatory=$true)][System.Uri]$domain,
          [Parameter(mandatory=$false)][Switch]$Open,
          [Parameter(mandatory=$false)][Switch]$PrintPEM,
          [Parameter(mandatory=$false)][Switch]$Status,
          [Parameter(mandatory=$false)][Switch]$OnlyValid,
          [Parameter(mandatory=$false)][Switch]$IncludeDuplicate)
    
    $ErrorActionPreference = "Stop"
    
    # TODO: add the possibility to use a Cert Spotter account

    $response = Invoke-RestMethod -Uri "https://certspotter.com/api/v0/certs?domain=$($domain)&duplicate=$($IncludeDuplicate)"

    foreach ($i in $response) {
        $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
        $bincert = [System.Convert]::FromBase64String($i.data)
        $cert.Import($bincert)

        Show-CertificateInfo $i.sha256 $cert

        if ($Status) {
            Show-CertificateStatus($cert)
        }
        if ($PrintPEM) {
            Show-PEM($cert)
        }
        if ($open) {
            Open-Certificate($cert)
        }
    }
}


Function Get-CertFromHost {
    <#
    .Synopsis
       Shows information about a certificate from an HTTPS site
    .DESCRIPTION
        Shows information about a certificate from an HTTPS site
    .EXAMPLE
       Get-CertFromURL example.com
       Shows information about the certificate from example.com
    .EXAMPLE
       Get-CertFromURL example.com:4443
       Shows information about the certificate from example.com on port 4443
    .INPUTS
       A certificate, or a URL presenting a certificate.
    .OUTPUTS
       Information about the certificate
    #>
    [cmdletbinding()]
    Param([Parameter(mandatory=$true)][String]$host,
          [Parameter(mandatory=$false)][Switch]$Open,
          [Parameter(mandatory=$false)][Switch]$PrintPEM,
          [Parameter(mandatory=$false)][Switch]$Status)

    $ErrorActionPreference = "Stop"

    $cert = Get-CertificateFromHost($host)

    Show-CertificateInfo $host $cert

    if ($Status) {
        Show-CertificateStatus($cert)
    }
    if ($PrintPEM) {
        Show-PEM($cert)
    }
    if ($open) {
        Open-Certificate($cert)
    }
}

Function Get-CertFromFile {
    <#
    .Synopsis
       Displays information about a certificate from a file
    .DESCRIPTION
       Displays information about a certificate from a file
    .EXAMPLE
       Get-CertFromURL ./cert.cer
       Displays information about the certificate from cert.cer
    .EXAMPLE
       Get-CertFromURL ./cert.cer -PrintPEM
       Displays information about the certificate from cert.cer and prints it out in PEM format
    .INPUTS
       A certificate
    .OUTPUTS
       Information about the certificate
    #>
    [cmdletbinding()]
    Param([Parameter(mandatory=$true)][String]$file,
          [Parameter(mandatory=$false)][Switch]$Open,
          [Parameter(mandatory=$false)][Switch]$PrintPEM,
          [Parameter(mandatory=$false)][Switch]$Status)

    $ErrorActionPreference = "Stop"

    $cert = Get-CertificateFromFile($file)

    Show-CertificateInfo (Resolve-Path -Path $file).path $cert

    if ($Status) {
        Show-CertificateStatus($cert)
    }
    if ($PrintPEM) {
        Show-PEM($cert)
    }
    if ($open) {
        Open-Certificate($cert)
    }
}

Function Get-CertFromBase64 {
    <#
    .Synopsis
       Displays information about a certificate from a base64 encoded string
    .DESCRIPTION
       Displays information about a certificate from a base64 encoded string
    .EXAMPLE
       Get-CertFromBase64 VGhpcyBpcyBzdXBwb3NlZCB0byBiZSBhIGNlcnRpZmljYXRl...
       Displays information about the base64 encoded certificate
    .EXAMPLE
       Get-CertFromBase64 VGhpcyBpcyBzdXBwb3NlZCB0byBiZSBhIGNlcnRpZmljYXRl... -PrintPEM
       Displays information about the base64 encoded certificate and prints it out in PEM format
    .INPUTS
       A certificate encoded as base64
    .OUTPUTS
       Information about the certificate
    #>
    [cmdletbinding()]
    Param([Parameter(mandatory=$true)][String]$string,
          [Parameter(mandatory=$false)][Switch]$Open,
          [Parameter(mandatory=$false)][Switch]$PrintPEM,
          [Parameter(mandatory=$false)][Switch]$Status)

    $ErrorActionPreference = "Stop"

    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2

    try {
        $cert.Import([System.Convert]::FromBase64String($string))
    } catch {
        throw "Could not load certificate: $($_)"
    }

    Show-CertificateInfo "cert" $cert

    if ($Status) {
        Show-CertificateStatus($cert)
    }
    if ($PrintPEM) {
        Show-PEM($cert)
    }
    if ($open) {
        Open-Certificate($cert)
    }
}

#endregion

Export-ModuleMember -Function Get-CertFromLDAP, Submit-CertToCT, Get-CertFromCT, Get-CertFromHost, Get-CertFromFile, Get-CertFromBase64