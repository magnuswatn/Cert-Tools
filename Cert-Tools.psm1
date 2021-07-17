<#
    Some certificate tools for Powershell

    https://github.com/magnuswatn/cert-tools
#>
using namespace System.Security.Cryptography.X509Certificates
#region scriptvariables

$script:signatureAlgorihtms = @{
    "BAM=" = "ecdsa-with-SHA256" #0x0403
    "BAE=" = "sha256WithRSAEncryption" #0x0401
}

# Created by running:
# $knownLogs = Invoke-RestMethod https://www.gstatic.com/ct/log_list/log_list.json
# $hash = [System.Security.Cryptography.SHA256Managed]::new()
# $knownLogs.logs | foreach { "`"$([system.convert]::ToBase64String($hash.ComputeHash([System.Convert]::FromBase64String($_.key))))`" = `"$($_.description)`"" }
# Last updated 2021-07-17
$script:knownLogs = @{
    "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=" = "Google 'Argon2021' log"
    "KXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4Q=" = "Google 'Argon2022' log"
    "6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=" = "Google 'Argon2023' log"
    "fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8Nc=" = "Google 'Xenon2021' log"
    "RqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUc=" = "Google 'Xenon2022' log"
    "rfe++nz/EMiLnT2cHj4YarRnKV3PsQwkyoWGNOvcgoo=" = "Google 'Xenon2023' log"
    "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=" = "Google 'Aviator' log"
    "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=" = "Google 'Icarus' log"
    "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=" = "Google 'Pilot' log"
    "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=" = "Google 'Rocketeer' log"
    "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=" = "Google 'Skydiver' log"
    "RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=" = "Cloudflare 'Nimbus2021' Log"
    "QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvY=" = "Cloudflare 'Nimbus2022' Log"
    "ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=" = "Cloudflare 'Nimbus2023' Log"
    "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=" = "DigiCert Log Server"
    "h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=" = "DigiCert Log Server 2"
    "XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=" = "DigiCert Yeti2021 Log"
    "IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=" = "DigiCert Yeti2022 Log"
    "Nc8ZG7+xbFe/D61MbULLu7YnICZR6j/hKu+oA8M71kw=" = "DigiCert Yeti2023 Log"
    "7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfk=" = "DigiCert Nessie2021 Log"
    "UaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeU=" = "DigiCert Nessie2022 Log"
    "s3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZo=" = "DigiCert Nessie2023 Log"
    "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=" = "Symantec log"
    "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=" = "Symantec 'Vega' log"
    "FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=" = "Symantec 'Sirius' log"
    "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=" = "Certly.IO log"
    "dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM=" = "Izenpe log"
    "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=" = "WoSign log"
    "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=" = "Venafi log"
    "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=" = "CNNIC CT log"
    "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=" = "StartCom log"
    "VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=" = "Sectigo 'Sabre' CT log"
    "b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=" = "Sectigo 'Mammoth' CT log"
    "lCC8Ho7VjWyIcx+CiyIsDdHaTV5sT5Q9YdtOL1hNosI=" = "Let's Encrypt 'Oak2021' log"
    "36Veq2iCTx9sre64X04+WurNohKkal6OOxLAIERcKnM=" = "Let's Encrypt 'Oak2022' log"
    "tz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJk=" = "Let's Encrypt 'Oak2023' log"
    "qNxS9j1rJCXlMeN89ORKcU8UKiCAOw0E0uLuBmR5SiM=" = "Trust Asia CT2021"
    "Z422Wz50Q7bzo3DV4TqxtDvgoNNR98p0IlDHxvpRqIo=" = "Trust Asia Log2021"
    "w2X5s2VPMoPHnamOk9dBj1ure+MlLJjh0vBLuetCfSM=" = "Trust Asia Log2022"
    "6H6nZgvCbPYALvVyXT/g4zG5OTu5L79Y6zuQSdr1Q1o=" = "Trust Asia Log2023"
    # old logs
    "AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=" = "Venafi Gen2 CT log"
}

# Base64 encoded versions of ASN1 encoded OIDs
$script:knownOIDs = @{
    # 2.23.140.1.1
    "Z4EMAQE="         = "Extended validation TLS certificate"
    # 2.23.140.1.2.1
    "Z4EMAQIB"         = "Domain validated TLS certificate"
    # 2.23.140.1.2.2
    "Z4EMAQIC"         = "Organization validated TLS certificate"
    # 2.16.578.1.26.1.3.2
    "YIRCARoBAwI="     = "Buypass Enterprise certificate"
    # 2.16.578.1.26.1.3.1
    "YIRCARoBAwE="     = "Buypass Person-High certificate"
    # 2.16.578.1.26.1.0.3.2
    "YIRCARoBAAMC"     = "Buypass TEST4 Enterprise certificate"
    # 2.16.578.1.26.1.0
    "YIRCARoBAA=="     = "Buypass TEST4 Person-High certificate"
    # 2.16.578.1.29.12.1.1.0
    "YIRCAR0MAQEA"     = "Commfides Person-High certificate"
    # 2.16.578.1.29.12.1.1.1
    "YIRCAR0MAQEB"     = "Commfides Person-High certificate"
    # 2.16.578.1.29.13.1.1.0
    "YIRCAR0NAQEA"     = "Commfides Enterprise certificate"
    # 2.16.578.1.29.912.1.1.0
    "YIRCAR2HEAEBAA==" = "Commfides TEST Person-High certificate"
    # 2.16.578.1.29.912.1.1.1
    "YIRCAR2HEAEBAQ==" = "Commfides TEST Person-High certificate"
    # 2.16.578.1.29.913.1.1.0
    "YIRCAR2HEQEBAA==" = "Commfides TEST Enterprise certificate"
}

#endregion

#region helperfunctions

function ConvertBigEndianArray ($data, $offset, $count) {
    <# Returns a subset of an BigEndian array as the correct endian for the system #>
    $subArray = $data[$offset..($offset + $count - 1)]
    if ([System.BitConverter]::IsLittleEndian) {
        [System.Array]::Reverse($subArray)
    }
    return $subArray
}

function CreateBigEndianArray($data) {
    <# Creates an BigEndian array from an array with the system endian #>
    if ([System.BitConverter]::IsLittleEndian) {
        [System.Array]::Reverse($data)
    }
    return $data
}

function ParseSCTExtension ($data) {
    <# Parses an x509 extension with CT Precertificate SCTs #>
    $offset = 0

    if ($data[$offset] -ne 4) {
        throw "Expected OCTET STRING (04), got $($data[0])"
    }
    $offset += 1

    $outerLength, $offset, $numberOfLengthBytes = DecodeASN1Length $data $offset

    $innerLength = [System.BitConverter]::ToUInt16((ConvertBigEndianArray $data $offset 2), 0)
    $offset += 2

    # some sanity checks
    if ($outerLength -ne ($data.length - $numberOfLengthBytes - 2)) {
        throw ("Extension length ($(($data.length))) does not match the ASN1 structure length ($($outerLength)). " +
            "This was unexpected.")
    }
    if ($outerLength -ne ($innerLength + 2)) {
        throw ("Length of ASN1 structure ($($outerLength)) does not match the length of the SCTs " +
            "contained within ($($innerLength)). This was unexpected.")
    }

    $scts = @()
    DO {
        $length = [System.BitConverter]::ToUInt16((ConvertBigEndianArray $data $offset 2), 0)
        $offset += 2

        $sct = $data[$offset..($offset + $length - 1)]
        $scts += ParseSCT $sct
        $offset += $length

    } While ($offset -le $innerLength)

    return $scts
}


function ParseSCT ($data) {
    <# Parses a Signed Certificate Timestamp #>
    $sct = New-Object System.Object
    $offset = 0

    $version = $data[$offset]
    if ($version -ne 0) {
        $sct | Add-Member -type NoteProperty -Name Error -Value "Unsupported SCT version"
        return $sct
    }
    $offset += 1

    $logID = $data[$offset..($offset + 31)]
    $sct | Add-Member -type NoteProperty -Name LogID -Value $([System.Convert]::ToBase64String($logID))
    $offset += 32

    $timestamp = [System.BitConverter]::ToUInt64((ConvertBigEndianArray $data $offset 8), 0)
    $sct | Add-Member -type NoteProperty -Name timestamp -Value $timestamp
    $offset += 8

    $extLength = [System.BitConverter]::ToUInt16((ConvertBigEndianArray $data $offset 2), 0)
    $offset += 2

    if ($extLength -gt 0) {
        # Whoa, This SCT has extensions! This must be the future.
        $extensions = $data[$offset..($offset + $extLength - 1)]
        $sct | Add-Member -type NoteProperty -Name Extensions -Value $extensions
    }
    $offset += $extLength

    $sigAlgID = $data[$offset..($offset + 1)]
    $signatureAlgorithm = $signatureAlgorihtms.get_item([System.Convert]::ToBase64String($sigAlgID))
    $sct | Add-Member -type NoteProperty -Name SignatureAlgorithm -Value $signatureAlgorithm
    $offset += 2

    $signatureLength = [System.BitConverter]::ToUInt16((ConvertBigEndianArray $data $offset 2), 0)
    $offset += 2

    $signature = $data[$offset..($offset + $signatureLength - 1)]
    $sct | Add-Member -type NoteProperty -Name signature -Value $signature

    return $sct
}

function CreateSCT ($response) {
    <# Creates an SCT out of the response from a log submission #>

    [byte[]]$response.sct_version

    $sct += [System.Convert]::FromBase64String($response.id)
    $sct += CreateBigEndianArray([System.BitConverter]::GetBytes([uint64]$response.timestamp))

    $decodedExtensions = [System.Convert]::FromBase64String($response.extensions)
    $sct += CreateBigEndianArray([System.BitConverter]::GetBytes([uint16]$decodedExtensions.length))
    $sct += $decodedExtensions

    $sct += [System.Convert]::FromBase64String($response.signature)

    return $sct
}

function CreateSCTList ($scts) {
    <# Creates an SCT list out of serveral SCTs #>

    [byte[]]$sctList
    $scts | ForEach-Object {
        $sctList += CreateBigEndianArray([System.BitConverter]::GetBytes([uint16]$_.Length))
        $sctList += $_
    }
    $length = CreateBigEndianArray([System.BitConverter]::GetBytes([uint16]$sctList.length))

    return [System.Convert]::ToBase64String($length + $sctList)
}

Function DecodeASN1Length ($data, $offset) {
    <# Decodes the ASN1 length encoding of $data, starting at $offset #>

    if ($data[$offset] -lt 128) {
        # short form length
        $numberOfLengthBytes = 0
        $length = $data[$offset]
        $offset += 1
    }
    else {
        # long form
        $numberOfLengthBytes = $data[$offset] - 128
        $offset += 1

        # since the length can be arbitrary number of bytes (also uneven)
        # we copy it into a 8 byte array, and convert it to an int64
        $lengthArray = New-Object -TypeName byte[] -ArgumentList 8

        [array]::Copy(
            $data[$offset..($offset + $numberOfLengthBytes - 1)],
            0,
            $lengthArray,
            ($lengthArray.Length - $numberOfLengthBytes),
            $numberOfLengthBytes
        )
        $length = [System.BitConverter]::ToUInt64((ConvertBigEndianArray $lengthArray 0 $lengthArray.length), 0)
        $offset += $numberOfLengthBytes
    }

    return $length, $offset, $numberOfLengthBytes
}

Function ParseCertificatePolicies ($data) {
    <# Parses an x509 extension with Certificate Policies #>
    $offset = 0

    if ($data[$offset] -ne 48) {
        throw "Expected SEQUENCE (48), got $($data[0])"
    }
    $offset += 1

    $length, $offset, $null = DecodeASN1Length $data $offset

    $oids = @()
    DO {
        if ($data[$offset] -ne 48) {
            throw "Expected SEQUENCE (48), got $($data[$offset])"
        }
        $offset += 1

        $oidLength, $offset, $null = DecodeASN1Length $data $offset
        $oidData = $data[$offset..($offset + $oidLength - 1)]
        $offset += $oidLength

        $oid = ParseOID($oidData)
        $oids += $oid
    } While ($offset -le $length)

    return $oids
}

Function ParseOID ($data) {
    <# Parses an OBJECT IDENTIFIER structure and returns a base64 encoded version of the ASN1 encoded OID #>
    $offset = 0

    if ($data[$offset] -ne 6) {
        throw "Expected OBJECT IDENTIFIER (6), got $($data[$offset])"
    }
    $offset += 1

    $length, $offset, $null = DecodeASN1Length $data $offset

    # There might be more data here (e.g. Policy Qualifier Info), but we only care about the OID
    return [System.Convert]::ToBase64String($data[$offset..($offset + $length - 1)])
}

Function RetrieveCertificateFromHost ($hostname) {
    <# Gets a certificate from a host listening on TLS #>

    $url = "https://$($hostname)"

    # Activate all SSL/TLS protocols, so that we can connect to as many sites as possible
    $oldtlsprotocols = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = 'ssl3', "tls", "tls11", "tls12"

    $request = [System.Net.HttpWebRequest]::Create($url)

    $request.AllowAutoRedirect = $false
    $request.UserAgent = "Cert-Tools (https://github.com/magnuswatn/cert-tools)"
    $request.KeepAlive = $false

    try {
        $request.GetResponse().Dispose()
    }
    catch {
        # Ignoring errors silently, might come of non-200 code or trust error. We only care if we got a cert
        $requestError = $_
    }

    # Setting the TLS protocols back to whatever it was
    [Net.ServicePointManager]::SecurityProtocol = $oldtlsprotocols

    if ($null -ne $request.ServicePoint.Certificate) {
        $params = @{
            "ArgumentList" = $request.ServicePoint.Certificate
            "TypeName"     = "X509Certificate2"
        }
        return New-Object @params
    }
    else {
        # We didn't get a certificate :-( throwing the error from the request
        throw $requestError
    }
}

Function PrintPEM ($certificate) {
    <# Prints a certificate in PEM format #>
    $b64cert = [System.Convert]::ToBase64String($certificate.RawData)
    $pemcert = "-----BEGIN CERTIFICATE-----`r`n"
    $i = 0
    foreach ($char in $b64cert.ToCharArray()) {
        if ($i -eq 64) {
            $pemcert += "`r`n$char"
            $i = 0
        }
        else {
            $pemcert += $char
        }
        $i += 1
    }
    $pemcert += "`r`n-----END CERTIFICATE-----"

    "[PEM format]"
    "$pemcert `r`n"
}

Function PrintHEX ($data) {
    <# Print base64 encoded data as HEX #>
    $hexdump = ""
    $rawdata = [System.Convert]::FromBase64String($data)
    foreach ($byte in $rawdata) {
        $hexdump += "{0:X2}:" -f $byte
    }
    return $hexdump.Substring(0, $hexdump.Length - 1)
}

Function RetrieveCertificateFromFile ($path) {
    <# Loads a certificate from file #>
    $pathtocert = (Resolve-Path -Path $path).path
    $cert = [X509Certificate2]::new($pathtocert)
    return $cert
}

Function OpenCertificate ($cert) {
    <# Opens a certificate in the Windows Certificate dialog #>
    $tempfil = ([System.IO.Path]::GetTempFileName() + ".cer")
    [io.file]::WriteAllBytes($tempfil, $cert.Export("cert"))
    & $tempfil
}

Function PrintCertificateInfo ($id, $cert) {
    <# Prints information about a certificate #>
    $serialnumberINT = $([bigint]::Parse($cert.GetSerialNumberString(),
            [System.Globalization.NumberStyles]::HexNumber))
    "#####################$($id)#####################"
    "$cert"
    "[Key Usages]"
    "  $($cert.Extensions.KeyUsages) `r`n"
    "[Serial Number in INT]"
    "  $serialnumberINT `r`n"
    "[DNS names]"
    $cert.DnsNameList.UniCode | ForEach-Object { "  $_" }
    "`r`n[Is trusted]"
    "  $($cert.verify()) `r`n"
    $cert.Extensions | ForEach-Object {
        if ($_.Oid.Value -eq "1.3.6.1.4.1.11129.2.4.2") {
            "[CT Precertificate SCTs]"
            ParseSCTExtension($_.RawData) | ForEach-Object {
                if (!($_.Error)) {
                    $logName = ($knownLogs.get_item($_.LogID))
                    if ($logName) {
                        "  $($logName)"
                    }
                    else {
                        "  Unknown log"
                    }
                }
                else {
                    "  $($_.Error)"
                }
            }
            "" # extra newline because pretty
        }
        if ($_.Oid.Value -eq "2.5.29.32") {
            ParseCertificatePolicies($_.RawData) | ForEach-Object {
                $certType = $knownOIDs.get_item($_)
                if ($certType) {
                    "[Type]"
                    "  $($certType)`r`n"
                }
            }
        }
    }
}

Function PrintCertificateStatus ($cert) {
    <# Prints information about the trust status of a certificate #>
    $chain = New-Object -TypeName X509Chain

    "[Certificate status]"
    if ($chain.Build($cert)) {
        "  OK`r`n"
    }
    else {
        "  $($chain.ChainStatus.StatusInformation)`r`n"
    }
}

#endregion


#region cmdlets

Function Get-CertFromLDAP {
    <#
    .Synopsis
       Downloads certificates from an ldap url
    .DESCRIPTION
       Downloads certificates from an ldap url and displays relevant information,
       and optionally opens the certificate in the Windows certificate dialog or
       prints them in PEM format.

       Buypass has a limit of 20 certificates, so if the query returns 20 certificates
       a new search will be done with the current results excluded.
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
    Param (
        [Parameter(mandatory = $true)][System.Uri]$ldapstring,
        [Parameter(mandatory = $false)][Switch]$Open,
        [Parameter(mandatory = $false)][Switch]$PrintPEM,
        [Parameter(mandatory = $false)][Switch]$Status,
        [Parameter(mandatory = $false)][Switch]$OnlyValid,
        [Parameter(mandatory = $false)][Int]$MaxRetries = 5
    )

    $ErrorActionPreference = "Stop"
    Add-Type -AssemblyName System.DirectoryServices.Protocols

    if ($ldapstring.scheme -eq "ldap") {
        $secure = $false
    }
    elseif ($ldapstring.Scheme -eq "ldaps") {
        $secure = $true
    }
    else {
        throw "Unknown protocol. LDAP(S) only."
    }

    $ldapConnectionParams = @{
        "ArgumentList" = "$($ldapstring.Host):$($ldapstring.Port)"
        "TypeName"     = "System.DirectoryServices.Protocols.LdapConnection"
    }

    $ldapConnection = New-Object @ldapConnectionParams
    $ldapConnection.SessionOptions.SecureSocketLayer = $secure
    $ldapConnection.SessionOptions.ProtocolVersion = 3
    $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous

    $basedn = $ldapstring.Segments[1]

    # Parsing the query string according to rfc1959. The syntax is: ? <attributes> ? <scope> ? <filter>
    $parsetstring = $ldapstring.query.split("?")
    $attributes = $parsetstring[1]
    if ($parsetstring[3] -ne "") {
        #.NET url encodes the string automagically, so we need to decode it
        $filter = [System.Uri]::UnescapeDataString($parsetstring[3])
    }
    else {
        # rfc1959: If <filter> is omitted, a filter of "(objectClass=*)" is assumed.
        $filter = "(objectClass=*)"
    }

    switch ($parsetstring[2]) {
        "sub" { $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree }
        "one" { $scope = [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
        "base" { $scope = [System.DirectoryServices.Protocols.SearchScope]::Base }
        # rfc1959: If <scope> is omitted, a scope of "base" is assumed.
        default { $scope = [System.DirectoryServices.Protocols.SearchScope]::Base }
    }

    DO {
        $searchRequestParams = @{
            "ArgumentList" = $basedn, $filter, $scope, $attributes
            "TypeName"     = "System.DirectoryServices.Protocols.SearchRequest"
        }
        $searchRequest = New-Object @searchRequestParams
        $searchResponse = $ldapConnection.SendRequest($searchRequest)

        if ($searchResponse.Entries.Count -ne 0) {
            "Got $($searchResponse.Entries.Count) results from the query:"
        }
        else {
            "Didn't get any results, check the query"
        }

        $DNarray = @()
        foreach ($i in $searchResponse.Entries) {
            $certarray = $i.Attributes.'usercertificate;binary'
            if ($certarray) {
                $cert = [X509Certificate2]::new($certarray[0])
                $DNarray += $($i.DistinguishedName).split(",")[0]

                if ($OnlyValid) {
                    if (!(($cert.NotBefore -le (get-date)) -and ($cert.NotAfter -ge (get-date)))) {
                        continue
                    }
                }

                PrintCertificateInfo $i.DistinguishedName $cert

                if ($Status) {
                    PrintCertificateStatus($cert)
                }
                if ($PrintPEM) {
                    PrintPEM($cert)
                }
                if ($open) {
                    OpenCertificate($cert)
                }
            }
            else {
                Write-Warning ("This result didn't contain any certificates. " +
                    "Was usercertificate;binary in the attribute list?")
            }
        }
        if ($searchResponse.Entries.Count -eq 20) {
            $retries += 1
            if ($retries -le $MaxRetries) {
                Write-Warning ("Got exactly 20 certificates from server, this may indicate an limit on the " +
                    "server. Will try to exclude these results and do another search")
                Start-Sleep(2)

                foreach ($DN in $DNarray) {
                    $excludedresults += "(!($DN))"
                }
                $filter = "(&$filter$excludedresults)"
            }
            else {
                Write-Warning ("Got exactly 20 certificates from server, this may indicate an limit on the " +
                    "server, but will not try again, as the retry count is exceeded. " +
                    "Try again with higher retry count or a more narrow filter.")
            }
        }
        else {
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
       Takes a certificate from a TLS enabled host, or file, and submits it to CT logs. If no logs are specified,
       it will be submitted to the following logs:

       Google 'Pilot' log (https://ct.googleapis.com/pilot)
       Google 'Rocketeer' log (https://ct.googleapis.com/rocketeer)
       Venafi Gen2 CT log (https://ctlog-gen2.api.venafi.com)
       DigiCert Log Server 2 (https://ctlog-gen2.api.venafi.com)
       Comodo Mammoth (https://mammoth.ct.comodo.com)
       Comodo Sabre (https://sabre.ct.comodo.com)

       A SCT list with the responses from the logs are also genereated.
       This can be usedful for configuring TLS servers that support the CT TLS extension.
    .EXAMPLE
       Submit-CertToCT example.com
       Get the certificate from port 443 on example.com and submit it to the default logs
    .EXAMPLE
       Submit-CertToCT example.com:8443 -log https://ct.googleapis.com/pilot
       Get the certificate from port 8443 on example.com and submit it to Google 'Pilot' log
    .EXAMPLE
       Submit-CertToCT ./cert.cer
       Submit the certificate from the specified file to the default logs
    .EXAMPLE
       Submit-CertToCT ./cert.cer -count 2
       Submit the specified certificate to two of the default logs.
       This will always be at least one Google log and one non-Google log, to match the Chrome CT requirement
    .INPUTS
       A certificate, or a TLS enabled host, and optionally URLs to one or more to CT log(s)
    .OUTPUTS
       The response from the logs and a base64 encoded sct list with all the responses
    .NOTES
       See RFC 6962 for more information about Certificate Transparency.
    #>
    [cmdletbinding()]
    Param (
        # The source to retrieve the certificate from. Can either be a file or a hostname (and optionally a port)
        [Parameter(mandatory = $true)][System.String]$source,
        # The log to submit to. Can be a comma separated list over several logs.
        # If not supplied the default logs will be used
        [Parameter(mandatory = $false)][System.String]$log,
        # The number of logs to submit to. Is only supported with the built in list of logs.
        # Is primarily useful for limiting the size of the SCT list.
        [Parameter(mandatory = $false)][int]$count
    )

    $ErrorActionPreference = "Stop"

    # Default logs
    $logs = @{
        'google-pilot'        = [System.Uri]"https://ct.googleapis.com/pilot";
        'google-rocketeer'    = [System.Uri]"https://ct.googleapis.com/rocketeer";
        'digicert-logserver2' = [System.Uri]"https://ct2.digicert-ct.com/log";
        'venafi-gen2'         = [System.Uri]"https://ctlog-gen2.api.venafi.com";
        'comodo-mammoth'      = [System.Uri]"https://mammoth.ct.comodo.com";
        'comodo-sabre'        = [System.Uri]"https://sabre.ct.comodo.com";
    }

    # If the log doesn't support TLSv1.2 it's not worth submitting to
    $oldtlsprotocols = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = 'tls12'

    if ($log) {
        $logs = @{}
        $log.split(",") | ForEach-Object {
            $logs += @{[System.Guid]::NewGuid() = [System.Uri]$_ }
        }
    }

    try {
        $certificate = RetrieveCertificateFromFile($source)
    }
    catch {
        $certificate = RetrieveCertificateFromHost($source)
    }

    $chain = New-Object -TypeName X509Chain

    # Deactivating revocation check on the certificate chain, so that we can submit revoked certificates
    # Not something that should be copied without understanding what it does
    $chain.ChainPolicy.RevocationMode = 'NoCheck'

    if (!($chain.Build($certificate))) {
        throw $chain.ChainStatus.StatusInformation
    }

    $certChain = @()
    $numberInChain = 1
    $chain.ChainElements | ForEach-Object {
        "Certificate number $($numberInChain) in the chain is issued to: $($_.Certificate.Subject)"
        $certChain += [System.Convert]::ToBase64String($_.Certificate.GetRawCertData())
        $numberInChain += 1
    }

    $scts = [System.Collections.ArrayList]@()
    $theBegnning = Get-Date 1/1/1970
    $nonGoogleLog = $googleLog = $false

    $logs.GetEnumerator() | Sort-Object { Get-Random } | ForEach-Object {
        if ($count) {
            # We must make sure that we submit it to at least one Google log and one non-Google log
            if ($scts.Count -gt 1 -and $scts.Count -eq ($count - 1)) {
                # This is the last submission. It must make the equation valid
                if ((($_.Name -like "google*") -and ($nonGoogleLog -eq $false)) -or
                    (($_.Name -notlike "google*") -and ($googleLog -eq $false))) {
                    return
                }
            }
            if ($scts.Count -ge $count) {
                return
            }
            if ($_.Name -like "google*") {
                $googleLog = $true
            }
            else {
                $nonGoogleLog = $true
            }
        }

        $addurl = "$($_.Value)/ct/v1/add-chain" -replace "(?<!:)\/\/", "/" # ugly hack to avoid double slashes

        $params = @{
            "Uri"         = $addurl
            "Method"      = "POST"
            "ContentType" = "application/json"
            "Body"        = (ConvertTo-Json -InputObject @{'chain' = $certChain })
            "UserAgent"   = "Cert-Tools (https://github.com/magnuswatn/cert-tools)"
        }

        $logurl = $_.Value
        try {
            $logAnswer = Invoke-RestMethod @params
        }
        catch {
            Write-Warning "Could not submit the cert to the log $($logurl): $($_)"
            return
        }

        "`r`n#####################$($_.Value)#####################"
        "[SCT version]"
        " $($logAnswer.sct_version)`r`n"
        "[Log ID]"
        " $(PrintHEX($logAnswer.id))`r`n"
        "[Timestamp]"
        " $(Get-Date $theBegnning.AddMilliseconds($logAnswer.timestamp) -format s)`r`n"
        "[Extensions]"
        " $($logAnswer.extensions)`r`n"
        "[Signature]"
        " $($logAnswer.signature)`r`n"

        $null = $scts.add((CreateSCT $logAnswer))
    }
    "`r`n`r`nSCT list:"
    CreateSCTList $scts

    [Net.ServicePointManager]::SecurityProtocol = $oldtlsprotocols
}

Function Get-CertFromCT {
    <#
    .Synopsis
       Gets certificates from the CT logs, via the Cert Spotter API
    .DESCRIPTION
       Gets the certificates for the specified domain from the CT logs,
       via the Cert Spotter API (https://sslmate.com/certspotter)
    .EXAMPLE
       Get-CertFromCT watn.no
       The information about the certificates for the domain watn.no is printed
    .EXAMPLE
       Get-CertFromCT watn.no -open
       The information about the certificates for the domain watn.no is printed,
       and the certificates is opened in the Windows certificate dialog
    .EXAMPLE
       Get-CertFromCT watn.no -OpenInCrtSh
       The information about the certificates for the domain watn.no is printed,
       and the certificates is showed on crt.sh
    .EXAMPLE
       Get-CertFromCT watn.no -PrintPEM
       The information about the certificates for the domain watn.no is printed,
       and the certificates is printed in PEM format
    .INPUTS
       A domain to query
    .OUTPUTS
       Information about the certificates
    .NOTES
       See RFC 6962 for more information about Certificate Transparency.
    #>
    [cmdletbinding()]
    Param (
        [Parameter(mandatory = $true)][String]$domain,
        [Parameter(mandatory = $false)][Switch]$Open,
        [Parameter(mandatory = $false)][Switch]$PrintPEM,
        [Parameter(mandatory = $false)][Switch]$Status,
        [Parameter(mandatory = $false)][Switch]$OpenInCrtSh
    )

    $ErrorActionPreference = "Stop"

    # TODO: add the possibility to use a Cert Spotter account

    $params = @{
        "UserAgent" = "Cert-Tools (https://github.com/magnuswatn/cert-tools)"
        "Uri"       = "https://api.certspotter.com/v1/issuances?domain=$($domain)&expand=cert"
    }

    $response = Invoke-RestMethod @params

    foreach ($i in $response) {
        $bincert = [System.Convert]::FromBase64String($i.cert.data)
        $cert = [X509Certificate2]::new($bincert)

        PrintCertificateInfo $i.cert.sha256 $cert

        if ($Status) {
            PrintCertificateStatus($cert)
        }
        if ($PrintPEM) {
            PrintPEM($cert)
        }
        if ($open) {
            OpenCertificate($cert)
        }
        if ($OpenInCrtSh) {
            Start-Process "https://crt.sh/?q=$([System.Uri]::EscapeDataString($i.cert.sha256))"
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
    Param (
        [Parameter(mandatory = $true)][String]$host,
        [Parameter(mandatory = $false)][Switch]$Open,
        [Parameter(mandatory = $false)][Switch]$PrintPEM,
        [Parameter(mandatory = $false)][Switch]$Status
    )

    $ErrorActionPreference = "Stop"

    $cert = RetrieveCertificateFromHost($host)

    PrintCertificateInfo $host $cert

    if ($Status) {
        PrintCertificateStatus($cert)
    }
    if ($PrintPEM) {
        PrintPEM($cert)
    }
    if ($open) {
        OpenCertificate($cert)
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
    Param (
        [Parameter(mandatory = $true)][String]$file,
        [Parameter(mandatory = $false)][Switch]$Open,
        [Parameter(mandatory = $false)][Switch]$PrintPEM,
        [Parameter(mandatory = $false)][Switch]$Status
    )

    $ErrorActionPreference = "Stop"

    $cert = RetrieveCertificateFromFile($file)

    PrintCertificateInfo (Resolve-Path -Path $file).path $cert

    if ($Status) {
        PrintCertificateStatus($cert)
    }
    if ($PrintPEM) {
        PrintPEM($cert)
    }
    if ($open) {
        OpenCertificate($cert)
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
    Param (
        [Parameter(mandatory = $true)][String]$string,
        [Parameter(mandatory = $false)][Switch]$Open,
        [Parameter(mandatory = $false)][Switch]$PrintPEM,
        [Parameter(mandatory = $false)][Switch]$Status
    )

    $ErrorActionPreference = "Stop"

    $unPemifiedString = $string -replace "-----(BEGIN|END) [^-]+-----", ""

    try {
        $cert = [X509Certificate2]::new([System.Convert]::FromBase64String($unPemifiedString))
    }
    catch {
        throw "Could not load certificate: $($_)"
    }

    PrintCertificateInfo "cert" $cert

    if ($Status) {
        PrintCertificateStatus($cert)
    }
    if ($PrintPEM) {
        PrintPEM($cert)
    }
    if ($open) {
        OpenCertificate($cert)
    }
}

Function Get-CertFromPKCS12 {
    <#
    .Synopsis
       Shows information about certificates from a pkcs12 keystore.
    .DESCRIPTION
        Lists out all the certificates in a pkcs12 keystore.

        Be aware! It is recommended not to supply the passowrd on the command line,
        but instead enter it when asked.
    .EXAMPLE
       Get-CertFromPKCS12 .\pkcs12file.pfx -password passw0rd
       Displays information about the certificates in the pkcs12file.pfx file
    .EXAMPLE
       Get-CertFromPKCS12 .\pkcs12file.pfx -password passw0rd -Open
       Displays information about the certificates in the pkcs12file.pfx file
       and opens them in the Windows certificate dialog
    .INPUTS
       A pkcs12 keystore (pfx/p12) (and the password)
    .OUTPUTS
       Information about the certificate(s)
    #>
    [cmdletbinding()]
    Param (
        [Parameter(mandatory = $true)][String]$file,
        [Parameter(mandatory = $false)][String]$password,
        [Parameter(mandatory = $false)][Switch]$Open,
        [Parameter(mandatory = $false)][Switch]$PrintPEM,
        [Parameter(mandatory = $false)][Switch]$Status
    )

    $ErrorActionPreference = "Stop"

    if ($password) {
        $securepassword = ($password | ConvertTo-SecureString -AsPlainText -Force)
    }
    else {
        $securepassword = Read-Host -Prompt "Enter password" -AsSecureString
    }

    $certs = Get-PfxData -FilePath $file -Password $securepassword

    $certs.EndEntityCertificates | ForEach-Object {

        PrintCertificateInfo $_.Subject $_

        if ($Status) {
            PrintCertificateStatus($_)
        }
        if ($PrintPEM) {
            PrintPEM($_)
        }
        if ($open) {
            OpenCertificate($_)
        }
    }

    $certs.OtherCertificates | ForEach-Object {
        PrintCertificateInfo $_.Subject $_

        if ($Status) {
            PrintCertificateStatus($_)
        }
        if ($PrintPEM) {
            PrintPEM($_)
        }
        if ($open) {
            OpenCertificate($_)
        }
    }
}

#endregion

Export-ModuleMember -Function Get-CertFromLDAP, Submit-CertToCT, Get-CertFromCT, Get-CertFromHost,
Get-CertFromFile, Get-CertFromBase64, Get-CertFromPKCS12
