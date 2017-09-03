Cert-Tools
=====
Some handy cmdlets for working with certificates and Certificate Transparency.

## cmdlets

The module consists of the following cmdlets:

**Get-CertFromHost**

Gets a certificate from a tls enabled host, and displays information about it.

**Get-CertFromCT**

Gets certificate(s) for a domain from the Certificate Transparency logs. Uses the Cert Spotter API.

**Get-CertFromLDAP**

Gets certificates from an LDAP URL. Primarily useful for Norwegian qualified certificates.

**Get-CertFromFile**

Displays information about a certificate loaded from a file

**Get-CertFromBase64**

Displays information about a base64 encoded certificate (e.g. taken from a SOAP message or similar)

**Get-CertFromPKCS12**

Displays information about certificates in a PKCS12 keystore

**Submit-CertToCT**

Submits a certificate to Certificate Transparency logs and outputs a SCT list with the responses.
