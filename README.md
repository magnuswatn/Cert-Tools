Cert-Tools
=====
Some handy cmdlets for working with certificates.

## cmdlets

The module consists of the following cmdlets:

**Get-CertFromHost**

Gets a certificate from a tls enabled host, and displays information about it.

**Get-CertFromCT**

Gets certificate(s) for a domain from the Certificate Transparency logs. Uses the Cert Spotter API.

**Get-CertFromLDAP**

Gets certificates from an LDAP URL. Primarily useful for Norwegian qualified certificates.

**Submit-CertToCT**

Submits a certificate to Certificate Transparency logs.
