# nifi-cms-bundle
Apache NiFi Processors and Controller Services for Cryptographic Message Syntax

## Summary

The NiFi CMS bundle of Processors and Controller Services supports content encryption and decryption using
[Cryptographic Message Syntax](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax) and
[X.509](https://en.wikipedia.org/wiki/X.509) certificates as defined in [RFC 5652](https://tools.ietf.org/html/rfc5652).

## Processors

The bundle includes several NiFi Processors for encrypting and decrypting binary messages using CMS. The processors
leverage the [Bouncy Castle](https://bouncycastle.org) library to support multiple algorithms including the
[Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).

### DecryptCMS

The DecryptCMS Processor reads encrypted CMS enveloped messages and uses the configured Private Key Service to
find recipients based on matching certificate serial number and issuer.

### EncryptCMS

The EncryptCMS Processor selects one or more X.509 certificates from the configured Certificate Service as message
recipients and writes encrypted bytes using the configured algorithm.

## Controller Services

The bundle includes several NiFi Controller Service implementations to support finding certificates and private keys.

### KeyStorePrivateKeyService

The KeyStorePrivateKeyService implements the PrivateKeyService interface using a JKS or PKCS12 key store
located on the file system. The service iterates through key store entries to find a certificate with a matching
serial number and issuer then returns the corresponding private key.

### TrustStoreCertificateService

The TrustStoreCertificateService implements the CertificateService interface using a JKS or PKCS12 trust store
located on the file system. The service iterates through key store certificate entries to find a matching certificate
subject principal based on the search pattern provided.