# FileSignatureValidator
Python command on top of poppler-utils and openssl used to verify file signatures.

this command will simply verify a signature, not the issuer certificate.
It would also implement the certificate issuer verification, downloading first the CA.crt or its chain of trusts.
Please open Issues if you need this additional feature.
