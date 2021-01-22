# X509 Sign

A simple endpoint to sign X509 certificates.

# Usage

### Via HTTP:

Expose `index.php` on a webserver.

Get the signature server public key:
```
POST /
{
  "publicKey": {}
}
```

Or specify a format:
```
POST /
{
  "publicKey": {"format": "PSS"}
}
```

Request a signature:
```
POST /
{
  "signedCertificate": {
    "certificate": "-----BEGIN...",
    "clientPublicKey": "-----BEGIN..."
  }
}
```

### As a service

Use `Issuer::issue()` to sign certificates from a PHP application.

## Config

Define environment variables to configure your server:

- `SIGNATURE_PRIVATE_KEY` PKCS1 string of the private signature key.

- `SIGNATURE_PRIVATE_KEY_PASSPHRASE` Passphrase/password of the private key.

- `EXTENSIONS` JSON representation of X509 extensions to support.
