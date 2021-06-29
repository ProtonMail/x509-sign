# X509 Sign

A simple endpoint to sign X509 certificates.

# Usage

### Via HTTP:

Expose `index.php` on a webserver.

Get the signature server public key:
```
POST /
```
```json
{
  "publicKey": {}
}
```

Or specify a format:
```
POST /
```
```json
{
  "publicKey": {"format": "PSS"}
}
```

Request a signature:
```
POST /
```
```json
{
  "signedCertificate": {
    "certificate": "-----BEGIN...",
    "clientPublicKey": "-----BEGIN..."
  }
}
```

You can group requests and get both results aggregated:

```
POST /
```
```json
{
  "publicKey": {},
  "signedCertificate": {
    "certificate": "-----BEGIN...",
    "clientPublicKey": "-----BEGIN..."
  }
}
```

Would result the following JSON output:

```json
{
  "publicKey": {
    "success": true,
    "result": "-----BEGIN..."
  }
  "signedCertificate": {
    "success": true,
    "result": "-----BEGIN..."
  }
}
```

With the server signature public key string and the signed certificate.

### As a service

Use `Issuer::issue()` to sign certificates from a PHP application.

```php
use Proton\X509Sign\Issuer;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;

$issuer = new Issuer();
$issuer->issue(
    PrivateKey::load('-----BEGIN...'),
    PublicKey::load('-----BEGIN...'),
    ['commonName' => 'foo'],
    ['commonName' => 'bar'],
    '9256',
);
```

## Config

Define environment variables to configure your server:

- `SIGNATURE_PRIVATE_KEY` PKCS1 string of the private signature key.

- `SIGNATURE_PRIVATE_KEY_PASSPHRASE` Passphrase/password of the private key.

- `EXTENSIONS` JSON representation of X509 extensions to support.
