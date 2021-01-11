<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\X509;

/**
 * Application class represents a separated application using the signature endpoint
 * to get a certificate re-signed.
 */
final class Application
{
    private array $issuerDn = [
        'countryName' => 'US',
        'stateOrProvinceName' => 'NY',
        'localityName' => 'New York',
        'organizationName' => 'Any Organization',
        'organizationalUnitName' => 'Some Department',
        'commonName' => 'Dream Team',
        'emailAddress' => 'dreamteam@any.org',
    ];

    private PrivateKey $applicationKey;

    private ?User $currentUser = null;

    public function __construct()
    {
        /** @var PrivateKey $middlewarePrivateKey */
        $middlewarePrivateKey = PrivateKey::createKey();

        $this->applicationKey = $middlewarePrivateKey;
    }

    public function receiveRequestFromUser(User $user): void
    {
        $this->currentUser = $user;
    }

    public function generateCertificate(string $signServerPublicKeyString): string
    {
        /** @var PublicKey $signServerPublicKey */
        $signServerPublicKey = PublicKey::load($signServerPublicKeyString);

        $subject = new X509();
        $subject->setPublicKey($signServerPublicKey);
        $subject->setDN($this->currentUser->getSubjectDn());

        $issuer = new X509();
        $issuer->setPrivateKey($this->applicationKey);
        $issuer->setDN($this->issuerDn);

        $x509 = new X509();
        $x509->makeCA();
        $x509->setSerialNumber('42', 10);
        $x509->setStartDate('-1 second');
        $x509->setEndDate('1 day');

        return $x509->saveX509($x509->sign($issuer, $subject));
    }

    /**
     * @return array|string[]
     */
    public function getIssuerDn(): array
    {
        return $this->issuerDn;
    }
}
