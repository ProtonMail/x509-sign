<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\X509;
use Proton\X509Sign\Server;

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

    private ?Server $signatureServer = null;

    private ?string $signatureServerPublicKey = null;

    private bool $satisfied = false;

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

    public function connectToSignatureServer(Server $signatureServer): void
    {
        $this->signatureServer = $signatureServer;
    }

    public function askForSignature(): void
    {
        $response = $this->postJson([
            'signedCertificate' => [
                'certificate' => $this->generateCertificate($this->getSignatureServerPublicKey()),
                'clientPublicKey' => $this->currentUser->getPublicKey(),
            ],
        ]);

        if (!($response['signedCertificate']['success'] ?? false)) {
            return;
        }

        /** @var string $certificate */
        $certificate = $response['signedCertificate']['result'];

        $this->currentUser->receiveCertificate($certificate);
        $this->satisfied = $this->currentUser->isSatisfiedWithItsCertificate();
    }

    public function isSatisfied(): bool
    {
        return $this->satisfied;
    }

    private function getSignatureServerPublicKey(): string
    {
        if (!$this->signatureServerPublicKey) {
            $response = $this->postJson([
                'publicKey' => [],
            ]);

            $this->signatureServerPublicKey = $response['publicKey']['result'];
        }

        return $this->signatureServerPublicKey;
    }

    /**
     * @param array<string, array> $requests
     *
     * @return array<string, array{success: bool, error?: string, result?: mixed}>
     */
    private function postJson(array $requests): array
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'x509-sign');
        $handler = fopen($tempFile, 'w+');
        $this->signatureServer->handleRequests($requests, $handler);
        fclose($handler);
        $contents = file_get_contents($tempFile);
        unlink($tempFile);

        return json_decode($contents, true);
    }
}
