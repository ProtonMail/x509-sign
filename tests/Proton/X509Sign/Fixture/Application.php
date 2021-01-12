<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use Proton\Apps\VPN\Contract\ClientCertificateInterface;
use Proton\X509Sign\Server;

/**
 * Application class represents a separated application using the signature endpoint
 * to get a certificate re-signed.
 */
final class Application
{
    public const NAME = 'super';

    private array $issuerDn = [
        'countryName' => 'US',
        'stateOrProvinceName' => 'NY',
        'localityName' => 'New York',
        'organizationName' => 'Any Organization',
        'organizationalUnitName' => 'Some Department',
        'commonName' => 'Dream Team',
        'emailAddress' => 'dreamteam@any.org',
    ];

    private array $usersDatabase = [
        'Alan' => [
            'cool' => true,
            'level' => 73,
        ],
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

        $this->loadASN1Extension();

        $userData = $this->currentUser->getSubjectDn();
        ['commonName' => $userName] = $userData;

        $subject = new X509();
        $subject->setPublicKey($signServerPublicKey);
        $subject->setDN($userData);

        $issuer = new X509();
        $issuer->setPrivateKey($this->applicationKey);
        $issuer->setDN($this->issuerDn);

        $x509 = new X509();
        $x509->makeCA();
        $x509->setSerialNumber('42', 10);
        $x509->setStartDate('-1 second');
        $x509->setEndDate('1 day');
        $x509->setExtensionValue(self::NAME, [
            'cool' => $this->usersDatabase[$userName]['cool'],
            'level' => $this->usersDatabase[$userName]['level'],
            'name' => $userName,
        ]);

        $certificate = $x509->saveX509($x509->sign($issuer, $subject));

        $this->unloadASN1Extension();

        return $certificate;
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

        $x509 = new X509();
        $data = $x509->loadX509($certificate);

        $time = strtotime($data['tbsCertificate']['validity']['notAfter']['utcTime']);
        $hours = (int) round(($time - time()) / 3600);

        $superAppExtension = $this->getFirstExtensionValue($data);

        $this->satisfied = (
            $hours === 24 &&
            (string) $data['tbsCertificate']['serialNumber'] === '42' &&
            $superAppExtension['cool'] &&
            (string) $superAppExtension['level'] === '73' &&
            (string) $superAppExtension['name'] === 'Alan' &&
            $this->currentUser->isSatisfiedWithItsCertificate()
        );
    }

    public function isSatisfied(): bool
    {
        return $this->satisfied;
    }

    /**
     * @return array{string, string, array}
     */
    public function getExtension(): array
    {
        return [
            self::NAME,
            '2.16.840.1.101.3.4.2.99',
            [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'cool' => ['type' => ASN1::TYPE_BOOLEAN],
                    'level' => ['type' => ASN1::TYPE_INTEGER],
                    'name' => ['type' => ASN1::TYPE_OCTET_STRING],
                ],
            ],
        ];
    }

    public function setUserData(string $name, array $data): void
    {
        $this->usersDatabase[$name] = array_merge($this->usersDatabase[$name], $data);
    }

    public function getFirstExtensionValue(array $data)
    {
        foreach ($data['tbsCertificate']['extensions'] as $extension) {
            if ($extension['extnId'] === self::NAME) {
                return $extension['extnValue'] ?? null;
            }
        }

        return null;
    }

    private function loadASN1Extension(): void
    {
        [$name, $id, $structure] = $this->getExtension();
        ASN1::loadOIDs([$name => $id]);
        X509::registerExtension($name, $structure);
    }

    private function unloadASN1Extension(): void
    {
        ASN1::loadOIDs([self::NAME => 'disabled']);
        X509::registerExtension(self::NAME, []);
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
