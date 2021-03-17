<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\File\X509;
use Proton\X509Sign\Key;
use Proton\X509Sign\Server;
use ReflectionProperty;

/**
 * A third-party service/server that should be able to authenticate a user by a provided certificate
 * and check it was signed by the expected signature server.
 */
final class ThirdParty
{
    private ?Server $signatureServer = null;

    private ?string $signatureServerPublicKey = null;

    private ?string $signatureServerPublicKeyMode = null;

    public function connectToSignatureServer(Server $signatureServer): void
    {
        $this->signatureServer = $signatureServer;
    }

    public function recognizeUserInCertificate(User $user, string $certificate): bool
    {
        $serverPublicKey = $this->getSignatureServerPublicKey();
        $mode = $user->getPublicKeyMode();
        $userPublicKey = Key::loadPublic($mode, $user->getPublicKey());

        $x509 = new X509();
        $data = $x509->loadX509($certificate);
        $r = new ReflectionProperty(X509::class, 'signatureSubject');
        $r->setAccessible(true);
        $signatureSubject = $r->getValue($x509);
        [
            'signature' => $signature,
            'tbsCertificate' => [
                'subjectPublicKeyInfo' => [
                    'subjectPublicKey' => $subjectPublicKey,
                ],
            ],
        ] = $data;

        if (substr($signature, 0, 1) === "\0") {
            $signature = substr($signature, 1);
        }

        $format = ([
            Key::RSA => 'PSS',
        ])[$mode] ?? 'PKCS8';

        return $subjectPublicKey === $userPublicKey->toString($format)
            && $serverPublicKey->verify($signatureSubject, $signature);
    }

    private function getSignatureServerPublicKey(): PublicKey
    {
        if (!$this->signatureServerPublicKey) {
            $response = $this->postJson([
                'publicKey' => [],
                'publicKeyMode' => [],
            ]);

            $this->signatureServerPublicKey = $response['publicKey']['result'];
            $this->signatureServerPublicKeyMode = $response['publicKeyMode']['result'];
        }

        return Key::loadPublic($this->signatureServerPublicKeyMode, $this->signatureServerPublicKey);
    }

    /**
     * @param array<string, array> $requests
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
