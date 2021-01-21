<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\X509;
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

    public function connectToSignatureServer(Server $signatureServer): void
    {
        $this->signatureServer = $signatureServer;
    }

    public function recognizeUserInCertificate(User $user, string $certificate): bool
    {
        /** @var PublicKey $serverPublicKey */
        $serverPublicKey = PublicKey::load($this->getSignatureServerPublicKey());
        /** @var PublicKey $userPublicKey */
        $userPublicKey = PublicKey::load($user->getPublicKey());

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

        return $subjectPublicKey === $userPublicKey->toString('PSS')
            && $serverPublicKey->verify($signatureSubject, $signature);
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
