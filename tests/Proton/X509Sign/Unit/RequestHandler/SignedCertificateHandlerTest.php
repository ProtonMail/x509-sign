<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit\RequestHandler;

use Generator;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use Proton\X509Sign\RequestHandler\SignedCertificateHandler;
use RuntimeException;
use Tests\Proton\X509Sign\Fixture\Application;
use Tests\Proton\X509Sign\Fixture\User;

/**
 * @covers \Proton\X509Sign\RequestHandler\SignedCertificateHandlerTest::handle
 */
class SignedCertificateHandlerTest extends TestCase
{
    /**
     * @param string|null $passPhrase
     *
     * @dataProvider getPassphrases
     */
    public function testHandle(?string $passPhrase): void
    {
        /** @var PrivateKey $signServerPrivateKey */
        $signServerPrivateKey = PrivateKey::createKey()->withPassword($passPhrase ?? false);

        /** @var PublicKey $signServerPublicKey */
        $signServerPublicKey = $signServerPrivateKey->getPublicKey();

        $application = new Application();
        $user = new User();
        $application->receiveRequestFromUser($user);
        $certificate = $application->generateCertificate($signServerPublicKey->toString('PKCS1'));

        $result = (new SignedCertificateHandler())->handle(
            $signServerPrivateKey->toString('PKCS1'),
            $passPhrase,
            [
                'certificate' => $certificate,
                'clientPublicKey' => $user->getPublicKey(),
            ],
        );

        self::assertNotSame($certificate, $result);

        $x509 = new X509();
        $data = $x509->loadX509($result);

        $time = strtotime($data['tbsCertificate']['validity']['notAfter']['utcTime']);
        $hours = (int) round(($time - time()) / 3600);

        self::assertSame(24, $hours);
        self::assertSame($application->getIssuerDn(), $this->getRdnSequenceData($data['tbsCertificate']['issuer']));
        self::assertSame($user->getSubjectDn(), $this->getRdnSequenceData($data['tbsCertificate']['subject']));
        self::assertSame('42', (string) $data['tbsCertificate']['serialNumber']);
    }

    public function testHandleIncorrectCertificate(): void
    {
        self::expectException(RuntimeException::class);
        self::expectExceptionMessage('Unable to sign the CSR.');

        $handler = new SignedCertificateHandler();
        /** @var PrivateKey $privateKey */
        $privateKey = PrivateKey::createKey()->withPassword('Le petit chien est sur la pente fatale.');

        $handler->handle(
            $privateKey->toString('PKCS1'),
            'Le petit chien est sur la pente fatale.',
            [
                'certificate' => 'foobar',
                'clientPublicKey' => (new User())->getPublicKey(),
            ],
        );
    }

    /**
     * @psalm-return Generator<?string[]>
     */
    public function getPassphrases(): Generator
    {
        // TODO: Support passphrases
        // yield ['Le petit chien est sur la pente fatale.'];
        yield [null];
    }

    private function getRdnSequenceData(array $sequence): array
    {
        $dnCopy = [];

        foreach (($sequence['rdnSequence'] ?? $sequence) as $item) {
            /**
             * @var string $type
             * @var string $value
             */
            ['type' => $type, 'value' => ['utf8String' => $value]] = $item[0];

            // Ignore namespace prefix
            $type = preg_replace('/^.*-at-/U', '', $type);

            $dnCopy[$type] = $value;
        }

        return $dnCopy;
    }
}
