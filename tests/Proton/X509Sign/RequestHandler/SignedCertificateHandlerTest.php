<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\RequestHandler;

use Generator;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\X509;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\TestCase;
use Proton\Apps\VPN\Contract\ClientCertificateInterface;
use Proton\X509Sign\RequestHandler\SignedCertificateHandler;
use RuntimeException;
use function Proton\Support\config;

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
        $issuerDn = [
            'countryName' => 'US',
            'stateOrProvinceName' => 'NY',
            'localityName' => 'New York',
            'organizationName' => 'Any Organization',
            'organizationalUnitName' => 'Some Department',
            'commonName' => 'Dream Team',
            'emailAddress' => 'dreamteam@any.org',
        ];

        $subjectDn = ['commonName' => 'Bob'];

        $handler = new SignedCertificateHandler();
        /** @var PrivateKey $signServerPrivateKey */
        $signServerPrivateKey = PrivateKey::createKey()->withPassword($passPhrase ?? false);

        /** @var PublicKey $signServerPublicKey */
        $signServerPublicKey = $signServerPrivateKey->getPublicKey();

        /** @var PrivateKey $middlewarePrivateKey */
        $middlewarePrivateKey = PrivateKey::createKey();

        /** @var PublicKey $middlewarePublicKey */
        $middlewarePublicKey = $middlewarePrivateKey->getPublicKey();

        /** @var PrivateKey $clientPrivateKey */
        $clientPrivateKey = PrivateKey::createKey();

        /** @var PublicKey $publicKey */
        $clientPublicKey = $clientPrivateKey->getPublicKey();

        $subject = new X509();
        $subject->setPublicKey($signServerPublicKey);
        $subject->setDN($subjectDn);

        $issuer = new X509();
        $issuer->setPrivateKey($middlewarePrivateKey);
        $issuer->setDN($issuerDn);

        $x509 = new X509();
        $x509->makeCA();
        $x509->setSerialNumber('42', 10);
        $x509->setStartDate('-1 second');
        $x509->setEndDate('1 day');

        $certificate = $x509->saveX509($x509->sign($issuer, $subject));

        $result = $handler->handle(
            $signServerPrivateKey->toString('PKCS1'),
            $passPhrase,
            [
                'certificate' => $certificate,
                'clientPublicKey' => $clientPublicKey->toString('PKCS1'),
                'issuerPublicKey' => $middlewarePublicKey->toString('PKCS1'),
            ],
        );

        self::assertNotSame($certificate, $result);

        $data = $x509->loadX509($result);

        $time = strtotime($data['tbsCertificate']['validity']['notAfter']['utcTime']);
        $hours = (int) round(($time - time()) / 3600);

        self::assertSame(24, $hours);
        self::assertSame($issuerDn, $this->getRdnSequenceData($data['tbsCertificate']['issuer']));
        self::assertSame($subjectDn, $this->getRdnSequenceData($data['tbsCertificate']['subject']));
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
            ['certificate' => 'foobar'],
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
