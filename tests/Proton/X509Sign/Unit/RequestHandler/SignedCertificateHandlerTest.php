<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit\RequestHandler;

use Generator;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use Proton\X509Sign\Issuer;
use Proton\X509Sign\RequestHandler\SignedCertificateHandler;
use ReflectionProperty;
use RuntimeException;
use Tests\Proton\X509Sign\Fixture\Application;
use Tests\Proton\X509Sign\Fixture\User;
use Tests\Proton\X509Sign\TestCase;

/**
 * @coversDefaultClass \Proton\X509Sign\RequestHandler\SignedCertificateHandler
 */
class SignedCertificateHandlerTest extends TestCase
{
    /**
     * @covers ::__construct
     */
    public function testConstructor(): void
    {
        $property = new ReflectionProperty(SignedCertificateHandler::class, 'issuer');
        $property->setAccessible(true);

        self::assertInstanceOf(Issuer::class, $property->getValue(new SignedCertificateHandler()));

        $issuer = new Issuer();

        self::assertSame($issuer, $property->getValue(new SignedCertificateHandler($issuer)));
    }

    /**
     * @param string|null $passPhrase
     *
     * @covers ::handle
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
            json_encode([$application->getExtension()]),
            [
                'certificate' => $certificate,
                'clientPublicKey' => $user->getPublicKey(),
            ],
        );

        self::assertNotSame($certificate, $result);

        [
            'hours' => $hours,
            'issuer' => $issuer,
            'subject' => $subject,
            'serialNumber' => $serialNumber,
        ] = $this->getCertificateData($result);

        self::assertSame(24, $hours);
        self::assertSame($application->getIssuerDn(), $issuer);
        self::assertSame($user->getSubjectDn(), $subject);
        self::assertSame('42', $serialNumber);
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

    /**
     * @covers ::handle
     */
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
            null,
            [
                'certificate' => 'foobar',
                'clientPublicKey' => (new User())->getPublicKey(),
            ],
        );
    }

    /**
     * @covers ::reIssueCertificate
     */
    public function testReIssueCertificate()
    {
        $handler = new class () extends SignedCertificateHandler {
            public function callReIssueCertificate(
                Application $application,
                string $certificate,
                PrivateKey $issuerKey,
                PublicKey $subjectKey
            ): ?string {
                $this->loadExtensions([$application->getExtension()]);

                return $this->reIssueCertificate($certificate, $issuerKey, $subjectKey);
            }
        };
        $application = new Application();

        self::assertNull($handler->callReIssueCertificate(
            $application,
            'foobar',
            PrivateKey::createKey(),
            PrivateKey::createKey()->getPublicKey(),
        ));

        /** @var PrivateKey $signServerPrivateKey */
        $signServerPrivateKey = PrivateKey::createKey();

        /** @var PublicKey $signServerPublicKey */
        $signServerPublicKey = $signServerPrivateKey->getPublicKey();

        $user = new User();
        $application->setUserData($user->getSubjectDn()['commonName'], ['level' => 12]);
        $application->receiveRequestFromUser($user);
        $certificate = $application->generateCertificate($signServerPublicKey->toString('PKCS1'));

        /** @var PublicKey $userPublicKey */
        $userPublicKey = PublicKey::load($user->getPublicKey());

        $reIssuedCertificate = $handler->callReIssueCertificate(
            $application,
            $certificate,
            $signServerPrivateKey,
            $userPublicKey,
        );

        self::assertIsString($reIssuedCertificate);

        $extension = $this->getCertificateData($reIssuedCertificate)['extensions']['super'];

        self::assertSame('12', (string) $extension['level']);
    }

    /**
     * @covers ::loadExtensions
     */
    public function testLoadExtensions()
    {
        $handler = new class () extends SignedCertificateHandler {
            public function callLoadExtensions(array $extensions): void
            {
                $this->loadExtensions($extensions);
            }
        };

        $handler->callLoadExtensions([
            [
                'my-id',
                'my-code',
                ['type' => ASN1::TYPE_INTEGER],
            ],
            [
                'foo',
                'bar',
                ['type' => ASN1::TYPE_ANY],
            ],
        ]);

        $oidsReflector = new ReflectionProperty(ASN1::class, 'oids');
        $oidsReflector->setAccessible(true);

        self::assertSame('my-id', $oidsReflector->getValue()['my-code']);
        self::assertSame('foo', $oidsReflector->getValue()['bar']);

        $extensionsReflector = new ReflectionProperty(X509::class, 'extensions');
        $extensionsReflector->setAccessible(true);

        self::assertSame(['type' => ASN1::TYPE_INTEGER], $extensionsReflector->getValue()['my-id']);
        self::assertSame(['type' => ASN1::TYPE_ANY], $extensionsReflector->getValue()['foo']);
    }

    /**
     * @covers ::getExtensionsValues
     */
    public function testGetExtensionsValues(): void
    {
        $handler = new class () extends SignedCertificateHandler {
            public function callGetExtensionsValues(array $certificateData): array
            {
                return iterator_to_array($this->getExtensionsValues($certificateData));
            }
        };

        self::assertSame([], $handler->callGetExtensionsValues([]));
        self::assertSame([
            'first' => 1,
            'second' => [2 => 2],
        ], $handler->callGetExtensionsValues([
            'extensions' => [
                [
                    'extnId' => 'first',
                    'extnValue' => 1,
                    'critical' => false,
                ],
                [
                    'extnId' => 'second',
                    'extnValue' => [2 => 2],
                    'critical' => true,
                ],
            ],
        ]));
    }
}
