<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit;

use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use Proton\X509Sign\Issuer;
use ReflectionProperty;
use Tests\Proton\X509Sign\TestCase;

/**
 * @coversDefaultClass \Proton\X509Sign\Issuer
 */
class IssuerTest extends TestCase
{
    /**
     * @covers ::issue
     */
    public function testIssueWithRSAKey(): void
    {
        $issuer = new Issuer();

        self::assertNull($issuer->issue(
            RSA::createKey(),
            RSA::createKey()->getPublicKey(),
            [],
            [],
        ));

        [
            'extensions' => $extensions,
            'issuer' => $issuerDn,
            'subject' => $subjectDn,
        ] = $this->getCertificateData($issuer->issue(
            PrivateKey::createKey(),
            PrivateKey::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
        ));

        self::assertSame($issuerDn, ['commonName' => 'foo']);
        self::assertSame($subjectDn, ['commonName' => 'bar']);
        self::assertFalse($extensions['id-ce-basicConstraints']['cA'] ?? false);

        [
            'extensions' => $extensions,
            'issuer' => $issuerDn,
            'subject' => $subjectDn,
        ] = $this->getCertificateData($issuer->issue(
            PrivateKey::createKey(),
            PrivateKey::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            null,
            null,
            null,
            [],
            static function (X509 $authority) {
                $authority->makeCA();
            },
        ));

        self::assertSame($issuerDn, ['commonName' => 'foo']);
        self::assertSame($subjectDn, ['commonName' => 'bar']);
        self::assertTrue($extensions['id-ce-basicConstraints']['cA'] ?? false);

        ['serialNumber' => $serialNumber] = $this->getCertificateData($issuer->issue(
            PrivateKey::createKey(),
            PrivateKey::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            '9256'
        ));

        self::assertSame('9256', $serialNumber);

        ['hours' => $hours] = $this->getCertificateData($issuer->issue(
            PrivateKey::createKey(),
            PrivateKey::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            null,
            '-1 day',
            '+5 days'
        ));

        self::assertSame(5 * 24, $hours);

        $issuer->loadExtensions([
            [
                'custom-ext-1',
                '2.16.840.1.101.3.4.2.45',
                ['type' => ASN1::TYPE_OCTET_STRING],
            ],
        ]);

        ['extensions' => $extensions] = $this->getCertificateData($issuer->issue(
            PrivateKey::createKey(),
            PrivateKey::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            null,
            null,
            null,
            [
                'custom-ext-1' => 'Yub yub!',
            ],
        ));

        self::assertSame('Yub yub!', $extensions['custom-ext-1']);
    }

    /**
     * @covers ::issue
     */
    public function testIssueWithEd25519Key(): void
    {
        $issuer = new Issuer();

        self::assertNull($issuer->issue(
            EC::createKey('Ed25519'),
            EC::createKey('Ed25519')->getPublicKey(),
            [],
            [],
        ));

        [
            'issuer' => $issuerDn,
            'subject' => $subjectDn,
        ] = $this->getCertificateData($issuer->issue(
            EC::createKey('Ed25519'),
            EC::createKey('Ed25519')->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
        ));

        self::assertSame($issuerDn, ['commonName' => 'foo']);
        self::assertSame($subjectDn, ['commonName' => 'bar']);

        ['serialNumber' => $serialNumber] = $this->getCertificateData($issuer->issue(
            EC::createKey('Ed25519'),
            EC::createKey('Ed25519')->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            '9256'
        ));

        self::assertSame('9256', $serialNumber);

        ['hours' => $hours] = $this->getCertificateData($issuer->issue(
            EC::createKey('Ed25519'),
            EC::createKey('Ed25519')->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            null,
            '-1 day',
            '+5 days'
        ));

        self::assertSame(5 * 24, $hours);

        $issuer->loadExtensions([
            [
                'custom-ext-1',
                '2.16.840.1.101.3.4.2.45',
                ['type' => ASN1::TYPE_OCTET_STRING],
            ],
        ]);

        ['extensions' => $extensions] = $this->getCertificateData($issuer->issue(
            EC::createKey('Ed25519'),
            EC::createKey('Ed25519')->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            null,
            null,
            null,
            [
                'custom-ext-1' => 'Yub yub!',
            ],
        ));

        self::assertSame('Yub yub!', $extensions['custom-ext-1']);
    }

    /**
     * @covers ::issue
     */
    public function testIssueWithDSAKey(): void
    {
        $issuer = new Issuer();

        self::assertNull($issuer->issue(
            DSA::createKey(),
            DSA::createKey()->getPublicKey(),
            [],
            [],
        ));

        [
            'issuer' => $issuerDn,
            'subject' => $subjectDn,
        ] = $this->getCertificateData($issuer->issue(
            DSA::createKey(),
            DSA::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
        ));

        self::assertSame($issuerDn, ['commonName' => 'foo']);
        self::assertSame($subjectDn, ['commonName' => 'bar']);

        ['serialNumber' => $serialNumber] = $this->getCertificateData($issuer->issue(
            DSA::createKey(),
            DSA::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            '9256'
        ));

        self::assertSame('9256', $serialNumber);

        ['hours' => $hours] = $this->getCertificateData($issuer->issue(
            DSA::createKey(),
            DSA::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            null,
            '-1 day',
            '+5 days'
        ));

        self::assertSame(5 * 24, $hours);

        $issuer->loadExtensions([
            [
                'custom-ext-1',
                '2.16.840.1.101.3.4.2.45',
                ['type' => ASN1::TYPE_OCTET_STRING],
            ],
        ]);

        ['extensions' => $extensions] = $this->getCertificateData($issuer->issue(
            DSA::createKey(),
            DSA::createKey()->getPublicKey(),
            ['commonName' => 'foo'],
            ['commonName' => 'bar'],
            null,
            null,
            null,
            [
                'custom-ext-1' => 'Yub yub!',
            ],
        ));

        self::assertSame('Yub yub!', $extensions['custom-ext-1']);
    }

    /**
     * @covers ::loadExtensions
     */
    public function testLoadExtensions(): void
    {
        $handler = new class () extends Issuer {
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
}
