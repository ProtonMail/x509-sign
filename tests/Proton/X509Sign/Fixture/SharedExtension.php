<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use ReflectionProperty;

trait SharedExtension
{
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

    private function loadASN1Extension(): void
    {
        [$name, $id, $structure] = $this->getExtension();
        ASN1::loadOIDs([$name => $id]);
        X509::registerExtension($name, $structure);
    }

    private function unloadASN1Extension(): void
    {
        ASN1::loadOIDs([self::NAME => 'disabled']);
        $extensionsReflector = new ReflectionProperty(X509::class, 'extensions');
        $extensionsReflector->setAccessible(true);
        $extensions = $extensionsReflector->getValue();
        unset($extensions[self::NAME]);
        $extensionsReflector->setValue($extensions);
    }
}
