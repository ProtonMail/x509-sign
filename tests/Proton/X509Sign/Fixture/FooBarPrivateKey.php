<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Fixture;

use phpseclib3\Crypt\Common\PrivateKey;

class FooBarPrivateKey implements PrivateKey
{
    public function sign($message)
    {
        // noop
    }

    public function getPublicKey()
    {
        // noop
    }

    public function toString($type, array $options = [])
    {
        // noop
    }

    public function withPassword($string)
    {
        // noop
    }
}
