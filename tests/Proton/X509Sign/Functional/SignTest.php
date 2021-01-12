<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Functional;

use PHPUnit\Framework\TestCase;
use Proton\X509Sign\Server;
use Tests\Proton\X509Sign\Fixture\Application;
use Tests\Proton\X509Sign\Fixture\User;

class SignTest extends TestCase
{
    /**
     * Test that the signature server can satisfy client applications needs.
     *
     * @coversNothing
     */
    public function testSignature(): void
    {
        $alan = new User();
        $alanFavoriteService = new Application();
        $signatureServer = new Server(null, null, json_encode([$alanFavoriteService->getExtension()]));

        $alan->use($alanFavoriteService);
        $alanFavoriteService->connectToSignatureServer($signatureServer);
        $alanFavoriteService->askForSignature();

        self::assertTrue($alanFavoriteService->isSatisfied());
    }
}
