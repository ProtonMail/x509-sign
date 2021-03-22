<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Functional;

use phpseclib3\Crypt\RSA;
use Proton\X509Sign\Key;
use Proton\X509Sign\Server;
use Tests\Proton\X509Sign\Fixture\Application;
use Tests\Proton\X509Sign\Fixture\ThirdParty;
use Tests\Proton\X509Sign\Fixture\User;
use Tests\Proton\X509Sign\TestCase;

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
        $signatureServer = new Server(null, json_encode([$alanFavoriteService->getExtension()]));

        $alan->use($alanFavoriteService);
        $alanFavoriteService->connectToSignatureServer($signatureServer);
        $alanFavoriteService->askForSignature();

        self::assertTrue($alanFavoriteService->isSatisfied());
    }

    /**
     * Test that the signature server can satisfy client applications needs.
     *
     * @coversNothing
     */
    public function testSignatureWithRSAKey(): void
    {
        $alan = new User(RSA::createKey());
        $alanFavoriteService = new Application();
        $signatureServer = new Server(null, json_encode([$alanFavoriteService->getExtension()]));

        $alan->use($alanFavoriteService);
        $alanFavoriteService->connectToSignatureServer($signatureServer);
        $alanFavoriteService->askForSignature(Key::RSA);

        self::assertTrue($alanFavoriteService->isSatisfied());
    }

    /**
     * Test that the signature server can satisfy client applications needs.
     *
     * @coversNothing
     */
    public function testThirdPartyChecking(): void
    {
        $alan = new User();
        $alanFavoriteService = new Application();
        $signatureServer = new Server(null, json_encode([$alanFavoriteService->getExtension()]));

        $alan->use($alanFavoriteService);
        $alanFavoriteService->connectToSignatureServer($signatureServer);
        $certificate = $alanFavoriteService->getSignedCertificate();

        $thirdParty = new ThirdParty();
        $thirdParty->connectToSignatureServer($signatureServer);
        $someoneElse = new User(); // Someone else trying to pretend he's Alan

        self::assertTrue($thirdParty->recognizeUserInCertificate($alan, $certificate));
        self::assertFalse($thirdParty->recognizeUserInCertificate($someoneElse, $certificate));

        $fakeSignatureServer = new Server(null, json_encode([$alanFavoriteService->getExtension()]));

        // Alan tweaks his application to use an other signature server
        $alanFavoriteService->connectToSignatureServer($fakeSignatureServer);
        $certificate = $alanFavoriteService->getSignedCertificate();

        self::assertFalse($thirdParty->recognizeUserInCertificate($alan, $certificate));
    }

    /**
     * Test that the signature server can satisfy client applications needs.
     *
     * @coversNothing
     */
    public function testThirdPartyCheckingWithRSA(): void
    {
        $alan = new User(RSA::createKey());
        $alanFavoriteService = new Application();
        $signatureServer = new Server(null, json_encode([$alanFavoriteService->getExtension()]));

        $alan->use($alanFavoriteService);
        $alanFavoriteService->connectToSignatureServer($signatureServer);
        $certificate = $alanFavoriteService->getSignedCertificate(Key::RSA);

        $thirdParty = new ThirdParty();
        $thirdParty->connectToSignatureServer($signatureServer);
        $someoneElse = new User(); // Someone else trying to pretend he's Alan

        self::assertTrue($thirdParty->recognizeUserInCertificate($alan, $certificate));
        self::assertFalse($thirdParty->recognizeUserInCertificate($someoneElse, $certificate));

        $fakeSignatureServer = new Server(null, json_encode([$alanFavoriteService->getExtension()]));

        // Alan tweaks his application to use an other signature server
        $alanFavoriteService->connectToSignatureServer($fakeSignatureServer);
        $certificate = $alanFavoriteService->getSignedCertificate(Key::RSA);

        self::assertFalse($thirdParty->recognizeUserInCertificate($alan, $certificate));
    }
}
