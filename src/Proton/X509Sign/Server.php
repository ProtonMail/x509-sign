<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use InvalidArgumentException;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\RSA;
use Proton\X509Sign\RequestHandler\CertificateAuthorityHandler;
use Proton\X509Sign\RequestHandler\PublicKeyHandler;
use Proton\X509Sign\RequestHandler\PublicKeyModeHandler;
use Proton\X509Sign\RequestHandler\SignedCertificateHandler;
use Throwable;

class Server
{
    protected array $handlers = [
        'certificateAuthority' => CertificateAuthorityHandler::class,
        'publicKey' => PublicKeyHandler::class,
        'publicKeyMode' => PublicKeyModeHandler::class,
        'signedCertificate' => SignedCertificateHandler::class,
    ];

    protected PrivateKey $privateKey;

    protected array $config;

    public function __construct(?PrivateKey $privateKey = null, array $config = [])
    {
        $this->privateKey = $privateKey ?? RSA::createKey();
        $this->config = $config;
    }

    private static function getEnv(array $keys): array
    {
        $envFile = __DIR__ . '/../../../storage/env.php';
        $cache = file_exists($envFile) ? (@include $envFile) : [];

        return array_combine($keys, array_map(
            static fn (string $key) => array_key_exists($key, $cache) ? $cache[$key] : getenv($key),
            $keys,
        ));
    }

    public static function fromEnv(): self
    {
        $env = self::getEnv([
            'SIGNATURE_PRIVATE_KEY',
            'SIGNATURE_PRIVATE_KEY_MODE',
            'SIGNATURE_PRIVATE_KEY_PASSPHRASE',
            'EXTENSIONS',
            'CA_FILE',
        ]);
        $privateKeyString = $env['SIGNATURE_PRIVATE_KEY'];
        $privateKey = $privateKeyString
            ? Key::loadPrivate(
                $env['SIGNATURE_PRIVATE_KEY_MODE'] ?: Key::EC,
                $privateKeyString,
                $env['SIGNATURE_PRIVATE_KEY_PASSPHRASE'] ?: null,
            )
            : null;

        return new static($privateKey, $env);
    }

    /**
     * @param array<string, array> $requests
     * @param resource|null $outputHandler
     */
    public function handleRequests(array $requests, $outputHandler = null): void
    {
        $handler = $outputHandler ?? fopen('php://output', 'w');
        fwrite($handler, '{');

        foreach ($this->getGroupedResponse($requests) as $output) {
            fwrite($handler, $output);
        }

        fwrite($handler, '}');

        if (!$outputHandler) {
            fclose($handler);
        }
    }

    /**
     * @param array[] $requests
     * @return iterable<string>
     */
    protected function getGroupedResponse(array $requests): iterable
    {
        $first = true;

        foreach ($requests as $id => $data) {
            yield ($first ? '' : ',') . json_encode($id) . ':';
            yield json_encode($this->getRequestResponse((string) $id, $data));

            if ($first) {
                $first = false;
            }
        }
    }

    /**
     * @param string $id
     * @param mixed $data
     * @return array{success: bool, error?: string, result?: mixed}
     */
    protected function getRequestResponse(string $id, $data): array
    {
        try {
            return [
                'success' => true,
                'result' => $this->executeHandler($id, $data),
            ];
        } catch (Throwable $exception) {
            return [
                'success' => false,
                'error' => $exception->getMessage(),
            ];
        }
    }

    protected function executeHandler(string $id, $data)
    {
        $handler = $this->handlers[$id] ?? null;

        if (!$handler) {
            throw new InvalidArgumentException("No handler for $id request.");
        }

        if (!is_array($data)) {
            throw new InvalidArgumentException("Request data must be an array.");
        }

        return (new $handler())->handle(
            $this->privateKey,
            $this->config,
            $data,
        );
    }
}
