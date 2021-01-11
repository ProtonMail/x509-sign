<?php

declare(strict_types=1);

namespace Proton\X509Sign;

use InvalidArgumentException;
use phpseclib3\Crypt\RSA\PrivateKey;
use Proton\X509Sign\RequestHandler\PublicKeyHandler;
use Proton\X509Sign\RequestHandler\SignedCertificateHandler;
use Throwable;

class Server
{
    protected array $handlers = [
        'publicKey' => PublicKeyHandler::class,
        'signedCertificate' => SignedCertificateHandler::class,
    ];

    protected string $privateKey;

    protected ?string $privateKeyPassPhrase;

    public function __construct(?string $privateKey = null, ?string $privateKeyPassPhrase = null)
    {
        $this->privateKey = $privateKey ?? PrivateKey::createKey()->toString('PKCS1');
        $this->privateKeyPassPhrase = $privateKeyPassPhrase;
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
     *
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
     *
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
            $this->privateKeyPassPhrase,
            (array) $data,
        );
    }
}
