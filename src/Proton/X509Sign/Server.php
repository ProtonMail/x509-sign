<?php

declare(strict_types=1);

namespace Proton\X509Sign;

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
     * @param array[] $requests
     * @param resource|null $outputHandler
     */
    public function handleRequests(array $requests, $outputHandler = null): void
    {
        $outputHandler = $outputHandler ?? fopen('php://output', 'w');
        fwrite($outputHandler, '{');

        foreach ($this->getGroupedResponse($requests) as $output) {
            fwrite($outputHandler, $output);
        }

        fwrite($outputHandler, '}');
        fclose($outputHandler);
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
            yield from $this->getRequestResponse((string) $id, $data);

            if ($first) {
                $first = false;
            }
        }
    }

    /**
     * @param string $id
     * @param mixed $data
     *
     * @return iterable<string>
     */
    protected function getRequestResponse(string $id, $data): iterable
    {
        $handler = $this->handlers[$id] ?? null;
        $error = null;

        if (!$handler) {
            $error = "No handler for $id request.";
        }

        if (!is_array($data)) {
            $error = "Request data must be an array.";
        }

        $result = null;

        try {
            $result = (new $handler())->handle(
                $this->privateKey,
                $this->privateKeyPassPhrase,
                (array) $data,
            );
        } catch (Throwable $exception) {
            $error = $exception->getMessage();
        }

        if ($error) {
            yield json_encode([
                'success' => false,
                'error' => $error,
            ]);

            return;
        }

        yield json_encode([
            'success' => true,
            'result' => $result,
        ]);
    }
}
