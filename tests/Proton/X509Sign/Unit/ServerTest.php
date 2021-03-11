<?php

declare(strict_types=1);

namespace Tests\Proton\X509Sign\Unit;

use InvalidArgumentException;
use Proton\X509Sign\Server;
use Tests\Proton\X509Sign\TestCase;

/**
 * @coversDefaultClass \Proton\X509Sign\Server
 */
class ServerTest extends TestCase
{
    /**
     * @covers ::__construct
     */
    public function testConstructor(): void
    {
        self::assertInstanceOf(Server::class, new Server());
        self::assertInstanceOf(Server::class, new Server('some string'));
        self::assertInstanceOf(Server::class, new Server(null, 'some string'));
    }

    /**
     * @covers ::handleRequests
     */
    public function testHandleRequests(): void
    {
        $server = new Server();
        $tempFile = tempnam(sys_get_temp_dir(), 'x509-sign');
        $handler = fopen($tempFile, 'w+');
        $server->handleRequests(['publicKey' => []], $handler);

        $contents = str_replace("\r", '', file_get_contents($tempFile));
        unlink($tempFile);

        self::assertMatchesRegularExpression(
            '/^{"publicKey":{"success":true,"result":[\s\S]+}}$/',
            $contents,
            'should succeed with a JSON-like output',
        );

        $data = json_decode($contents, true);

        self::assertIsArray($data, 'should decode as an array');
        self::assertIsString($data['publicKey']['result'] ?? null, 'should return a string result');

        ob_start();
        $server->handleRequests(['publicKey' => []]);
        $contents = ob_get_contents();
        ob_end_clean();

        $data = json_decode($contents, true);

        self::assertIsArray($data, 'should decode as an array');
        self::assertIsString($data['publicKey']['result'] ?? null, 'should return a string result');
    }

    /**
     * @covers ::getGroupedResponse
     */
    public function testGetGroupedResponse(): void
    {
        $server = new class() extends Server {
            public function callGetGroupedResponse(array $requests): array
            {
                return iterator_to_array($this->getGroupedResponse($requests));
            }

            protected function getRequestResponse(string $id, $data): array
            {
                return [
                    'success' => true,
                    'result' => "result for $id",
                ];
            }
        };

        $requests = [
            'publicKey' => [],
            'signedCertificate' => [],
        ];

        $responses = $server->callGetGroupedResponse($requests);

        self::assertSame('"publicKey":', $responses[0]);
        self::assertTrue(json_decode($responses[1])->success);
        self::assertSame(',"signedCertificate":', $responses[2]);
        self::assertTrue(json_decode($responses[3])->success);
    }

    /**
     * @covers ::getRequestResponse
     */
    public function testGetRequestResponse(): void
    {
        $server = new class() extends Server {
            public function callGetRequestResponse(string $id, $data): array
            {
                return $this->getRequestResponse($id, $data);
            }
        };

        $result = $server->callGetRequestResponse('publicKey', 'not-an-array');

        self::assertSame([
            'success' => false,
            'error' => 'Request data must be an array.'
        ], $result);

        $result = $server->callGetRequestResponse('publicKey', []);

        self::assertSame(['success', 'result'], array_keys($result));
        self::assertTrue($result['success']);
        self::assertIsString($result['result']);
    }

    /**
     * @covers ::executeHandler
     */
    public function testExecuteHandler(): void
    {
        $server = new class() extends Server {
            public function callExecuteHandler(string $id, $data)
            {
                return $this->executeHandler($id, $data);
            }
        };

        $result = $server->callExecuteHandler('publicKey', []);

        self::assertIsString($result);

        $result = str_replace("\r", '', $result);

        self::assertMatchesRegularExpression(
            '/^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----$/',
            $result,
        );
    }

    /**
     * @covers ::executeHandler
     */
    public function testExecuteHandlerPKCS1(): void
    {
        $server = new class() extends Server {
            public function callExecuteHandler(string $id, $data)
            {
                return $this->executeHandler($id, $data);
            }
        };

        $result = $server->callExecuteHandler('publicKey', [
            'format' => 'PKCS1',
        ]);

        self::assertIsString($result);

        $result = str_replace("\r", '', $result);

        self::assertMatchesRegularExpression(
            '/^-----BEGIN RSA PUBLIC KEY-----\n[\s\S]+\n-----END RSA PUBLIC KEY-----$/',
            $result,
        );
    }

    /**
     * @covers ::executeHandler
     */
    public function testExecuteHandlerWithInvalidId(): void
    {
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('No handler for i-do-not-exist request.');

        $server = new class() extends Server {
            public function callExecuteHandler(string $id, $data)
            {
                return $this->executeHandler($id, $data);
            }
        };

        $server->callExecuteHandler('i-do-not-exist', []);
    }

    /**
     * @covers ::executeHandler
     */
    public function testExecuteHandlerWithInvalidData(): void
    {
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('Request data must be an array.');

        $server = new class() extends Server {
            public function callExecuteHandler(string $id, $data)
            {
                return $this->executeHandler($id, $data);
            }
        };

        $server->callExecuteHandler('publicKey', 'not-an-array');
    }
}
