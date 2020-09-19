<?php

namespace MadWizard\WebAuthn\Remote;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use MadWizard\WebAuthn\Exception\RemoteException;
use Psr\Http\Client\ClientExceptionInterface;

class Downloader implements DownloaderInterface
{
    /**
     * @var Client
     */
    private $client;

    public function __construct(Client $client)     // TODO use clientfactory and ClientInterface
    {
        $this->client = $client;
    }

    /**
     * @throws RemoteException
     */
    public function downloadFile(string $uri): FileContents
    {
        try {
            $response = $this->client->get($uri);
        } catch (RequestException $e) {
            $message = 'Failed to download URL';
            $errorResponse = $e->getResponse();
            if ($errorResponse) {
                $message = sprintf('Error response while downloading URL: %d %s', $errorResponse->getStatusCode(), $errorResponse->getReasonPhrase());
            } else {
                $message = sprintf('Failed to download URL: %s', $e->getMessage());
            }
            throw new RemoteException($message, 0, $e);
        } catch (ClientExceptionInterface $e) {
            throw new RemoteException(sprintf('Failed to download URL: %s', $e->getMessage()), 0, $e);
        }

        $content = $response->getBody()->getContents();
        $types = $response->getHeader('Content-Type');
        $contentType = $types[0] ?? 'application/octet-stream';
        return new FileContents($content, $contentType);
    }
}
