<?php

namespace MadWizard\WebAuthn\Remote;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use MadWizard\WebAuthn\Exception\RemoteException;

class Downloader implements DownloaderInterface
{
    /**
     * @var Client
     */
    private $client;

    public function __construct(Client $client)     // TODO use clientfactory
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
            throw new RemoteException('Failed to download URL.', 0, $e);
        }

        $content = $response->getBody()->getContents();
        $types = $response->getHeader('Content-Type');
        $contentType = $types[0] ?? 'application/octet-stream';
        return new FileContents($content, $contentType);
    }
}
