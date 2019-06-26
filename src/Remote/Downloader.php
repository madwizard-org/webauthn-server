<?php


namespace MadWizard\WebAuthn\Remote;

use GuzzleHttp\Client;
use Psr\Cache\CacheItemPoolInterface;
use function var_dump;

class Downloader
{
    /**
     * @var CacheItemPoolInterface
     */
    private $cache;

    /**
     * @var Client
     */
    private $client;

    public function __construct(CacheItemPoolInterface $cache, ?Client $client = null)
    {
        $this->cache = $cache;
        $this->client = $client ?? new Client();
    }

    public function downloadFile(string $uri) : FileContents
    {
        $hash = hash('sha256', $uri);

        $item = $this->cache->getItem($hash);
        if ($item->isHit()) {
            return $item->get();
        }

        $response = $this->client->get($uri);

        //var_dump($response->getHeader('Cache-Control'));
        $content = $response->getBody()->getContents();
        $types = $response->getHeader('Content-Type');
        $contentType = $types[0] ?? 'application/octet-stream';
        $file = new FileContents($content, $contentType);
        $item->set($file);
        $item->expiresAfter(10 * 60); // TODO: actual caching
        $this->cache->save($item);
        return $file;
    }
}
