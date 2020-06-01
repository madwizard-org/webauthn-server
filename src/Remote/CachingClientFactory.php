<?php


namespace MadWizard\WebAuthn\Remote;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Kevinrob\GuzzleCache\CacheMiddleware;
use Kevinrob\GuzzleCache\Storage\Psr6CacheStorage;
use Kevinrob\GuzzleCache\Strategy\PrivateCacheStrategy;
use MadWizard\WebAuthn\Cache\CacheProviderInterface;

final class CachingClientFactory
{
    /**
     * @var CacheProviderInterface
     */
    private $cacheProvider;

    public function __construct(CacheProviderInterface $cacheProvider)
    {
        $this->cacheProvider = $cacheProvider;
    }

    public function createClient(): Client
    {
        $stack = HandlerStack::create();

        $stack->push(
            new CacheMiddleware(
                new PrivateCacheStrategy(
                    new Psr6CacheStorage(
                        $this->cacheProvider->getCachePool('http')
                    )
                )
            )
        );

        return new Client(['handler' => $stack]);
    }
}
