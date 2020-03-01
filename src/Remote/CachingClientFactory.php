<?php


namespace MadWizard\WebAuthn\Remote;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Kevinrob\GuzzleCache\CacheMiddleware;
use Kevinrob\GuzzleCache\Storage\Psr6CacheStorage;
use Kevinrob\GuzzleCache\Strategy\PrivateCacheStrategy;
use MadWizard\WebAuthn\Cache\CacheProviderInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

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
        $stack->push(
            function (callable $handler) {
                return function (RequestInterface $request, array $options) use ($handler) {
                    error_log('DL:' . $request->getHeaderLine('Host') . ' ' . $request->getUri());

                    $res = $handler($request, $options);

                    return $res->then(function (ResponseInterface $response) use ($request) {
                        // Invalidate cache after a call of non-safe method on the same URI
                        error_log('DL:' . $response->getStatusCode());

                        return $response;
                    });
                };
            }
        );


        return new Client(['handler' => $stack]);
    }
}
