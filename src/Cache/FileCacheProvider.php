<?php

namespace MadWizard\WebAuthn\Cache;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

final class FileCacheProvider implements CacheProviderInterface
{
    /**
     * @var string
     */
    private $cacheDir;

    public function __construct(string $cacheDir)
    {
        $this->cacheDir = $cacheDir;
    }

    public function getCachePool(string $scope): CacheItemPoolInterface
    {
        return new FilesystemAdapter($scope, 0, $this->cacheDir);
    }
}
