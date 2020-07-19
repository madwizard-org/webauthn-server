<?php

namespace MadWizard\WebAuthn\Cache;

use Psr\Cache\CacheItemPoolInterface;

interface CacheProviderInterface
{
    public function getCachePool(string $scope): CacheItemPoolInterface;
}
