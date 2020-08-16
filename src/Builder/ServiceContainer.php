<?php

namespace MadWizard\WebAuthn\Builder;

use ArrayAccess;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;

/**
 * @implements ArrayAccess<string, object>
 */
class ServiceContainer implements ArrayAccess
{
    /**
     * @phpstan-var array<class-string, object>
     *
     * @var object[]
     */
    private $serviceMap = [];

    /**
     * @phpstan-var array<class-string, callable(self): object>
     *
     * @var callable[]
     */
    private $instantiators = [];

    /**
     * @param string $offset
     * @param string $offset
     * @phpstan-param class-string $offset
     *
     * @return bool
     */
    public function offsetExists($offset)
    {
        return isset($this->serviceMap[$offset]) || isset($this->instantiators[$offset]);
    }

    /**
     * @template T of object
     *
     * @param string $service
     * @phpstan-param class-string<T> $service
     * @phpstan-return T
     */
    public function offsetGet($service)
    {
        /**
         * @phpstan-var T
         */
        $service = ($this->serviceMap[$service] ?? $this->instantiate($service));
        return $service;
    }

    /**
     * @param string $offset
     */
    public function offsetUnset($offset)
    {
        throw new RuntimeException('Unset operation is not supported.');
    }

    /**
     * @param string   $offset
     * @param callable $value
     * @phpstan-param class-string $offset
     * @phpstan-param callable(self): object $value
     */
    public function offsetSet($offset, $value)
    {
        $this->instantiators[$offset] = $value;
    }

    /**
     * @template T of object
     * @phpstan-param class-string<T> $offset
     * @phpstan-return T of object
     */
    private function instantiate(string $offset): object
    {
        $instantiator = $this->instantiators[$offset] ?? null;
        if ($instantiator === null) {
            throw new WebAuthnException(sprintf('Missing service %s.', $offset));
        }
        /**
         * @phpstan-var T
         */
        $service = $instantiator($this);
        $this->serviceMap[$offset] = $service;

        if ($service instanceof LoggerAwareInterface) {
            $service->setLogger($this[LoggerInterface::class]);
        }
        // Free instantatior resources:
        unset($this->instantiators[$offset]);
        return $service;
    }
}
