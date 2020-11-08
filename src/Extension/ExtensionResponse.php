<?php

namespace MadWizard\WebAuthn\Extension;

use MadWizard\WebAuthn\Exception\NotAvailableException;

final class ExtensionResponse implements ExtensionResponseInterface
{
    /**
     * @var bool
     */
    private $hasClientExtensionOutput = false;

    /**
     * @var mixed
     */
    private $clientExtensionOutput;

    /**
     * @var bool
     */
    private $hasAuthenticatorExtensionOutput = false;

    /**
     * @var mixed
     */
    private $authenticatorExtensionOutput;

    /**
     * @var string
     */
    private $identifier;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function hasClientExtensionOutput(): bool
    {
        return $this->hasClientExtensionOutput;
    }

    public function getClientExtensionOutput()
    {
        return $this->clientExtensionOutput;
    }

    public function hasAuthenticatorExtensionOutput(): bool
    {
        if (!$this->hasClientExtensionOutput) {
            throw new NotAvailableException(sprintf('No client extension output is available for extension "%s".', $this->identifier));
        }
        return $this->hasAuthenticatorExtensionOutput;
    }

    public function getAuthenticatorExtensionOutput()
    {
        if (!$this->hasAuthenticatorExtensionOutput) {
            throw new NotAvailableException(sprintf('No authenticator extension output is available for extension "%s".', $this->identifier));
        }
        return $this->authenticatorExtensionOutput;
    }

    /**
     * @param mixed $clientExtensionOutput
     */
    public function setClientExtensionOutput($clientExtensionOutput): void
    {
        $this->hasClientExtensionOutput = true;
        $this->clientExtensionOutput = $clientExtensionOutput;
    }

    /**
     * @param mixed $authenticatorExtensionOutput
     */
    public function setAuthenticatorExtensionOutput($authenticatorExtensionOutput): void
    {
        $this->hasAuthenticatorExtensionOutput = true;
        $this->authenticatorExtensionOutput = $authenticatorExtensionOutput;
    }
}
