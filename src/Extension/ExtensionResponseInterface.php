<?php

namespace MadWizard\WebAuthn\Extension;

use MadWizard\WebAuthn\Exception\NotAvailableException;

interface ExtensionResponseInterface
{
    /**
     * Returns the extension identifier.
     */
    public function getIdentifier(): string;

    /**
     * Returns true if client extension output is present
     * (from PublicKeyCredential.clientExtensionResults).
     */
    public function hasClientExtensionOutput(): bool;

    /**
     * Returns the extensions's output from PublicKeyCredential.clientExtensionResults (JSON, with associative arrays).
     *
     * @return mixed
     *
     * @throws NotAvailableException
     */
    public function getClientExtensionOutput();

    /**
     * Returns true if authenticator extension output is present (from AuthenticatorData).
     */
    public function hasAuthenticatorExtensionOutput(): bool;

    /**
     * Returns the extension's output from AuthenticatorData (as decoded CBOR).
     *
     * @return mixed
     *
     * @throws NotAvailableException
     */
    public function getAuthenticatorExtensionOutput();
}
