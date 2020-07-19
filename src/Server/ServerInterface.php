<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Exception\CredentialIdExistsException;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationContext;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationRequest;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationResult;
use MadWizard\WebAuthn\Server\Registration\RegistrationContext;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationRequest;
use MadWizard\WebAuthn\Server\Registration\RegistrationResult;

interface ServerInterface
{
    public function startRegistration(RegistrationOptions $options): RegistrationRequest;

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     *
     * @throws CredentialIdExistsException
     */
    public function finishRegistration($credential, RegistrationContext $context): RegistrationResult;

    public function startAuthentication(AuthenticationOptions $options): AuthenticationRequest;

    /**
     * @param PublicKeyCredentialInterface|string $credential object or JSON serialized representation from the client.
     */
    public function finishAuthentication($credential, AuthenticationContext $context): AuthenticationResult;
}
