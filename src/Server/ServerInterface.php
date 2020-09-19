<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialInterface;
use MadWizard\WebAuthn\Exception\CredentialIdExistsException;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationContext;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationRequest;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationResultInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationContext;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationRequest;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

interface ServerInterface
{
    public function startRegistration(RegistrationOptions $options): RegistrationRequest;

    /**
     * @param PublicKeyCredentialInterface $credential Attestation credential response from the client
     *
     * @throws CredentialIdExistsException
     */
    public function finishRegistration(PublicKeyCredentialInterface $credential, RegistrationContext $context): RegistrationResultInterface;

    public function startAuthentication(AuthenticationOptions $options): AuthenticationRequest;

    /**
     * @param PublicKeyCredentialInterface $credential Assertion credential response from the client
     */
    public function finishAuthentication(PublicKeyCredentialInterface $credential, AuthenticationContext $context): AuthenticationResultInterface;
}
