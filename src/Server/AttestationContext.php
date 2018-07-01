<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Web\Origin;

class AttestationContext
{
    /**
     * @var Origin
     */
    private $origin;

    /**
     * @var ByteBuffer
     */
    private $challenge;

    /**
     * @var string
     */
    private $rpId;

    /**
     * @var bool
     */
    private $userVerificationRequired;

    private function __construct()
    {
    }

    public static function create(PublicKeyCredentialCreationOptions $options, WebAuthnConfiguration $configuration) : AttestationContext
    {
        $context = new self();

        $context->challenge = $options->getChallenge();

        $context->origin = $configuration->getRelyingPartyOrigin();
        if ($context->origin === null) {
            throw new ConfigurationException('Could not determine relying party origin.');
        }

        $rpId = $options->getRpEntity()->getId();
        if ($rpId === null) {
            $rpId = $configuration->getEffectiveReyingPartyId();
        }

        $context->rpId = $rpId;

        $context->userVerificationRequired = false;
        $authSel = $options->getAuthenticatorSelection();
        if ($authSel !== null && $authSel->getUserVerification() === UserVerificationRequirement::REQUIRED) {
            $context->userVerificationRequired = true;
        }

        return $context;
    }

    /**
     * @return Origin
     */
    public function getOrigin(): Origin
    {
        return $this->origin;
    }

    /**
     * @return ByteBuffer
     */
    public function getChallenge(): ByteBuffer
    {
        return $this->challenge;
    }

    /**
     * @return string
     */
    public function getRpId(): string
    {
        return $this->rpId;
    }

    /**
     * @return bool
     */
    public function isUserVerificationRequired(): bool
    {
        return $this->userVerificationRequired;
    }
}
