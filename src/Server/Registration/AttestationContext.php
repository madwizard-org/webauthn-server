<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\AbstractContext;
use MadWizard\WebAuthn\Server\RequestContext;
use MadWizard\WebAuthn\Web\Origin;

class AttestationContext extends AbstractContext implements RequestContext
{
    /**
     * @var ByteBuffer
     */
    private $userHandle;

    public function __construct(ByteBuffer $challenge, Origin $origin, string $rpId, ByteBuffer $userHandle)
    {
        parent::__construct($challenge, $origin, $rpId);
        $this->userHandle = $userHandle;
    }

    public static function create(PublicKeyCredentialCreationOptions $options, WebAuthnConfiguration $configuration) : self
    {
        $origin = $configuration->getRelyingPartyOrigin();
        if ($origin === null) {
            throw new ConfigurationException('Could not determine relying party origin.');
        }

        $rpId = $options->getRpEntity()->getId();
        if ($rpId === null) {
            $rpId = $configuration->getEffectiveRelyingPartyId();
        }

        $context = new self($options->getChallenge(), $origin, $rpId, $options->getUserEntity()->getId());

        $authSel = $options->getAuthenticatorSelection();
        if ($authSel !== null && $authSel->getUserVerification() === UserVerificationRequirement::REQUIRED) {
            $context->setUserVerificationRequired(true);
        }

        return $context;
    }

    public function getUserHandle() : ByteBuffer
    {
        return $this->userHandle;
    }

    public function serialize()
    {
        return \serialize([$this->userHandle, parent::serialize()]);
    }

    public function unserialize($serialized)
    {
        [$this->userHandle, $parentStr] = \unserialize((string) $serialized);
        parent::unserialize($parentStr);
    }
}
