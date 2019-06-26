<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Config\WebAuthnConfigurationInterface;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\AbstractContext;
use MadWizard\WebAuthn\Server\RequestContext;
use MadWizard\WebAuthn\Web\Origin;

class RegistrationContext extends AbstractContext implements RequestContext
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

    public static function create(PublicKeyCredentialCreationOptions $options, WebAuthnConfigurationInterface $configuration) : self
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

        $context->setUserPresenceRequired($configuration->isUserPresenceRequired());
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
        return \serialize([parent::serialize(), clone $this->userHandle]);
    }

    public function unserialize($serialized)
    {
        [ $parentStr,$this->userHandle] = \unserialize((string) $serialized);
        parent::unserialize($parentStr);
    }
}
