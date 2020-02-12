<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Config\ConfigurationInterface;
use MadWizard\WebAuthn\Credential\UserHandle;
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
     * @var UserHandle
     */
    private $userHandle;

    public function __construct(ByteBuffer $challenge, Origin $origin, string $rpId, UserHandle $userHandle)
    {
        parent::__construct($challenge, $origin, $rpId);
        $this->userHandle = $userHandle;
    }

    public static function create(PublicKeyCredentialCreationOptions $options, ConfigurationInterface $configuration) : self
    {
        $origin = $configuration->getRelyingPartyOrigin();
        if ($origin === null) {
            throw new ConfigurationException('Could not determine relying party origin.');
        }

        $rpId = $options->getRpEntity()->getId();
        if ($rpId === null) {
            $rpId = $configuration->getEffectiveRelyingPartyId();
        }

        $context = new self($options->getChallenge(), $origin, $rpId, UserHandle::fromBuffer($options->getUserEntity()->getId()));

        $context->setUserPresenceRequired($configuration->isUserPresenceRequired());
        $authSel = $options->getAuthenticatorSelection();
        if ($authSel !== null && $authSel->getUserVerification() === UserVerificationRequirement::REQUIRED) {
            $context->setUserVerificationRequired(true);
        }

        return $context;
    }

    public function getUserHandle() : UserHandle
    {
        return $this->userHandle;
    }

    public function __serialize(): array
    {
        return [
            'parent' => parent::__serialize(),
            'userHandle' => $this->userHandle,
        ];
    }

    public function __unserialize(array $data): void
    {
        parent::__unserialize($data['parent']);
        $this->userHandle = $data['userHandle'];
    }
}
