<?php


namespace MadWizard\WebAuthn\Server\Registration;

use MadWizard\WebAuthn\Config\ConfigurationInterface;
use MadWizard\WebAuthn\Config\RelyingPartyInterface;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
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

    // TODO: remove configuration
    public static function create(PublicKeyCredentialCreationOptions $options, ConfigurationInterface $configuration, RelyingPartyInterface $rp) : self
    {
        $origin = $rp->getOrigin();
        $rpId = $rp->getEffectiveId();

        // TODO: mismatch $rp and rp in $options? Check?
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
