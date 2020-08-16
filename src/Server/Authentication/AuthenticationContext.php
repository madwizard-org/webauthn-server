<?php

namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialRequestOptions;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Policy\PolicyInterface;
use MadWizard\WebAuthn\Server\AbstractContext;
use MadWizard\WebAuthn\Server\RequestContext;
use MadWizard\WebAuthn\Web\Origin;

class AuthenticationContext extends AbstractContext implements RequestContext
{
    /**
     * @var ByteBuffer[]
     */
    private $allowCredentialIds = [];

    public function __construct(ByteBuffer $challenge, Origin $origin, string $rpId)
    {
        parent::__construct($challenge, $origin, $rpId);
    }

    public function addAllowCredentialId(ByteBuffer $buffer)
    {
        $this->allowCredentialIds[] = $buffer;
    }

    /**
     * @internal TODO: do not include here?
     */
    public static function create(PublicKeyCredentialRequestOptions $options, PolicyInterface $policy): self
    {
        $relyingParty = $policy->getRelyingParty();
        $origin = $relyingParty->getOrigin();
        $rpId = $relyingParty->getEffectiveId();

        // TODO: mismatch $rp and rp in $policy? Check?
        $context = new self($options->getChallenge(), $origin, $rpId);

        if ($options->getUserVerification() === UserVerificationRequirement::REQUIRED) {
            $context->setUserVerificationRequired(true);
        }

        $context->setUserPresenceRequired($policy->isUserPresenceRequired());

        $allowCredentials = $options->getAllowCredentials();
        if ($allowCredentials !== null) {
            foreach ($allowCredentials as $credential) {
                $context->addAllowCredentialId($credential->getId());
            }
        }
        return $context;
    }

    /**
     * @return ByteBuffer[]
     */
    public function getAllowCredentialIds(): array
    {
        return $this->allowCredentialIds;
    }

    public function __serialize(): array
    {
        return [
            'parent' => parent::__serialize(),
            'allowCredentialIds' => $this->allowCredentialIds,
        ];
    }

    public function __unserialize(array $data): void
    {
        parent::__unserialize($data['parent']);
        $this->allowCredentialIds = $data['allowCredentialIds'];
    }
}
