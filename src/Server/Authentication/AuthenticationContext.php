<?php

namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\AbstractContext;
use MadWizard\WebAuthn\Server\RequestContext;
use MadWizard\WebAuthn\Web\Origin;

final class AuthenticationContext extends AbstractContext implements RequestContext
{
    /**
     * @var CredentialId[]
     */
    private $allowCredentialIds = [];

    /**
     * @var UserHandle|null
     */
    private $userHandle;

    public function __construct(ByteBuffer $challenge, Origin $origin, string $rpId, ?UserHandle $userHandle)
    {
        parent::__construct($challenge, $origin, $rpId);
        $this->userHandle = $userHandle;
    }

    public function addAllowCredentialId(CredentialId $credentialId): void
    {
        $this->allowCredentialIds[] = $credentialId;
    }

    public function getUserHandle(): ?UserHandle
    {
        return $this->userHandle;
    }

    /**
     * @return CredentialId[]
     */
    public function getAllowCredentialIds(): array
    {
        return $this->allowCredentialIds;
    }

    public function __serialize(): array
    {
        return [
            'parent' => parent::__serialize(),
            'userHandle' => $this->userHandle,
            'allowCredentialIds' => $this->allowCredentialIds,
        ];
    }

    public function __unserialize(array $data): void
    {
        parent::__unserialize($data['parent']);
        $this->userHandle = $data['userHandle'];
        $this->allowCredentialIds = $data['allowCredentialIds'];
    }
}
