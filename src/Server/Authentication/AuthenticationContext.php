<?php

namespace MadWizard\WebAuthn\Server\Authentication;

use MadWizard\WebAuthn\Format\ByteBuffer;
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
