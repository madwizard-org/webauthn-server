<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Credential\UserHandle;

class UserIdentity implements UserIdentityInterface
{
    /**
     * @var UserHandle
     */
    private $userHandle;

    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $displayName;

    public function __construct(UserHandle $userHandle, string $username, string $displayName)
    {
        $this->userHandle = $userHandle;
        $this->username = $username;
        $this->displayName = $displayName;
    }

    public function getUserHandle(): UserHandle
    {
        return $this->userHandle;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }
}
