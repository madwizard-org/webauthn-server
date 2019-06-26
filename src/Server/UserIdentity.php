<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Credential\UserHandle;

class UserIdentity
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

    /**
     * @return UserHandle
     */
    public function getUserHandle(): UserHandle
    {
        return $this->userHandle;
    }

    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getDisplayName(): string
    {
        return $this->displayName;
    }
}
