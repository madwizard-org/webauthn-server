<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Credential\UserHandle;

interface UserIdentityInterface
{
    /**
     * @return UserHandle
     */
    public function getUserHandle(): UserHandle;

    /**
     * @return string
     */
    public function getUsername(): string;

    /**
     * @return string
     */
    public function getDisplayName(): string;
}
