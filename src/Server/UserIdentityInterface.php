<?php

namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Credential\UserHandle;

interface UserIdentityInterface
{
    public function getUserHandle(): UserHandle;

    public function getUsername(): string;

    public function getDisplayName(): string;
}
