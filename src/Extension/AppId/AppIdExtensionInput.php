<?php

namespace MadWizard\WebAuthn\Extension\AppId;

use MadWizard\WebAuthn\Extension\AbstractExtensionInput;
use MadWizard\WebAuthn\Extension\AuthenticationExtensionInputInterface;

class AppIdExtensionInput extends AbstractExtensionInput implements AuthenticationExtensionInputInterface
{
    public function __construct(string $appId)
    {
        parent::__construct('appid');
        $this->input = $appId;
    }

    public function getAppId(): string
    {
        return $this->input;
    }
}
