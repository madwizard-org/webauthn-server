<?php

namespace MadWizard\WebAuthn\Extension\AppId;

use MadWizard\WebAuthn\Extension\AbstractExtensionInput;

class AppIdExtensionInput extends AbstractExtensionInput
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
