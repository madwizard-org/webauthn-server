<?php

namespace MadWizard\WebAuthn\Extension\AppId;

use MadWizard\WebAuthn\Extension\AbstractExtensionOutput;

class AppIdExtensionOutput extends AbstractExtensionOutput
{
    /**
     * @var bool
     */
    private $appIdUsed;

    public function __construct(bool $appIdUsed)
    {
        parent::__construct('appid');
        $this->appIdUsed = $appIdUsed;
    }

    public function getAppIdUsed(): bool
    {
        return $this->appIdUsed;
    }
}
