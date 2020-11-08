<?php

namespace MadWizard\WebAuthn\Extension;

use Serializable;

interface ExtensionInputInterface extends Serializable
{
    public function getIdentifier(): string;

    /**
     * @return mixed
     */
    public function getInput();
}
