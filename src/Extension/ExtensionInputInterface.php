<?php

namespace MadWizard\WebAuthn\Extension;

use Serializable;

interface ExtensionInputInterface extends Serializable
{
    public function getIdentifier(): string;

    public function getInput();
}
