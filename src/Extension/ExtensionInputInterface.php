<?php


namespace MadWizard\WebAuthn\Extension;

interface ExtensionInputInterface
{
    public function getIdentifier(): string;

    public function getInput();
}
