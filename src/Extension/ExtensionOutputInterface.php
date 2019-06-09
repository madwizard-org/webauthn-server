<?php


namespace MadWizard\WebAuthn\Extension;

interface ExtensionOutputInterface
{
    public function getIdentifier(): string;

    public function getOutput();
}
