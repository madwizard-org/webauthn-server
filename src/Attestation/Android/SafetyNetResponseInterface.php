<?php


namespace MadWizard\WebAuthn\Attestation\Android;

interface SafetyNetResponseInterface
{
    public function getNonce() : string;

    /**
     * @return string[]
     */
    public function getCertificateChain(): array;

    public function isCtsProfileMatch(): bool;
}
