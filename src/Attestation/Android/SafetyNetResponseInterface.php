<?php

namespace MadWizard\WebAuthn\Attestation\Android;

use MadWizard\WebAuthn\Pki\X509Certificate;

interface SafetyNetResponseInterface
{
    public function getNonce(): string;

    /**
     * @return int|float
     */
    public function getTimestampMs();

    /**
     * @return X509Certificate[]
     */
    public function getCertificateChain(): array;

    public function isCtsProfileMatch(): bool;
}
