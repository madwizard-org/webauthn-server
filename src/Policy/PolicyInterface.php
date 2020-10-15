<?php

namespace MadWizard\WebAuthn\Policy;

use MadWizard\WebAuthn\Crypto\CoseAlgorithm;

interface PolicyInterface
{
    public function isUserPresenceRequired(): bool;

    public function getChallengeLength(): int;

    /**
     * @return int[]
     *
     * @see CoseAlgorithm
     */
    public function getAllowedAlgorithms(): array;
}
