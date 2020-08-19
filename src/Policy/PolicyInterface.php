<?php

namespace MadWizard\WebAuthn\Policy;

interface PolicyInterface
{
    public function isUserPresenceRequired(): bool;

    public function getChallengeLength(): int;

    public function getAllowedAlgorithms(): array;
}
