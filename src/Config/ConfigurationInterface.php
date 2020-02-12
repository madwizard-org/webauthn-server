<?php


namespace MadWizard\WebAuthn\Config;

interface ConfigurationInterface
{
    public function getChallengeLength(): int;

    public function getAllowedAlgorithms() : array;
}
