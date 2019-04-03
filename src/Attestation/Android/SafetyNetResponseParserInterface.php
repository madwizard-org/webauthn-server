<?php


namespace MadWizard\WebAuthn\Attestation\Android;

interface SafetyNetResponseParserInterface
{
    public function parse(string $response): SafetyNetResponseInterface;
}
