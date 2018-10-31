<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Attestation\Verifier\PackedAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class PackedStatementVerifierTest extends TestCase
{
    public function testPacked()
    {
        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationPackedB64UrlMsg');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationPackedB64UrlMsg');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new PackedAttestationStatement($attObj);

        $verifier = new PackedAttestationVerifier(new CertificateParser());
        $result = $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        $this->assertSame(AttestationType::BASIC, $result->getAttestationType());
        // TODO: check trust path
    }
}
