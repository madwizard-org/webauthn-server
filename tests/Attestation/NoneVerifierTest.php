<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\NoneAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;

class NoneVerifierTest extends VerifierTest
{
    public function testNone()
    {
        $statements = FixtureHelper::getJsonFixture('Statement/statements.json');
        $attObject = new AttestationObject(new ByteBuffer(Base64UrlEncoding::decode($statements['none'])));

        $verifier = new NoneAttestationVerifier();
        $statement = new NoneAttestationStatement($attObject);
        $result = $verifier->verify($statement, $this->createMock(AuthenticatorData::class), hash('sha256', '123', true));
        $this->assertSame(AttestationType::NONE, $result->getAttestationType());
        $this->assertInstanceOf(EmptyTrustPath::class, $result->getTrustPath());
    }
}
