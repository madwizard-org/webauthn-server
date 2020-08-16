<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\NoneAttestationVerifier;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;

class NoneVerifierTest extends VerifierTest
{
    /**
     * @var NoneAttestationVerifier
     */
    private $verifier;

    protected function setUp(): void
    {
        $this->verifier = new NoneAttestationVerifier();
    }

    public function testNone()
    {
        $statements = FixtureHelper::getJsonFixture('Statement/statements.json');
        $attObject = AttestationObject::parse(new ByteBuffer(Base64UrlEncoding::decode($statements['none'])));

        $statement = new NoneAttestationStatement($attObject);
        $result = $this->verifier->verify($statement, $this->getTestAuthenticatorData(), hash('sha256', '123', true));
        $this->assertSame(AttestationType::NONE, $result->getAttestationType());
        $this->assertInstanceOf(EmptyTrustPath::class, $result->getTrustPath());
    }

    public function testCreateFormat()
    {
        $this->checkFormat($this->verifier, NoneAttestationStatement::class);
    }
}
