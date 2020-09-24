<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\PackedAttestationVerifier;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use function hash;

class PackedStatementVerifierTest extends VerifierTest
{
    /**
     * @var PackedAttestationVerifier
     */
    private $verifier;

    protected function setUp(): void
    {
        $this->verifier = new PackedAttestationVerifier();
    }

    public function testPacked()
    {
        $plain = FixtureHelper::getFidoTestPlain('challengeResponseAttestationPackedB64UrlMsg');
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationPackedB64UrlMsg');

        $hash = hash('sha256', Base64UrlEncoding::decode($plain['response']['clientDataJSON']), true);
        $statement = new PackedAttestationStatement($attObj);

        $result = $this->verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        self::assertSame(AttestationType::BASIC, $result->getAttestationType());
        // TODO: check trust path
    }

    public function testSelfSurrogate()
    {
        $clientResponse = FixtureHelper::getTestPlain('packed-surrogate');
        $attObj = AttestationObject::parse(ByteBuffer::fromBase64Url($clientResponse['response']['attestationObject']));

        $hash = hash('sha256', Base64UrlEncoding::decode($clientResponse['response']['clientDataJSON']), true);
        $statement = new PackedAttestationStatement($attObj);

        $result = $this->verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        self::assertSame(AttestationType::SELF, $result->getAttestationType());
        self::assertInstanceOf(EmptyTrustPath::class, $result->getTrustPath());
    }

    public function testWrongType()
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('~expecting.+packed~i');
        $this->verifier->verify(
            $this->createMock(NoneAttestationStatement::class),
            $this->getTestAuthenticatorData(),
            hash('sha256', '123', true)
        );
    }

    public function testECDAAUnsupported()
    {
        $this->expectException(UnsupportedException::class);

        $statement = $this->createMock(PackedAttestationStatement::class);
        $statement->expects($this->once())->method('getEcdaaKeyId')->willReturn(new ByteBuffer('12345678'));
        $this->verifier->verify(
            $statement,
            $this->getTestAuthenticatorData(),
            hash('sha256', '123', true)
        );
    }

    public function testCreateFormat()
    {
        $this->checkFormat($this->verifier, PackedAttestationStatement::class);
    }
}
