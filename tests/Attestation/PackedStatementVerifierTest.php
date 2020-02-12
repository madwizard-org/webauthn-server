<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\AuthenticatorDataInterface;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\EmptyTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\PackedAttestationVerifier;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Pki\CertificateParser;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use function hash;

class PackedStatementVerifierTest extends VerifierTest
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

    public function testSelfSurrogate()
    {
        $clientResponse = FixtureHelper::getTestPlain('packed-surrogate');
        $attObj = new AttestationObject(ByteBuffer::fromBase64Url($clientResponse['response']['attestationObject']));

        $hash = hash('sha256', Base64UrlEncoding::decode($clientResponse['response']['clientDataJSON']), true);
        $statement = new PackedAttestationStatement($attObj);

        $verifier = new PackedAttestationVerifier();
        $result = $verifier->verify($statement, new AuthenticatorData($attObj->getAuthenticatorData()), $hash);

        $this->assertSame(AttestationType::SELF, $result->getAttestationType());
        $this->assertInstanceOf(EmptyTrustPath::class, $result->getTrustPath());
    }

    public function testWrongType()
    {
        $verifier = new PackedAttestationVerifier();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~expecting.+packed~i');
        $verifier->verify(
            $this->createMock(NoneAttestationStatement::class),
            $this->createMock(AuthenticatorDataInterface::class),
            hash('sha256', '123', true)
        );
    }

    public function testECDAAUnsupported()
    {
        $verifier = new PackedAttestationVerifier();

        $this->expectException(UnsupportedException::class);

        $statement = $this->createMock(PackedAttestationStatement::class);
        $statement->expects($this->once())->method('getEcdaaKeyId')->willReturn(new ByteBuffer('12345678'));
        $verifier->verify(
            $statement,
            $this->createMock(AuthenticatorDataInterface::class),
            hash('sha256', '123', true)
        );
    }
}
