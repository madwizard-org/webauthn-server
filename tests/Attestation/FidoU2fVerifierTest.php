<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\FidoU2fAttestationVerifier;
use MadWizard\WebAuthn\Exception\VerificationException;

class FidoU2fVerifierTest extends VerifierTest
{
    /**
     * @var FidoU2fAttestationVerifier
     */
    private $verifier;

    protected function setUp(): void
    {
        $this->verifier = new FidoU2fAttestationVerifier();
    }

    public function testFidoU2f()
    {
        $response = $this->getFidoResponse('challengeResponseAttestationU2fMsgB64Url');
        $buffer = $response->getAttestationObject();

        $att = AttestationObject::parse($buffer);
        $statement = new FidoU2fAttestationStatement($att);

        $result = $this->verifier->verify(
            $statement,
            new AuthenticatorData($att->getAuthenticatorData()),
            hash('sha256', $response->getClientDataJson(), true)
        );

        self::assertSame(AttestationType::BASIC, $result->getAttestationType());
        self::assertInstanceOf(CertificateTrustPath::class, $result->getTrustPath());
        $path = $result->getTrustPath();
        /*
         * @var CertificateTrustPath $path
         */
        self::assertCount(1, $path->getCertificates());
        self::assertStringContainsString('XPyTKmyvroUpl3LtsCeCAgPNQUHT7rb2os6Z45V4AyY6urjW', $path->asPemList()[0]);
    }

    public function testFidoU2fHypersecu()
    {
        $response = $this->getFidoResponse('challengeResponseAttestationU2fHypersecuB64UrlMsg');
        $buffer = $response->getAttestationObject();

        $att = AttestationObject::parse($buffer);
        $statement = new FidoU2fAttestationStatement($att);

        $result = $this->verifier->verify(
            $statement,
            new AuthenticatorData($att->getAuthenticatorData()),
            hash('sha256', $response->getClientDataJson(), true)
        );

        self::assertSame(AttestationType::BASIC, $result->getAttestationType());
        self::assertInstanceOf(CertificateTrustPath::class, $result->getTrustPath());
        $path = $result->getTrustPath();
        /*
         * @var CertificateTrustPath $path
         */
        self::assertCount(1, $path->getCertificates());
        self::assertStringContainsString('AAIjLWZXR95+CztkDiGfPlfcJLrt5RaAwBJnOnAodXJuiGGmkoYD', $path->asPemList()[0]);
    }

    public function testFidoU2fWrongHash()
    {
        $response = $this->getFidoResponse('challengeResponseAttestationU2fMsgB64Url');
        $buffer = $response->getAttestationObject();

        $att = AttestationObject::parse($buffer);
        $statement = new FidoU2fAttestationStatement($att);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('~signature~i');
        $this->verifier->verify($statement, new AuthenticatorData($att->getAuthenticatorData()), hash('sha256', '123', true));
    }

    public function testFidoWrongType()
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('~expecting.+fido~i');
        $this->verifier->verify(
            $this->createMock(NoneAttestationStatement::class),
            $this->getTestAuthenticatorData(),
            hash('sha256', '123', true)
        );
    }

    public function testCreateFormat()
    {
        $this->checkFormat($this->verifier, FidoU2fAttestationStatement::class);
    }
}
