<?php


namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\AuthenticatorData;
use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\TrustPath\CertificateTrustPath;
use MadWizard\WebAuthn\Attestation\Verifier\FidoU2FStatementVerifier;
use MadWizard\WebAuthn\Exception\VerificationException;

class FidoU2fVerifierTest extends VerifierTest
{
    public function testFidoU2f()
    {
        $response = $this->getFidoResponse('challengeResponseAttestationU2fMsgB64Url');
        $buffer = $response->getAttestationObject();

        $att = new AttestationObject($buffer);
        $statement = new FidoU2fAttestationStatement($att);
        $verifier = new FidoU2FStatementVerifier();

        $result = $verifier->verify(
            $statement,
            new AuthenticatorData($att->getAuthenticatorData()),
            hash('sha256', $response->getClientDataJSON(), true)
        );

        $this->assertSame(AttestationType::BASIC, $result->getAttestationType());
        $this->assertInstanceOf(CertificateTrustPath::class, $result->getTrustPath());
        $path = $result->getTrustPath();
        /**
         * @var CertificateTrustPath $path
         */
        $this->assertCount(1, $path->getCertificates());
        $this->assertContains('XPyTKmyvroUpl3LtsCeCAgPNQUHT7rb2os6Z45V4AyY6urjW', $path->getCertificates()[0]);
    }

    public function testFidoU2fHypersecu()
    {
        $response = $this->getFidoResponse('challengeResponseAttestationU2fHypersecuB64UrlMsg');
        $buffer = $response->getAttestationObject();

        $att = new AttestationObject($buffer);
        $statement = new FidoU2fAttestationStatement($att);
        $verifier = new FidoU2FStatementVerifier();

        $result = $verifier->verify(
            $statement,
            new AuthenticatorData($att->getAuthenticatorData()),
            hash('sha256', $response->getClientDataJSON(), true)
        );

        $this->assertSame(AttestationType::BASIC, $result->getAttestationType());
        $this->assertInstanceOf(CertificateTrustPath::class, $result->getTrustPath());
        $path = $result->getTrustPath();
        /**
         * @var CertificateTrustPath $path
         */
        $this->assertCount(1, $path->getCertificates());
        $this->assertContains('AAIjLWZXR95+CztkDiGfPlfcJLrt5RaAwBJnOnAodXJuiGGmkoYD', $path->getCertificates()[0]);
    }

    public function testFidoU2fWrongHash()
    {
        $response = $this->getFidoResponse('challengeResponseAttestationU2fMsgB64Url');
        $buffer = $response->getAttestationObject();

        $att = new AttestationObject($buffer);
        $statement = new FidoU2fAttestationStatement($att);
        $verifier = new FidoU2FStatementVerifier();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~signature~i');
        $verifier->verify($statement, new AuthenticatorData($att->getAuthenticatorData()), hash('sha256', '123', true));
    }

    public function testFidoWrongType()
    {
        $verifier = new FidoU2FStatementVerifier();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageRegExp('~expecting.+fido~i');
        $verifier->verify(
            $this->createMock(NoneAttestationStatement::class),
            $this->createMock(AuthenticatorData::class),
            hash('sha256', '123', true)
        );
    }
}
