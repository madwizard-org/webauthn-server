<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Fido;

use MadWizard\WebAuthn\Attestation\Fido\FidoAaguidExtension;
use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Pki\CertificateDetails;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class FidoAaguidExtensionTest extends TestCase
{
    private function getData(string $name): CertificateDetails
    {
        $json = FixtureHelper::getJsonFixture('Pki/testcertificates.json');
        return CertificateDetails::fromPem($json[$name]);
    }

    public function testExtension()
    {
        $cert = $this->getData('example.com');

        // no extension - no check
        FidoAaguidExtension::checkAaguidExtension($cert, new Aaguid(ByteBuffer::fromHex('00000000000000000000000000000000')));
        $this->assertTrue(true);
    }

    public function testPacked()
    {
        $cert = $this->getData('packedAttestation');
        FidoAaguidExtension::checkAaguidExtension($cert, new Aaguid(ByteBuffer::fromHex('42383245443733433846423445354132')));
        $this->assertTrue(true);
    }

    public function testNoMatch()
    {
        $cert = $this->getData('packedAttestation');
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('~does not match the AAGUID~i');
        FidoAaguidExtension::checkAaguidExtension($cert, new Aaguid(ByteBuffer::fromHex('22222222222222222246423445354132')));
        $this->assertTrue(true);
    }

    public function testWrongFidoExtensionType()
    {
        $cert = $this->getData('wrongFidoExtType');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~failed to parse AAGUID extension~i');
        FidoAaguidExtension::checkAaguidExtension($cert, new Aaguid(ByteBuffer::fromHex('42383245443733433846423445354132')));
    }

    public function testFidoExtensionNonCritical()
    {
        $cert = $this->getData('fidoCritical');
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessageMatches('~must not be critical~i');
        FidoAaguidExtension::checkAaguidExtension($cert, new Aaguid(ByteBuffer::fromHex('42383245443733433846423445354132')));
    }
}
