<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInAttestationFormat;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\AttestationVerifierInterface;
use MadWizard\WebAuthn\Exception\FormatNotSupportedException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class AttestationFormatRegistryTest extends TestCase
{
    private function getRegistry(): AttestationFormatRegistry
    {
        $registry = new AttestationFormatRegistry();

        $format1 = new BuiltInAttestationFormat(
            'format1',
            $this->getMockClass(AttestationStatementInterface::class, [], [], 'TestFormat1Statement'),
            $this->getMockClass(AttestationVerifierInterface::class, [], [], 'TestFormat1Verifier')
        );
        $registry->addFormat($format1);

        $format2 = new BuiltInAttestationFormat(
            'format2',
            $this->getMockClass(AttestationStatementInterface::class, [], [], 'TestFormat2Statement'),
            $this->getMockClass(AttestationVerifierInterface::class, [], [], 'TestFormat2Verifier')
        );
        $registry->addFormat($format2);

        return $registry;
    }

    public function testStatementFormats()
    {
        $registry = $this->getRegistry();
        $attObj = new AttestationObject('format1', [], new ByteBuffer(''));

        $this->assertInstanceOf('TestFormat1Statement', $registry->createStatement($attObj));

        $attObj2 = new AttestationObject('format2', [], new ByteBuffer(''));

        $this->assertInstanceOf('TestFormat2Statement', $registry->createStatement($attObj2));
    }

    public function testVerifierFormats()
    {
        $registry = $this->getRegistry();
        $this->assertInstanceOf('TestFormat1Verifier', $registry->getVerifier('format1'));
        $this->assertInstanceOf('TestFormat2Verifier', $registry->getVerifier('format2'));
    }

    public function testNotSupportedStatement()
    {
        $this->expectException(FormatNotSupportedException::class);

        $registry = $this->getRegistry();
        $attObj = new AttestationObject('unsupported', [], new ByteBuffer(''));
        $registry->createStatement($attObj);
    }

    public function testNotSupportedVerifer()
    {
        $this->expectException(FormatNotSupportedException::class);

        $registry = $this->getRegistry();

        $registry->getVerifier('unsupported');
    }
}
