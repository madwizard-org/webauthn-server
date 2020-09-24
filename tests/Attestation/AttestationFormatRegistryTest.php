<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Attestation\Registry\BuiltInAttestationFormat;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\AttestationVerifierInterface;
use MadWizard\WebAuthn\Exception\FormatNotSupportedException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborMap;
use PHPUnit\Framework\TestCase;

class AttestationFormatRegistryTest extends TestCase
{
    private $verifier1;

    private $verifier2;

    private function getRegistry(): AttestationFormatRegistry
    {
        $registry = new AttestationFormatRegistry();

        $this->verifier1 = $this->createMock(AttestationVerifierInterface::class);
        $this->verifier2 = $this->createMock(AttestationVerifierInterface::class);
        $format1 = new BuiltInAttestationFormat(
            'format1',
            $this->getMockClass(AttestationStatementInterface::class, [], [], 'TestFormat1Statement'),
            $this->verifier1
        );
        $registry->addFormat($format1);

        $format2 = new BuiltInAttestationFormat(
            'format2',
            $this->getMockClass(AttestationStatementInterface::class, [], [], 'TestFormat2Statement'),
            $this->verifier2
        );
        $registry->addFormat($format2);

        return $registry;
    }

    public function testStatementFormats()
    {
        $registry = $this->getRegistry();
        $attObj = new AttestationObject('format1', new CborMap(), new ByteBuffer(''));

        self::assertInstanceOf('TestFormat1Statement', $registry->createStatement($attObj));

        $attObj2 = new AttestationObject('format2', new CborMap(), new ByteBuffer(''));

        self::assertInstanceOf('TestFormat2Statement', $registry->createStatement($attObj2));
    }

    public function testVerifierFormats()
    {
        $registry = $this->getRegistry();
        self::assertSame($this->verifier1, $registry->getVerifier('format1'));
        self::assertSame($this->verifier2, $registry->getVerifier('format2'));
    }

    public function testNotSupportedStatement()
    {
        $this->expectException(FormatNotSupportedException::class);

        $registry = $this->getRegistry();
        $attObj = new AttestationObject('unsupported', new CborMap(), new ByteBuffer(''));
        $registry->createStatement($attObj);
    }

    public function testNotSupportedVerifer()
    {
        $this->expectException(FormatNotSupportedException::class);

        $registry = $this->getRegistry();

        $registry->getVerifier('unsupported');
    }
}
