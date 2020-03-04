<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use InvalidArgumentException;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Metadata\Statement\AttestationConstant;
use PHPUnit\Framework\TestCase;

class AttestationConstantTest extends TestCase
{
    public function testConvertType()
    {
        $this->assertSame(AttestationConstant::TAG_ATTESTATION_BASIC_FULL, AttestationConstant::convertType(AttestationType::BASIC));
    }

    public function testInvalidType()
    {
        $this->expectException(InvalidArgumentException::class);
        AttestationConstant::convertType('invalid');
    }
}
