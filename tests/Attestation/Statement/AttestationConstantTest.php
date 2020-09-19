<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Metadata\Statement\AttestationConstant;
use PHPUnit\Framework\TestCase;

class AttestationConstantTest extends TestCase
{
    public function testConvertType()
    {
        $this->assertSame(AttestationConstant::TAG_ATTESTATION_BASIC_FULL, AttestationConstant::convertType(AttestationType::BASIC));
        $this->assertNull(AttestationConstant::convertType(AttestationType::NONE));
    }

    public function testUnknownType()
    {
        $this->assertNull(AttestationConstant::convertType('invalid'));
    }
}
