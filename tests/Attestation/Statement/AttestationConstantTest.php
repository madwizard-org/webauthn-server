<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Metadata\Statement\AttestationConstant;
use PHPUnit\Framework\TestCase;

class AttestationConstantTest extends TestCase
{
    public function testConvertType()
    {
        self::assertSame(AttestationConstant::TAG_ATTESTATION_BASIC_FULL, AttestationConstant::convertType(AttestationType::BASIC));
        self::assertNull(AttestationConstant::convertType(AttestationType::NONE));
    }

    public function testUnknownType()
    {
        self::assertNull(AttestationConstant::convertType('invalid'));
    }
}
