<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class AbstractAttestationStatementTest extends TestCase
{
    public function testWrongFormat()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~not expecting format~i');

        $attObj = FixtureHelper::getTestObject('none');

        new FidoU2fAttestationStatement($attObj);
    }
}
