<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CborEncoder;
use MadWizard\WebAuthn\Format\CborMap;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class NoneAttestationStatementTest extends TestCase
{
    public function testNoneStatement()
    {
        $attObj = FixtureHelper::getTestObject('none');

        $statement = new NoneAttestationStatement($attObj);

        // Valid when no exceptions thrown

        self::assertSame('none', $statement->getFormatId());
    }

    public function testInvalidStatement()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~expecting empty map~i');
        $invalid = AttestationObject::parse(
            new ByteBuffer(
                CborEncoder::encodeMap(CborMap::fromArray(
                    [
                        'fmt' => 'none',
                        'attStmt' => CborMap::fromArray(['a' => 'b']),
                        'authData' => new ByteBuffer(''),
                    ])
                )
            )
        );
        new NoneAttestationStatement($invalid);
    }
}
