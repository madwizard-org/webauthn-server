<?php


namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\CBOREncoder;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class NoneAttestationStatementTest extends TestCase
{
    public function testNoneStatement()
    {
        $attObj = FixtureHelper::getTestObject('none');

        $statement = new NoneAttestationStatement($attObj);

        // Valid when no exceptions thrown

        $this->assertSame('none', $statement->getFormatId());
    }

    public function testInvalidStatement()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~expecting empty map~i');
        $invalid = new AttestationObject(
            new ByteBuffer(
                CBOREncoder::encodeMapValues([
                    CBOREncoder::encodeTextString('fmt') => CBOREncoder::encodeTextString('none'),
                    CBOREncoder::encodeTextString('attStmt') => CBOREncoder::encodeMap(['a' => 'b']),
                    CBOREncoder::encodeTextString('authData') => CBOREncoder::encodeByteString(new ByteBuffer('')),
                ])
            )
        );
        new NoneAttestationStatement($invalid);
    }

    public function testCreateFormat()
    {
        $format = NoneAttestationStatement::createFormat();
        $this->assertSame(NoneAttestationStatement::FORMAT_ID, $format->getFormatId());
    }
}
