<?php


namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\Base64UrlEncoding;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class StatementTest extends TestCase
{
    private function getTestObject(string $key): AttestationObject
    {
        $statements = FixtureHelper::getJsonFixture('Statement/statements.json');
        return new AttestationObject(new ByteBuffer(Base64UrlEncoding::decode($statements[$key])));
    }

    public function testNoneStatement()
    {
        $attObj = $this->getTestObject('none');

        $statement = new NoneAttestationStatement($attObj);

        // Valid when no exceptions thrown

        $this->assertSame('none', $statement->getFormatId());
    }

    public function testFidoU2f()
    {
        $attObj = $this->getTestObject('fido-u2f');

        $statement = new FidoU2fAttestationStatement($attObj);

        $this->assertSame('fido-u2f', $statement->getFormatId());

        $certChain = $statement->getCertificates();

        $this->assertSame(
            [
                "-----BEGIN CERTIFICATE-----\n" .
                "MIIBMTCB2aADAgECAgUA4LY4HTAKBggqhkjOPQQDAjAhMR8wHQYDVQQDExZGaXJl\n" .
                "Zm94IFUyRiBTb2Z0IFRva2VuMB4XDTE4MDYxOTE0MDUwOVoXDTE4MDYyMTE0MDUw\n" .
                "OVowITEfMB0GA1UEAxMWRmlyZWZveCBVMkYgU29mdCBUb2tlbjBZMBMGByqGSM49\n" .
                "AgEGCCqGSM49AwEHA0IABD/TMEIaO7qczyzQ+pkFoiztnVbuzN2ExsOmLd+K4aOr\n" .
                "4IvITgbC2WA9yOVZOi/cqTADsy37w43Bl8BjAm/wcWEwCgYIKoZIzj0EAwIDRwAw\n" .
                "RAIgdeOS9BvTN4FsiexRrsblNdjTPCYPne7F/VUZXob+LAYCIGmQ7+RijVHU2KFA\n" .
                "vU7ddLpEEW0UH+hKT6FjrquVwq0q\n" .
                "-----END CERTIFICATE-----\n"
            ],
            $certChain
        );

        $this->assertSame(
            '30450221009baaba2efe577f8fef31e6c3f6adb6fc454e50b80a5689c7f0a271' .
            '07a621de550220654a1a8578c66257686635991740a76487d50589801c4b10a30' .
            'aa2e6c21f7916',
            $statement->getSignature()->getHex()
        );
    }

    public function testWrongFormat()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~not expecting format~i');

        $attObj = $this->getTestObject('none');

        new FidoU2fAttestationStatement($attObj);
    }
}
