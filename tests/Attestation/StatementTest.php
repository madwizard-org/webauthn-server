<?php


namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\NoneAttestationStatement;
use MadWizard\WebAuthn\Attestation\Statement\PackedAttestationStatement;
use MadWizard\WebAuthn\Dom\COSEAlgorithm;
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

    private function getFidoTestObject(string $key): AttestationObject
    {
        $data = FixtureHelper::getJsonFixture('fido2-helpers/attestation.json');
        $attestationObject = $data[$key]['response']['attestationObject'];
        return new AttestationObject(new ByteBuffer(Base64UrlEncoding::decode($attestationObject)));
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
            '30450221009baaba2efe577f8fef31e6c3f6adb6fc454e50b80a5689c7f0a27107a621d' .
            'e550220654a1a8578c66257686635991740a76487d50589801c4b10a30aa2e6c21f7916',
            $statement->getSignature()->getHex()
        );
    }

    public function testFidoU2fTEST()
    {
        $attObj = $this->getFidoTestObject('challengeResponseAttestationPackedB64UrlMsg');

        $statement = new PackedAttestationStatement($attObj);


        $this->assertSame('packed', $statement->getFormatId());

        $this->assertNull($statement->getEcdaaKeyId());
        $certChain = $statement->getCertificates();

        $this->assertSame(
            [
                "-----BEGIN CERTIFICATE-----\n" .
                "MIICQTCCAeigAwIBAgIQFZ97ws2JGPEoa5NI+p8z4jAKBggqhkjOPQQDAjBJMQsw\n" .
                "CQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxGzAZBgNV\n" .
                "BAMMEkZlaXRpYW4gRklETzIgQ0EtMTAgFw0xODA0MTEwMDAwMDBaGA8yMDMzMDQx\n" .
                "MDIzNTk1OVowbzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5v\n" .
                "bG9naWVzMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMR0wGwYD\n" .
                "VQQDDBRGVCBCaW9QYXNzIEZJRE8yIFVTQjBZMBMGByqGSM49AgEGCCqGSM49AwEH\n" .
                "A0IABIAGdVxZ+8lJsBWo0gqSWJe+gwqy7+gs+I/toJCWY+VIxx8RJwUztCRGeJ1M\n" .
                "/uEBQ4qU6YM94gAsLyod129N212jgYkwgYYwHQYDVR0OBBYEFHpUgkKAYtiK56+E\n" .
                "mCXEr5GpNJjyMB8GA1UdIwQYMBaAFE072MRnFRu7E+jzhNgwT51pFcCDMAwGA1Ud\n" .
                "EwEB/wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQ\n" .
                "QjgyRUQ3M0M4RkI0RTVBMjAKBggqhkjOPQQDAgNHADBEAiAkS0Wjvojct+Alosaj\n" .
                "Es/7hu28J0oiwQUuMUhR8OiwhwIgNBq/Thwk8gsac9U9rMKp+RW0G7I6awFvH+/4\n" .
                "4Of4kMA=\n" .
                "-----END CERTIFICATE-----\n",

                "-----BEGIN CERTIFICATE-----\n" .
                "MIIB+zCCAaCgAwIBAgIQFZ97ws2JGPEoa5NI+p8z4TAKBggqhkjOPQQDAjBLMQsw\n" .
                "CQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNV\n" .
                "BAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQxMDAwMDAwMFoYDzIwMzgw\n" .
                "NDA5MjM1OTU5WjBJMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNo\n" .
                "bm9sb2dpZXMxGzAZBgNVBAMMEkZlaXRpYW4gRklETzIgQ0EtMTBZMBMGByqGSM49\n" .
                "AgEGCCqGSM49AwEHA0IABI5+YAnswRZlzKD6w+lv5Qg7lW1XJRHrWzL01mc5V91n\n" .
                "2LYXNR3/S7mA5gupuTO5mjQw8xfqIRMHVr1qB3TedY+jZjBkMB0GA1UdDgQWBBRN\n" .
                "O9jEZxUbuxPo84TYME+daRXAgzAfBgNVHSMEGDAWgBTRoZhNgX/DuWv2B2e9UBL+\n" .
                "kEXxVDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjO\n" .
                "PQQDAgNJADBGAiEA+3+j0kBHoRFQwnhWbSHMkBaY7KF/TztINFN5ymDkwmUCIQDr\n" .
                "CkPBiMHXvYg+kSRgVsKwuVtYonRvC588qRwpLStZ7A==\n" .
                "-----END CERTIFICATE-----\n",

                "-----BEGIN CERTIFICATE-----\n" .
                "MIIB2DCCAX6gAwIBAgIQFZ97ws2JGPEoa5NI+p8z1jAKBggqhkjOPQQDAjBLMQsw\n" .
                "CQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNV\n" .
                "BAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQwMTAwMDAwMFoYDzIwNDgw\n" .
                "MzMxMjM1OTU5WjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNo\n" .
                "bm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZI\n" .
                "zj0CAQYIKoZIzj0DAQcDQgAEnfAKbjvMX1Ey1b6k+WQQdNVMt9JgGWyJ3PvM4BSK\n" .
                "5XqTfo++0oAj/4tnwyIL0HFBR9St+ktjqSXDfjiXAurs86NCMEAwHQYDVR0OBBYE\n" .
                "FNGhmE2Bf8O5a/YHZ71QEv6QRfFUMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\n" .
                "BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIQC3sT1lBjGeF+xKTpzV1KYU2ckahTd4\n" .
                "mLJyzYOhaHv4igIgD2JYkfyH5Q4Bpo8rroO0It7oYjF2kgy/eSZ3U9Glaqw=\n" .
                "-----END CERTIFICATE-----\n"
            ],
            $certChain
        );

        $this->assertSame(
            '30460221008b0ad16afdb66b9dfb0688628430db45168bb0cbfe00f1fcf346dcf079ede1' .
            'cb022100b51c9dfb8248da90955fe743cf899b1dcfc092f0b777fe2a9c105ade7d88fe15',
            $statement->getSignature()->getHex()
        );

        $this->assertSame(COSEAlgorithm::ES256, $statement->getAlgorithm());
    }

    public function testWrongFormat()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~not expecting format~i');

        $attObj = $this->getTestObject('none');

        new FidoU2fAttestationStatement($attObj);
    }
}
