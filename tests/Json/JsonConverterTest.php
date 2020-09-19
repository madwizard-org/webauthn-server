<?php

namespace MadWizard\WebAuthn\Tests\Json;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class JsonConverterTest extends TestCase
{
    private function getResponse(array $override = []): array
    {
        $json = FixtureHelper::getJsonFixture('fido2-helpers/attestation.json');
        return $json['challengeResponseAttestationU2fMsgB64Url'];
    }

    public function testInvalidJson()
    {
        $this->expectException(ParseException::class);
        JsonConverter::decodeAssertionString(']');
    }

    public function testNotPublicKey()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~public-key~i');
        JsonConverter::decodeAssertionString('{}');
    }

    public function testMissingId()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~missing id~i');
        JsonConverter::decodeAssertionString('{"type":"public-key"}');
    }

    public function testNonStringId()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~should be a string~i');
        JsonConverter::decodeAssertionString('{"type":"public-key","id":333}');
    }

    public function testInvalidEncodedId()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~base64url~i');
        JsonConverter::decodeAssertionString('{"type":"public-key","id":"%%%"}');
    }

    public function testInvalidType()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~Unknown or missing type~i');
        JsonConverter::decodeCredential($this->getResponse(), 'invalid');
    }

    public function testInvalidResponse()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~expecting array~i');
        $json = array_merge(
                $this->getResponse(),
                ['response' => 5]
            );

        JsonConverter::decodeAttestation($json);
    }

    public function testInvalidClientDataType()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~client data json~i');
        $json = array_merge(
                $this->getResponse(),
                ['response' => ['clientDataJSON' => 123]]
            );

        JsonConverter::decodeCredential($json, 'attestation');
    }
}
