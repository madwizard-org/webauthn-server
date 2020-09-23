<?php

namespace MadWizard\WebAuthn\Tests\Json;

use MadWizard\WebAuthn\Exception\DataValidationException;
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
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~Required key "type"~i');
        JsonConverter::decodeAssertionString('{"id":"YWE","response":{}}');
    }

    public function testMissingId()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~Required key "id"~i');
        JsonConverter::decodeAssertionString('{"type":"public-key"}');
    }

    public function testNonStringId()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~Expecting key "id" to be of type "string" ~i');
        JsonConverter::decodeAssertionString('{"type":"public-key","id":333}');
    }

    public function testInvalidEncodedId()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~base64url~i');
        JsonConverter::decodeAssertionString('{"type":"public-key","response":{},"id":"%%%"}');
    }

    public function testInvalidType()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~Unknown or missing type~i');
        JsonConverter::decodeCredential($this->getResponse(), 'invalid');
    }

    public function testInvalidResponse()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~Expecting key "response" to be of type "array"~i');
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
