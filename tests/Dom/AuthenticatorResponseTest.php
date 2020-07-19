<?php

namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\AuthenticatorAssertionResponse;
use MadWizard\WebAuthn\Dom\AuthenticatorAttestationResponse;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class AuthenticatorResponseTest extends TestCase
{
    public function testAssertion()
    {
        $assertion = new AuthenticatorAssertionResponse(
            '{"a": 123}',
            ByteBuffer::fromHex('123456'),
            ByteBuffer::fromHex('789ABC'),
            null
        );

        $this->assertSame('{"a": 123}', $assertion->getClientDataJson());
        $this->assertSame('123456', $assertion->getAuthenticatorData()->getHex());
        $this->assertSame('789abc', $assertion->getSignature()->getHex());
        $this->assertNull($assertion->getUserHandle());
    }

    public function testAssertionWithUser()
    {
        $assertion = new AuthenticatorAssertionResponse(
            '{"a": 123}',
            ByteBuffer::fromHex('123456'),
            ByteBuffer::fromHex('789abc'),
            ByteBuffer::fromHex('0099aabbcc')
        );

        $this->assertSame('{"a": 123}', $assertion->getClientDataJson());
        $this->assertSame('123456', $assertion->getAuthenticatorData()->getHex());
        $this->assertSame('789abc', $assertion->getSignature()->getHex());
        $this->assertSame('0099aabbcc', $assertion->getUserHandle()->getHex());
    }

    public function testAssertionUnparseableJson()
    {
        $buf = ByteBuffer::fromHex('12');

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~Unparseable~i');

        new AuthenticatorAssertionResponse('{{123', $buf, $buf, null);
    }

    public function testAttestation()
    {
        $assertion = new AuthenticatorAttestationResponse(
            '{"a": 123}',
            ByteBuffer::fromHex('123456')
        );

        $this->assertSame('{"a": 123}', $assertion->getClientDataJson());
        $this->assertSame('123456', $assertion->getAttestationObject()->getHex());
    }

    public function testAttestationUnparseableJson()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~Unparseable~i');

        new AuthenticatorAttestationResponse('{{123', ByteBuffer::fromHex('123456'));
    }
}
