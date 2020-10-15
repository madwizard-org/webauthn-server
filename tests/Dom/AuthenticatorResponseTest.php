<?php

namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\AuthenticatorAssertionResponse;
use MadWizard\WebAuthn\Dom\AuthenticatorAttestationResponse;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class AuthenticatorResponseTest extends TestCase
{
    private const GET_CLIENT_DATA = '{"type":"get","challenge":"Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA","origin":"https://localhost"}';

    private const CREATE_CLIENT_DATA = '{"type":"create","challenge":"Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA","origin":"https://localhost"}';

    public function testAssertion()
    {
        $assertion = new AuthenticatorAssertionResponse(
            self::GET_CLIENT_DATA,
            ByteBuffer::fromHex('123456'),
            ByteBuffer::fromHex('789ABC'),
            null
        );

        self::assertSame(self::GET_CLIENT_DATA, $assertion->getClientDataJson());
        self::assertSame('123456', $assertion->getAuthenticatorData()->getHex());
        self::assertSame('789abc', $assertion->getSignature()->getHex());
        self::assertNull($assertion->getUserHandle());
    }

    public function testAssertionWithUser()
    {
        $assertion = new AuthenticatorAssertionResponse(
            self::GET_CLIENT_DATA,
            ByteBuffer::fromHex('123456'),
            ByteBuffer::fromHex('789abc'),
            ByteBuffer::fromHex('0099aabbcc')
        );

        self::assertSame(self::GET_CLIENT_DATA, $assertion->getClientDataJson());
        self::assertSame('123456', $assertion->getAuthenticatorData()->getHex());
        self::assertSame('789abc', $assertion->getSignature()->getHex());
        self::assertSame('0099aabbcc', $assertion->getUserHandle()->getHex());
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
            self::CREATE_CLIENT_DATA,
            ByteBuffer::fromHex('123456')
        );

        self::assertSame(self::CREATE_CLIENT_DATA, $assertion->getClientDataJson());
        self::assertSame('123456', $assertion->getAttestationObject()->getHex());
    }

    public function testAttestationUnparseableJson()
    {
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~Unparseable~i');

        new AuthenticatorAttestationResponse('{{123', ByteBuffer::fromHex('123456'));
    }

    public function testParsedClientData()
    {
        $assertion = new AuthenticatorAssertionResponse(
            self::GET_CLIENT_DATA,
            ByteBuffer::fromHex('123456'),
            ByteBuffer::fromHex('789ABC'),
            null
        );

        self::assertSame('get', $assertion->getParsedClientData()->getType());
    }
}
