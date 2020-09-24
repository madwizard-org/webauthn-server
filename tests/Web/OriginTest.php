<?php

namespace MadWizard\WebAuthn\Tests\Web;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Web\Origin;
use PHPUnit\Framework\TestCase;
use Serializable;

class OriginTest extends TestCase
{
    public function testSimple()
    {
        $localhost = Origin::parse('http://localhost');

        self::assertSame('localhost', $localhost->getHost());
        self::assertSame('http://localhost', $localhost->toString());
        self::assertSame('http', $localhost->getScheme());
        self::assertSame(80, $localhost->getPort());
    }

    public function testPort()
    {
        $localhost = Origin::parse('http://localhost:8080');

        self::assertSame('localhost', $localhost->getHost());
        self::assertSame('http://localhost:8080', $localhost->toString());
    }

    public function testDefaultHttps()
    {
        $localhost = Origin::parse('https://localhost');
        self::assertSame(443, $localhost->getPort());
    }

    public function testCase()
    {
        $origin = Origin::parse('HTTP://EXAMPLE.com');
        self::assertSame('http', $origin->getScheme());
        self::assertSame('example.com', $origin->getHost());
    }

    public function testUnexpectedPath()
    {
        $this->expectException(ParseException::class);
        Origin::parse('http://example.com/path');
    }

    public function testEquality()
    {
        $origin = Origin::parse('https://example.com');

        self::assertTrue($origin->equals(Origin::parse('https://example.com:443')));
    }

    public function testMissingScheme()
    {
        $this->expectException(ParseException::class);
        Origin::parse('//example.com');
    }

    public function testUnknownDefaultPort()
    {
        $this->expectException(ParseException::class);
        Origin::parse('abcd://example.com');
    }

    public function testIPV4()
    {
        $origin = Origin::parse('https://127.0.0.1');
        self::assertSame('127.0.0.1', $origin->getHost());
    }

    public function testEmpty()
    {
        $this->expectException(ParseException::class);
        Origin::parse('');
    }

    public function testInvalidDomain()
    {
        $this->expectException(ParseException::class);
        Origin::parse('https://a...b');
    }

    public function testInvalid()
    {
        $this->expectException(ParseException::class);
        Origin::parse(':');
    }

    public function testSerialize()
    {
        $origin = Origin::parse('https://example.com:8443');
        self::assertInstanceOf(Serializable::class, $origin);
        $s = serialize($origin);
        $new = unserialize($s);
        self::assertInstanceOf(Origin::class, $new);
        self::assertSame('example.com', $new->getHost());
        self::assertSame('https', $new->getScheme());
        self::assertSame(8443, $new->getPort());
    }
}
