<?php


namespace MadWizard\WebAuthn\Tests\Web;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Web\Origin;
use PHPUnit\Framework\TestCase;

class OriginTest extends TestCase
{
    public function testSimple()
    {
        $localhost = Origin::parse('http://localhost');

        $this->assertSame('localhost', $localhost->getHost());
        $this->assertSame('http://localhost', $localhost->toString());
        $this->assertSame('http', $localhost->getScheme());
        $this->assertSame(80, $localhost->getPort());
    }

    public function testPort()
    {
        $localhost = Origin::parse('http://localhost:8080');

        $this->assertSame('localhost', $localhost->getHost());
        $this->assertSame('http://localhost:8080', $localhost->toString());
    }

    public function testDefaultHttps()
    {
        $localhost = Origin::parse('https://localhost');
        $this->assertSame(443, $localhost->getPort());
    }

    public function testCase()
    {
        $origin = Origin::parse('HTTP://EXAMPLE.com');
        $this->assertSame('http', $origin->getScheme());
        $this->assertSame('example.com', $origin->getHost());
    }

    public function testUnexpectedPath()
    {
        $this->expectException(ParseException::class);
        Origin::parse('http://example.com/path');
    }

    public function testEquality()
    {
        $origin = Origin::parse('https://example.com');

        $this->assertTrue($origin->equals(Origin::parse('https://example.com:443')));
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
        $this->assertSame('127.0.0.1', $origin->getHost());
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
}
