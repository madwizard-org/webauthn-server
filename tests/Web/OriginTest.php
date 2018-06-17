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

        $this->assertSame('localhost', $localhost->getDomain());
        $this->assertSame('http://localhost', $localhost->toString());
        $this->assertSame('http', $localhost->getScheme());
        $this->assertSame(80, $localhost->getPort());
    }

    public function testPort()
    {
        $localhost = Origin::parse('http://localhost:8080');

        $this->assertSame('localhost', $localhost->getDomain());
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
        $this->assertSame('example.com', $origin->getDomain());
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
        $origin = Origin::parse('//example.com');
        $this->assertSame('http://example.com', $origin->toString());
    }

    public function testEmpty()
    {
        $this->expectException(ParseException::class);
        Origin::parse('');
    }

    public function testInvalid()
    {
        $this->expectException(ParseException::class);
        Origin::parse(':');
    }
}
