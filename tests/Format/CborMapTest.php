<?php

namespace MadWizard\WebAuthn\Tests\Format;

use MadWizard\WebAuthn\Exception\CborException;
use MadWizard\WebAuthn\Format\CborMap;
use PHPUnit\Framework\TestCase;

class CborMapTest extends TestCase
{
    public function testEmpty()
    {
        $map = new CborMap();
        self::assertSame(0, $map->count());
    }

    public function testString()
    {
        $map = new CborMap();
        $map->set('test', 123);
        $map->set('hello', null);
        $map->set('string', 'test');
        self::assertSame(3, $map->count());

        self::assertSame(123, $map->get('test'));
        self::assertNull($map->get('hello'));
        self::assertSame('test', $map->get('string'));

        self::assertTrue($map->has('hello'));
        self::assertFalse($map->has('nope'));
    }

    public function testInt()
    {
        $map = new CborMap();
        $map->set(-123, 123);
        $map->set(0, null);
        $map->set(1, 'test');
        $map->set(2, 'dummy');

        self::assertSame(4, $map->count());

        self::assertSame(123, $map->get(-123));
        self::assertNull($map->get(0));
        self::assertSame('test', $map->get(1));
        self::assertSame('dummy', $map->get(2));

        self::assertTrue($map->has(0));
        self::assertFalse($map->has(4));
    }

    public function testOverwrite()
    {
        $map = new CborMap();
        $map->set('test', 123);
        $map->set('hello', 456);
        $map->set('test', 789);

        self::assertSame(2, $map->count());
        self::assertSame(['test', 'hello'], $map->getKeys());
    }

    public function testRemove()
    {
        $map = new CborMap();
        $map->set('hi', 123);
        $map->set('there', 456);
        $map->set('test', 789);

        $map->remove('there');

        self::assertSame(2, $map->count());
        self::assertSame(['hi', 'test'], $map->getKeys());
    }

    public function testInvalidKey()
    {
        $map = new CborMap();
        self::expectException(CborException::class);
        self::expectExceptionMessageMatches('~Only string and integer~i');
        $map->set([1, 2, 3], 123);
    }

    public function testRemoveMissing()
    {
        $map = new CborMap();
        self::expectException(CborException::class);
        self::expectExceptionMessageMatches('~is not present~i');
        $map->remove('test');
    }

    public function testGetMissing()
    {
        $map = new CborMap();
        self::expectException(CborException::class);
        self::expectExceptionMessageMatches('~is not present~i');
        $map->get('test');
    }

    public function testMixed()
    {
        $map = new CborMap();
        $map->set(-123, 123);
        $map->set(0, 'zero');
        $map->set('', 'empty');

        $map->set('1', 'string 1');
        $map->set(1, 'int 1');

        self::assertSame(5, $map->count());

        self::assertSame(123, $map->get(-123));
        self::assertSame('zero', $map->get(0));
        self::assertSame('empty', $map->get(''));
        self::assertSame('string 1', $map->get('1'));
        self::assertSame('int 1', $map->get(1));
    }

    public function testEntries()
    {
        $map = new CborMap();
        $map->set(-123, 123);
        $map->set(0, 'zero');
        $map->set('', 'empty');
        $map->set('1', 'string 1');
        $map->set(1, 'int 1');

        self::assertSame(5, $map->count());

        self::assertSame([
            [-123, 123],
            [0, 'zero'],
            ['', 'empty'],
            ['1', 'string 1'],
            [1, 'int 1'],
        ], $map->getEntries());
    }

    public function testCopy()
    {
        $map = new CborMap();

        $map->set('hello', 'there');

        $copy = $map->copy();

        $map->set('another', 'one');

        self::assertSame(1, $copy->count());
        self::assertSame(2, $map->count());
    }
}
