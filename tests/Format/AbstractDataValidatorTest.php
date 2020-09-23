<?php

namespace MadWizard\WebAuthn\Tests\Format;

use DateTime;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

abstract class AbstractDataValidatorTest extends TestCase
{
    abstract protected function check(array $data, array $types, bool $complete = true): void;

    public function testCheckTypes()
    {
        $this->check(
            [
                'a' => 4,
                'b' => 'ab',
                'c' => [1, 2, 3],
                'd' => new ByteBuffer(''),
                'e' => false,
                'f' => null,
            ],
            [
                'a' => 'integer',
                'b' => 'string',
                'c' => 'array',
                'd' => ByteBuffer::class,
                'e' => 'boolean',
                'f' => 'NULL',
            ]
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesWrong()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~expecting.+type~i');
        $this->check(
            [
                'a' => 4,
                'b' => 'ab',
            ],
            [
                'a' => 'integer',
                'b' => 'integer',
            ]
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesWrongClass()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~expecting.+DateTime~i');
        $this->check(
            [
                'a' => new ByteBuffer(''),
                'b' => new ByteBuffer(''),
            ],
            [
                'a' => ByteBuffer::class,
                'b' => DateTime::class,
            ]
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesMissing()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~missing~i');

        $this->check(
            [
                'a' => 4,
                'b' => 'ab',
                 // c missing
                'd' => new ByteBuffer(''),
                'e' => false,
                'f' => null,
            ],
            [
                'a' => 'integer',
                'b' => 'string',
                'c' => 'array',
                'd' => ByteBuffer::class,
                'e' => 'boolean',
                'f' => 'NULL',
            ]
        );
    }

    public function testCheckTypesAdditional()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~unexpected~i');

        $this->check(
            [
                'a' => 4,
                'b' => 'ab',
                'e' => false,
            ],
            [
                'a' => 'integer',
                'b' => 'string',
            ]
        );
    }

    public function testCheckTypesAdditionalAllowed()
    {
        $this->check(
            [
                'a' => 4,
                'b' => 'ab',
                'e' => false,
            ],
            [
                'a' => 'integer',
                'b' => 'string',
            ],
            false
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesOptional()
    {
        $this->check(
            [
                'a' => 4,
                'c' => [1, 2, 3],
            ],
            [
                'a' => 'integer',
                'b' => '?string',
                'c' => 'array',
                'd' => '?' . ByteBuffer::class,
            ]
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesOptionalPresent()
    {
        $this->check(
            [
                'a' => 4,
                'b' => 'test',
                'c' => [1, 2, 3],
                'd' => new ByteBuffer(''),
            ],
            [
                'a' => 'integer',
                'b' => '?string',
                'c' => '?array',
                'd' => '?' . ByteBuffer::class,
            ]
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesNullable()
    {
        $this->check(
            [
                'a' => 4,
                'c' => null,
                'd' => 'text',
            ],
            [
                'a' => 'integer',
                'c' => ':string',
                'd' => ':string',
            ]
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesNullableInvalid()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~string~i');

        $this->check(
            [
                'a' => 4,
                'c' => 5,
            ],
            [
                'a' => 'integer',
                'c' => ':string',
            ]
        );
    }

    public function testCheckTypesNullableMissing()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~required key "c"~i');
        $this->check(
            [
                'a' => 4,
            ],
            [
                'a' => 'integer',
                'c' => ':string',
            ]
        );
    }

    public function testCheckTypesNullableOptional()
    {
        $this->check(
            [
                'a' => 4,
                // b missing
                'c' => null,
                'd' => 'text',
            ],
            [
                'a' => 'integer',
                'b' => '?:string',
                'c' => '?:string',
                'd' => '?:string',
            ]
        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesWrongParameters()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageMatches('~invalid type~i');

        $this->check(
            [
                'a' => 4,
                'b' => 'ab',
            ],
            [
                'a' => '',
                'b' => 'string',
            ]
        );
    }
}
