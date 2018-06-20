<?php


namespace MadWizard\WebAuthn\Tests\Format;

use DateTime;
use MadWizard\WebAuthn\Exception\DataValidationException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Format\DataValidator;
use PHPUnit\Framework\TestCase;

class DataValidatorTest extends TestCase
{
    public function testCheckTypes()
    {
        DataValidator::checkTypes(
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
        $this->expectExceptionMessageRegExp('~expecting.+type~i');
        DataValidator::checkTypes(
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
        $this->expectExceptionMessageRegExp('~expecting.+DateTime~i');
        DataValidator::checkTypes(
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
        $this->expectExceptionMessageRegExp('~missing~i');

        DataValidator::checkTypes(
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
        $this->expectExceptionMessageRegExp('~unexpected~i');

        DataValidator::checkTypes(
            [
                'a' => 4,
                'b' => 'ab',
                'e' => false
            ],
            [
                'a' => 'integer',
                'b' => 'string',
            ]
        );
    }

    public function testCheckTypesAdditionalAllowed()
    {
        DataValidator::checkTypes(
            [
                'a' => 4,
                'b' => 'ab',
                'e' => false
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
        DataValidator::checkTypes(
            [
                'a' => 4,
                'c' => [1, 2, 3],
            ],
            [
                'a' => 'integer',
                'b' => '?string',
                'c' => 'array',
                'd' => '?' . ByteBuffer::class
            ]

        );

        // Assert when no exceptions thrown
        $this->assertTrue(true);
    }

    public function testCheckTypesWrongParameters()
    {
        $this->expectException(DataValidationException::class);
        $this->expectExceptionMessageRegExp('~invalid type~i');

        DataValidator::checkTypes(
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
