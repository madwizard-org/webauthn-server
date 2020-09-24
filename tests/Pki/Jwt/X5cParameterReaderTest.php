<?php

namespace MadWizard\WebAuthn\Tests\Pki\Jwt;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\UnsupportedException;
use MadWizard\WebAuthn\Pki\Jwt\Jwt;
use MadWizard\WebAuthn\Pki\Jwt\X5cParameterReader;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class X5cParameterReaderTest extends TestCase
{
    /**
     * @dataProvider invalidTokensData
     */
    public function testTokens(bool $hasResult, string $tokenFile, ?string $exeptionClass = null, ?string $msgRegEx = null)
    {
        $token = FixtureHelper::getFixtureContent($tokenFile);
        $jwt = new Jwt($token);
        if ($exeptionClass) {
            $this->expectException($exeptionClass);
        }
        if ($msgRegEx) {
            $this->expectExceptionMessageMatches($msgRegEx);
        }
        $param = X5cParameterReader::getX5cParameter($jwt);

        // TODO: actually compare result
        if ($hasResult) {
            self::assertNotNull($param);
        } else {
            self::assertNull($param);
        }
    }

    public function invalidTokensData()
    {
        return [
            'valid' => [true, 'Jwt/token-valid.txt'],
            'unsupported-alg' => [true, 'Jwt/token-unsupported-alg.txt', UnsupportedException::class, '~Unsupported algorithm~i'],
            'invalid-x5c' => [true, 'Jwt/token-invalid-x5c.txt', ParseException::class, '~Expecting array for x5c~'],
            'no-x5c' => [false, 'Jwt/token-no-x5c.txt'],
        ];
    }
}
