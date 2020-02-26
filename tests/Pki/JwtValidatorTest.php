<?php

namespace MadWizard\WebAuthn\Tests\Pki;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Pki\ChainValidator;
use MadWizard\WebAuthn\Pki\JwtValidator;
use MadWizard\WebAuthn\Pki\X509Certificate;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class JwtValidatorTest extends TestCase
{
    /**
     * @throws \MadWizard\WebAuthn\Exception\ParseException
     * @dataProvider invalidTokensData
     */
    public function testTokens(bool $valid, string $tokenFile, ?string $exeptionClass = null, ?string $msgRegEx = null)
    {
        $token = FixtureHelper::getFixtureContent($tokenFile);
        $root = FixtureHelper::getFixtureContent('Jwt/root.crt');

        if ($exeptionClass) {
            $this->expectException($exeptionClass);
        }
        if ($msgRegEx) {
            $this->expectExceptionMessageRegExp($msgRegEx);
        }

        $chainValidator = new ChainValidator();
        $jwt = new JwtValidator($chainValidator);
        $claims = $jwt->validate($token, X509Certificate::fromPem($root));
        if ($valid) {
            $this->assertSame(['test' => 'data', 'hello' => true], $claims);
        } else {
            $this->assertTrue(false);
        }
    }

    public function invalidTokensData()
    {
        return [
            'valid' => [true, 'Jwt/token-valid.txt'],
            'ca-only' => [false, 'Jwt/token-ca-only.txt', VerificationException::class],
            'invalid-sig' => [false, 'Jwt/token-invalid-sig.txt', VerificationException::class],
            'missing-ca' => [false, 'Jwt/token-missing-ca.txt', VerificationException::class, '~chain could not be validated~i'],
            'no-x5c' => [false, 'Jwt/token-no-x5c.txt', VerificationException::class, '~No key available~i'],
            'unsupported-alg' => [false, 'Jwt/token-unsupported-alg.txt', VerificationException::class, '~Algorithm not allowed~i'],
            'wrong-key' => [false, 'Jwt/token-wrong-key.txt', VerificationException::class, '~Failed to verify JWT~i'],
            'invalid-x5c' => [false, 'Jwt/token-invalid-x5c.txt', ParseException::class, '~Expecting array for x5c~'],
            'not-a-token' => [false, 'Jwt/token-not-a-token.txt', ParseException::class, '~Invalid JWT~'],
            'header-no-json' => [false, 'Jwt/token-header-no-json.txt', ParseException::class, '~JSON~'],
        ];
    }
}
