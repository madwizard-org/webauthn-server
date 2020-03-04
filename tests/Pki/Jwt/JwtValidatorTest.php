<?php

namespace MadWizard\WebAuthn\Tests\Pki\Jwt;

use MadWizard\WebAuthn\Crypto\Ec2Key;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Pki\Jwt\Jwt;
use MadWizard\WebAuthn\Pki\Jwt\JwtValidator;
use MadWizard\WebAuthn\Pki\Jwt\ValidationContext;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class JwtValidatorTest extends TestCase
{
    /**
     * @dataProvider invalidTokensData
     */
    public function testTokens(string $tokenFile, ?string $exeptionClass = null, ?string $msgRegEx = null)
    {
        $key = Ec2Key::fromString(trim(FixtureHelper::getFixtureContent('Jwt/cosekey.txt')));
        $token = FixtureHelper::getFixtureContent($tokenFile);

        $validator = new JwtValidator();


        if ($exeptionClass) {
            $this->expectException($exeptionClass);
        }
        if ($msgRegEx) {
            $this->expectExceptionMessageRegExp($msgRegEx);
        }

        // TODO: split parse and validate tests
        $jwt = new Jwt($token);


        $ctx = new ValidationContext(['ES256', 'ES384', 'ES512'], $key);
        $this->assertSame(['test' => 'data', 'hello' => true], $validator->validate($jwt, $ctx));
    }

    public function invalidTokensData()
    {
        return [

            'invalid-sig' => ['Jwt/token-invalid-sig.txt', VerificationException::class],

            'unsupported-alg' => ['Jwt/token-unsupported-alg.txt', VerificationException::class, '~Algorithm not allowed~i'],
            'wrong-key' => ['Jwt/token-wrong-key.txt', VerificationException::class, '~Invalid signature~i'],

            'not-a-token' => ['Jwt/token-not-a-token.txt', ParseException::class, '~Invalid JWT~'],
            'header-no-json' => ['Jwt/token-header-no-json.txt', ParseException::class, '~JSON~'],

            // TODO: remove/move to chain test
            //  'ca-only' => [false, 'Jwt/token-ca-only.txt', VerificationException::class],
            //  'missing-ca' => [false, 'Jwt/token-missing-ca.txt', VerificationException::class, '~chain could not be validated~i'],


        ];
    }
}
