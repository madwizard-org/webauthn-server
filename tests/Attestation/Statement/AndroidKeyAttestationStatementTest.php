<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Statement\AndroidKeyAttestationStatement;
use MadWizard\WebAuthn\Crypto\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class AndroidKeyAttestationStatementTest extends TestCase
{
    public function testAndroidKey()
    {
        $attObj = FixtureHelper::getTestObject('android-key');
        $chains = FixtureHelper::getTestPlain('certChains');

        $statement = new AndroidKeyAttestationStatement($attObj);

        self::assertSame('android-key', $statement->getFormatId());
        self::assertSame(CoseAlgorithm::ES256, $statement->getAlgorithm());
        self::assertSame(
            '304402202ca7a8cfb6299c4a073e7e022c57082a46c657e9e53b28a6e454659ad02449' .
            '9602201f9cae7ff95a3f2372e0f952e9ef191e3b39ee2cedc46893a8eec6f75b1d9560',
            $statement->getSignature()->getHex()
        );

        $certChain = $statement->getCertificates();

        self::assertSame($chains['android-key'], $certChain);

        self::assertSame(CoseAlgorithm::ES256, $statement->getAlgorithm());
    }

    public function testInvalidStatementMap()
    {
        $attObj = FixtureHelper::getTestObject('invalid-android-key');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('~invalid .+ attestation statement~i');
        new AndroidKeyAttestationStatement($attObj);
    }
}
