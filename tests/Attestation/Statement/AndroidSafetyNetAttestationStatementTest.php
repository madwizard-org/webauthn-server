<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Statement\AndroidSafetyNetAttestationStatement;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class AndroidSafetyNetAttestationStatementTest extends TestCase
{
    public function testAndroidSafetyNet()
    {
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationSafetyNetMsgB64Url');
        $jwsText = FixtureHelper::getFidoTestPlain('androidSafetyNetJWS');

        $statement = new AndroidSafetyNetAttestationStatement($attObj);

        self::assertSame('android-safetynet', $statement->getFormatId());
        self::assertSame($jwsText, $statement->getResponse());
    }
}
