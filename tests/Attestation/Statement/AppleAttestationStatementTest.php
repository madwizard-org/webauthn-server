<?php

namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Attestation\Statement\AppleAttestationStatement;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\CertHelper;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class AppleAttestationStatementTest extends TestCase
{
    public function testAppleStatement()
    {
        $clientResponse = FixtureHelper::getTestPlain('apple');
        $chains = FixtureHelper::getTestPlain('certChains');
        $attObj = AttestationObject::parse(ByteBuffer::fromBase64Url($clientResponse['response']['attestationObject']));
        $statement = new AppleAttestationStatement($attObj);
        self::assertSame('apple', $statement->getFormatId());
        self::assertSame($chains['apple'], CertHelper::pemList(...$statement->getCertificates()));
    }
}
