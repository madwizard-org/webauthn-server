<?php

namespace MadWizard\WebAuthn\Tests\Metadata\Statement;

use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Attestation\TrustAnchor\CertificateTrustAnchor;
use MadWizard\WebAuthn\Metadata\Statement\MetadataStatement;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class MetadataStatementTest extends TestCase
{
    public const TEST_AAGUID = 'b1a0c872-ce5b-a96d-95fe-ad73f637e591';

    public function testStatement()
    {
        $statement = MetadataStatement::decodeString(FixtureHelper::getFixtureContent('mds-dir/mds-testauth.json'));
        self::assertSame(self::TEST_AAGUID, $statement->getAaguid()->toString());
        self::assertNull($statement->getAaid());
        self::assertEmpty($statement->getAttestationCertificateKeyIdentifiers());
        self::assertSame('Test authenticator', $statement->getDescription());

        self::assertTrue($statement->supportsAttestationType(AttestationType::SELF));
        self::assertTrue($statement->supportsAttestationType(AttestationType::BASIC));
        self::assertFalse($statement->supportsAttestationType(AttestationType::NONE));

        self::assertTrue($statement->matchesIdentifier(Aaguid::parseString(self::TEST_AAGUID)));
        $anchors = $statement->getTrustAnchors();
        self::assertCount(1, $anchors);
        self::assertInstanceOf(CertificateTrustAnchor::class, $anchors[0]);
    }
}
