<?php

namespace MadWizard\WebAuthn\Tests\Metadata\Provider;

use MadWizard\WebAuthn\Attestation\Identifier\Aaguid;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Metadata\Provider\FileProvider;
use MadWizard\WebAuthn\Metadata\Source\StatementDirectorySource;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MadWizard\WebAuthn\Metadata\Provider\FileProvider
 */
class FileProviderTest extends TestCase
{
    public const TEST_AAGUID = 'b1a0c872-ce5b-a96d-95fe-ad73f637e591';

    public const UNKNOWN_AAGUID = 'faf54e66-f8f7-ce58-49be-f21240d0b426';

    /**
     * @var FileProvider
     */
    private $provider;

    protected function setUp(): void
    {
        $dir = FixtureHelper::getFixtureDirectory('mds-dir');
        $this->provider = new FileProvider(new StatementDirectorySource($dir));
    }

    private function find(?string $aaguid): ?MetadataInterface
    {
        $stub = $this->createMock(RegistrationResultInterface::class);
        $stub->method('getIdentifier')->willReturn($aaguid === null ? null : Aaguid::parseString($aaguid));

        return $this->provider->getMetadata($stub);
    }

    public function testMetadataFound(): void
    {
        $metadata = $this->find(self::TEST_AAGUID);
        self::assertNotNull($metadata);
        self::assertStringContainsString('Test authenticator', $metadata->getDescription());
    }

    public function testMetadataNotFound(): void
    {
        $metadata = $this->find(self::UNKNOWN_AAGUID);
        self::assertNull($metadata);
    }

    public function testNoIdentifier(): void
    {
        $metadata = $this->find(null);
        self::assertNull($metadata);
    }

    public function testDescription(): void
    {
        $desc = $this->provider->getDescription();
        self::assertStringContainsString('Metadata files', $desc);
        self::assertStringContainsString('mds-dir', $desc);
    }
}
