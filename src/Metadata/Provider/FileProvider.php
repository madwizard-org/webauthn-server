<?php

namespace MadWizard\WebAuthn\Metadata\Provider;

use GlobIterator;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Metadata\Source\StatementDirectorySource;
use MadWizard\WebAuthn\Metadata\Statement\MetadataStatement;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;
use SplFileInfo;

final class FileProvider implements MetadataProviderInterface
{
    /**
     * @var StatementDirectorySource
     */
    private $source;

    public function __construct(StatementDirectorySource $source)
    {
        $this->source = $source;
    }

    public function getMetadata(RegistrationResultInterface $registrationResult): ?MetadataInterface
    {
        $identifier = $registrationResult->getIdentifier();
        if ($identifier === null) {
            return null;
        }

        $iterator = new GlobIterator($this->source->getMetadataDir() . DIRECTORY_SEPARATOR . '*.json');

        /**
         * @var SplFileInfo $fileInfo
         */
        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile()) {
                continue;
            }

            $data = file_get_contents($fileInfo->getPathname());
            if ($data === false) {
                throw new WebAuthnException(sprintf('Cannot read file %s.', $fileInfo->getPathname()));
            }
            $statement = MetadataStatement::decodeString($data);

            if ($statement->matchesIdentifier($identifier)) {
                return $statement;
            }
        }
        return null;
    }

    public function getDescription(): string
    {
        return sprintf('Metadata files directory=%s', $this->source->getMetadataDir());
    }
}
