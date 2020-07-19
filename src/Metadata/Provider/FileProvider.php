<?php

namespace MadWizard\WebAuthn\Metadata\Provider;

use GlobIterator;
use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Metadata\Source\StatementDirectorySource;
use MadWizard\WebAuthn\Metadata\Statement\MetadataStatement;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;
use SplFileInfo;

class FileProvider implements MetadataProviderInterface
{
    /**
     * @var StatementDirectorySource
     */
    private $source;

    public function __construct(StatementDirectorySource $source)
    {
        $this->source = $source;
    }

    public function getMetadata(IdentifierInterface $identifier, RegistrationResultInterface $registrationResult): ?MetadataInterface
    {
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
}
