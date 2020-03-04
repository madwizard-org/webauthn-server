<?php


namespace MadWizard\WebAuthn\Metadata\Source;

use const DIRECTORY_SEPARATOR;
use GlobIterator;
use MadWizard\WebAuthn\Attestation\Identifier\IdentifierInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Metadata\Statement\MetadataStatement;
use SplFileInfo;
use function file_get_contents;
use function sprintf;

class StatementDirectorySource implements MetadataSourceInterface
{
    /**
     * @var string
     */
    private $metadataDir;

    public function __construct(string $metadataDir)
    {
        $this->metadataDir = $metadataDir;
    }

    public function getMetadata(IdentifierInterface $identifier): ?MetadataInterface
    {
        $iterator = new GlobIterator($this->metadataDir . DIRECTORY_SEPARATOR . '*.json');

        /**
         * @var SplFileInfo $fileInfo
         */
        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile()) {
                continue;
            }

            $data = file_get_contents($fileInfo->getRealPath());
            if ($data === false) {
                throw new WebAuthnException(sprintf('Cannot read file %s.', $fileInfo->getRealPath()));
            }
            $statement = MetadataStatement::decodeString($data);

            if ($statement->matchesIdentifier($identifier)) {
                return $statement;
            }
        }
        return null;
    }
}
