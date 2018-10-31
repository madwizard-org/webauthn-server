<?php


namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\UnsupportedException;

class CoseHash
{
    private $phpAlg;

    private const MAP = [
        CoseAlgorithm::RS1 => 'sha1',
        CoseAlgorithm::ES256 => 'sha256',
        CoseAlgorithm::RS256 => 'sha256',
    ];

    /**
     * CoseHash constructor.
     * @param int $algorithm CoseAlgorithm identifier
     * @see CoseAlgorithm
     * @throws UnsupportedException
     */
    public function __construct(int $algorithm)
    {
        $this->phpAlg = self::MAP[$algorithm] ?? null;
        if ($this->phpAlg === null) {
            throw new UnsupportedException(sprintf('COSE algorithm %d not supported for hashing.', $algorithm));
        }
    }

    public function hash(string $data) : string
    {
        return hash($this->phpAlg, $data, true);
    }
}
