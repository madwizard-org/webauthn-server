<?php

namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Exception\UnsupportedException;

class CoseHash
{
    private $phpAlg;

    private const MAP = [
        CoseAlgorithm::RS1 => 'sha1',
        CoseAlgorithm::ES256 => 'sha256',
        CoseAlgorithm::ES384 => 'sha384',
        CoseAlgorithm::ES512 => 'sha512',
        CoseAlgorithm::RS256 => 'sha256',
        CoseAlgorithm::RS384 => 'sha384',
        CoseAlgorithm::RS512 => 'sha512',
    ];

    /**
     * CoseHash constructor.
     *
     * @param int $algorithm CoseAlgorithm identifier
     *
     * @see CoseAlgorithm
     *
     * @throws UnsupportedException
     */
    public function __construct(int $algorithm)
    {
        $this->phpAlg = self::MAP[$algorithm] ?? null;
        if ($this->phpAlg === null) {
            throw new UnsupportedException(sprintf('COSE algorithm %d not supported for hashing.', $algorithm));
        }
    }

    public function hash(string $data): string
    {
        return hash($this->phpAlg, $data, true);
    }
}
