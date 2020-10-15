<?php

namespace MadWizard\WebAuthn\Crypto;

use MadWizard\WebAuthn\Format\ByteBuffer;

interface CoseKeyInterface
{
    /**
     * Converts the CoseKey to a string representation. The string contains the key as base64url encoded CBOR.
     */
    public function toString(): string;

    public function getCbor(): ByteBuffer;

    /**
     * @return int Algorithm identifier (@see CoseAlgorithm)
     *
     * @see CoseAlgorithm
     */
    public function getAlgorithm(): int;

    /**
     * Verifies if signature is a valid signature over data with this key.
     *
     * @param ByteBuffer $data      Data that is signed
     * @param ByteBuffer $signature Signature to verify
     *
     * @return bool True if the signature is valid, false otherwise
     */
    public function verifySignature(ByteBuffer $data, ByteBuffer $signature): bool;

    public function asDer(): string;

    public function asPem(): string;
}
