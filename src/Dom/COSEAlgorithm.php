<?php


namespace MadWizard\WebAuthn\Dom;

/**
 * Enumeration for COSE algorithm identifiers.
 * This is not a complete enumeration of all algorithms, only the algorithms relevant to this WebAuthn implementation
 * are included.
 * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
final class COSEAlgorithm
{
    /**
     * EdDSA (RFC8152)
     */
    public const ES256 = -1;

    private function __construct()
    {
    }
}
