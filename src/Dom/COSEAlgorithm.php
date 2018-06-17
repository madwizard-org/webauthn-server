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
     * ECDSA w/ SHA-256 (RFC8152)
     */
    public const ES256 = -7;

    /**
     * RSASSA-PKCS1-v1_5 w/ SHA-256
     */
    public const RS256 = -257;

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }
}
