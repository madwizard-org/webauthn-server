<?php


namespace MadWizard\WebAuthn\Dom;

/**
 * Enumeration for COSE algorithm identifiers.
 * This is not a complete enumeration of all algorithms, only the algorithms relevant to this WebAuthn implementation
 * are included.
 * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
final class CoseAlgorithm
{
    /**
     * ECDSA w/ SHA-256 (RFC8152)
     */
    public const ES256 = -7;

    /**
     * ECDSA w/ SHA-384 (RFC8152)
     */
    public const ES384 = -35;

    /**
     * ECDSA w/ SHA-512 (RFC8152)
     */
    public const ES512 = -36;

    /**
     * RSASSA-PKCS1-v1_5 w/ SHA-256
     */
    public const RS256 = -257;

    /**
     * RSASSA-PKCS1-v1_5 w/ SHA-384
     */
    public const RS384 = -258;

    /**
     * RSASSA-PKCS1-v1_5 w/ SHA-512
     */
    public const RS512 = -259;

    /**
     * RSASSA-PKCS1-v1_5 w/ SHA-1
     */
    public const RS1 = -65535;

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }
}
