<?php

namespace MadWizard\WebAuthn\Metadata\Statement;

use MadWizard\WebAuthn\Attestation\AttestationType;

final class AttestationConstant
{
    /**
     * Indicates full basic attestation as defined in [UAFProtocol].
     */
    public const TAG_ATTESTATION_BASIC_FULL = 0x3E07;

    /**
     * Indicates surrogate basic attestation as defined in [UAFProtocol].
     */
    public const TAG_ATTESTATION_BASIC_SURROGATE = 0x3E08;

    public const TAG_ATTESTATION_ATT_CA = 0x3E0A;

    /**
     * Indicates use of elliptic curve based direct anonymous attestation as defined in [FIDOEcdaaAlgorithm].
     */
    public const TAG_ATTESTATION_ECDAA = 0x3E09;

    private const MAP = [
        AttestationType::BASIC => self::TAG_ATTESTATION_BASIC_FULL,
        AttestationType::SELF => self::TAG_ATTESTATION_BASIC_SURROGATE,
        AttestationType::ATT_CA => self::TAG_ATTESTATION_ATT_CA,
        AttestationType::ECDAA => self::TAG_ATTESTATION_ECDAA,
    ];

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    /**
     * Converts AttestationType style constant to numerical constant.
     * Returns null if there is no equivalent.
     */
    public static function convertType(string $type): ?int
    {
        return self::MAP[$type] ?? null;
    }
}
