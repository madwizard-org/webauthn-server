<?php

namespace MadWizard\WebAuthn\Attestation;

final class AttestationType
{
    /**
     * In this case, no attestation information is available.
     */
    public const NONE = 'None';

    /**
     * The authenticator’s attestation key pair is specific to an authenticator model.
     */
    public const BASIC = 'Basic';

    /**
     * The Authenticator does not have any specific attestation key. Instead it uses the credential private key to
     * create the attestation signature. Authenticators without meaningful protection measures for an attestation
     * private key typically use this attestation type.
     */
    public const SELF = 'Self';

    /**
     * The authenticator is based on a Trusted Platform Module (TPM) and holds an authenticator-specific
     * "endorsement key" (EK).
     */
    public const ATT_CA = 'AttCA';

    /**
     * The Authenticator receives direct anonymous attestation (DAA) credentials from a single DAA-Issuer.
     */
    public const ECDAA = 'ECDAA';

    /**
     * The authenticator works with a cloud-operated Anonymization CA owned by its manufacturer to dynamically generate
     * per-credential attestation certificates on the CA such that no identification information of an individual
     * authenticator will be revealed to Relying Parties in the attestation statement.
     */
    public const ANON_CA = 'AnonCA';

    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    public static function isValidType(string $type): bool
    {
        return \in_array(
            $type,
            [
                self::NONE,
                self::BASIC,
                self::SELF,
                self::ATT_CA,
                self::ECDAA,
                self::ANON_CA,
            ],
            true
        );
    }
}
