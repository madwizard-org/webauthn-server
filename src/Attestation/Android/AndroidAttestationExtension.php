<?php


namespace MadWizard\WebAuthn\Attestation\Android;

use MadWizard\WebAuthn\Format\ByteBuffer;

/**
 * @see https://source.android.com/security/keystore/attestation#attestation-extension
 */
class AndroidAttestationExtension
{
    public const OID = '1.3.6.1.4.1.11129.2.1.17';

    /**
     * @var AuthorizationList
     */
    private $seAuthList;

    /**
     * @var AuthorizationList
     */
    private $teeAuthList;

    /**
     * @var ByteBuffer
     */
    private $challenge;

    /**
     * AndroidAttestationExtension constructor.
     * @param AuthorizationList $seAuthList
     * @param AuthorizationList $teeAuthList
     * @param ByteBuffer $challenge
     */
    public function __construct(ByteBuffer $challenge, AuthorizationList $seAuthList, AuthorizationList $teeAuthList)
    {
        $this->seAuthList = $seAuthList;
        $this->teeAuthList = $teeAuthList;
        $this->challenge = $challenge;
    }

    /**
     * @return AuthorizationList
     */
    public function getSoftwareEnforcedAuthList(): AuthorizationList
    {
        return $this->seAuthList;
    }

    /**
     * @return AuthorizationList
     */
    public function getTeeEnforcedAuthList(): AuthorizationList
    {
        return $this->teeAuthList;
    }

    /**
     * @return ByteBuffer
     */
    public function getChallenge(): ByteBuffer
    {
        return $this->challenge;
    }
}
