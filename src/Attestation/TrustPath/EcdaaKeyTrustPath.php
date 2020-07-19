<?php

namespace MadWizard\WebAuthn\Attestation\TrustPath;

use MadWizard\WebAuthn\Format\ByteBuffer;

class EcdaaKeyTrustPath implements TrustPathInterface
{
    /**
     * @var ByteBuffer
     */
    private $ecdaaKeyId;

    public function __construct(ByteBuffer $ecdaaKeyId)
    {
        $this->ecdaaKeyId = $ecdaaKeyId;
    }

    public function getEcdaaKeyId(): ByteBuffer
    {
        return $this->ecdaaKeyId;
    }
}
