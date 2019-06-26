<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use MadWizard\WebAuthn\Attestation\Verifier\VerificationResult;

class TrustAnchorSet implements TrustAnchorSetInterface
{
    /**
     * @var TrustAnchorInterface[]
     */
    private $trustAnchors = [];

    public function __construct()
    {
    }

    public function addTrustAnchor(TrustAnchorInterface $trustAnchor)
    {
        $this->trustAnchors[] = $trustAnchor;
    }

    public function isTrusted(VerificationResult $verificationResult): TrustStatus
    {
        foreach ($this->trustAnchors as $trustAnchor) {
            $trustStatus = $trustAnchor->isTrusted($verificationResult);
            if ($trustStatus->isTrusted()) {
                return $trustStatus;
            }
        }
        return TrustStatus::notTrusted();
    }
}
