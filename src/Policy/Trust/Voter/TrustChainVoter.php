<?php


namespace MadWizard\WebAuthn\Policy\Trust\Voter;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidatorInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustVote;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

final class TrustChainVoter implements TrustVoterInterface
{
    /**
     * @var TrustPathValidatorInterface
     */
    private $pathValidator;

    public function __construct(TrustPathValidatorInterface $pathVal)
    {
        $this->pathValidator = $pathVal;
    }

    public function voteOnTrust(
        RegistrationResultInterface $registrationResult,
        TrustPathInterface $trustPath,
        ?MetadataInterface $metadata
    ): TrustVote {
        if ($metadata === null) {
            return TrustVote::abstain();
        }

        $trustAnchors = $metadata->getTrustAnchors();
        foreach ($trustAnchors as $anchor) {
            if ($this->pathValidator->validate($trustPath, $anchor)) {
                return TrustVote::trusted();
            }
        }
        return TrustVote::abstain();
    }
}
