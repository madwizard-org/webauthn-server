<?php


namespace MadWizard\WebAuthn\Policy\Trust\Voter;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustAnchor\TrustPathValidatorInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
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
    ): string {
        if ($metadata === null) {
            return self::VOTE_ABSTAIN;
        }

        $trustAnchors = $metadata->getTrustAnchors();
        foreach ($trustAnchors as $anchor) {
            if ($this->pathValidator->validate($trustPath, $anchor)) {
                return self::VOTE_TRUSTED;
            }
        }
        return self::VOTE_ABSTAIN;
    }
}
