<?php

namespace MadWizard\WebAuthn\Policy\Trust\Voter;

use InvalidArgumentException;
use MadWizard\WebAuthn\Attestation\AttestationType;
use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustVote;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

final class TrustAttestationTypeVoter implements TrustVoterInterface
{
    /**
     * @var string
     */
    private $trustedType;

    public function __construct(string $attestationType)
    {
        if (!AttestationType::isValidType($attestationType)) {
            throw new InvalidArgumentException(sprintf('Type "%s" is not a valid attestation type.', $attestationType));
        }

        $this->trustedType = $attestationType;
    }

    public function voteOnTrust(
        RegistrationResultInterface $registrationResult,
        TrustPathInterface $trustPath,
        ?MetadataInterface $metadata
    ): TrustVote {
        if ($registrationResult->getVerificationResult()->getAttestationType() === $this->trustedType) {
            return TrustVote::trusted();
        }
        return TrustVote::abstain();
    }
}
