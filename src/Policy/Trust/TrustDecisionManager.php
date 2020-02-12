<?php


namespace MadWizard\WebAuthn\Policy\Trust;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Policy\Trust\Voter\TrustVoterInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

final class TrustDecisionManager implements TrustDecisionManagerInterface
{
    /**
     * @var TrustVoterInterface[]
     */
    private $voters = [];

    public function addVoter(TrustVoterInterface $trustVoter): self
    {
        $this->voters[] = $trustVoter;
        return $this;
    }

    // TODO: return details in case untrusted?
    public function isTrusted(RegistrationResultInterface $registrationResult, ?MetadataInterface $metadata): bool
    {
        $trusted = false;
        $trustPath = $registrationResult->getVerificationResult()->getTrustPath();
        foreach ($this->voters as $voter) {
            $vote = $voter->voteOnTrust($registrationResult, $trustPath, $metadata); // todo remove trustpath?? in regresult
            if ($vote === TrustVoterInterface::VOTE_TRUSTED) {
                $trusted = true;
            } elseif ($vote === TrustVoterInterface::VOTE_UNTRUSTED) {
                return false;
            } elseif ($vote !== TrustVoterInterface::VOTE_ABSTAIN) {
                throw new WebAuthnException(sprintf("Invalid vote result '%s' (class %s)", $vote, get_class($voter)));
            }
        }

        return $trusted;
    }
}
