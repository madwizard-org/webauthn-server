<?php


namespace MadWizard\WebAuthn\Policy\Trust;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Exception\UntrustedException;
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

    public function verifyTrust(RegistrationResultInterface $registrationResult, ?MetadataInterface $metadata): void
    {
        $trusted = false;
        $trustPath = $registrationResult->getVerificationResult()->getTrustPath();
        foreach ($this->voters as $voter) {
            $vote = $voter->voteOnTrust($registrationResult, $trustPath, $metadata);
            if ($vote->isTrusted()) {
                $trusted = true;
            } elseif ($vote->isUntrusted()) {
                throw UntrustedException::createWithReason($vote->getReason());
            } elseif (!$vote->isAbstain()) {
                throw new WebAuthnException('Unsupported vote type.');
            }
        }

        if (!$trusted) {
            throw UntrustedException::createWithReason('No voter trusted the registration.');
        }
    }
}
