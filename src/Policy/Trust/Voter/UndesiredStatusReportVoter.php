<?php


namespace MadWizard\WebAuthn\Policy\Trust\Voter;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustVote;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

final class UndesiredStatusReportVoter implements TrustVoterInterface
{
    public function voteOnTrust(
        RegistrationResultInterface $registrationResult,
        TrustPathInterface $trustPath,
        ?MetadataInterface $metadata
    ): TrustVote {
        if ($metadata === null) {
            return TrustVote::abstain();
        }

        foreach ($metadata->getStatusReports() as $sr) {
            if ($sr->hasUndesiredStatus()) {
                return TrustVote::untrusted();
            }
        }
        return TrustVote::abstain();
    }
}
