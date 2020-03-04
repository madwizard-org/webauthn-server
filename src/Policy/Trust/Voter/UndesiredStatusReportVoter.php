<?php


namespace MadWizard\WebAuthn\Policy\Trust\Voter;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

final class UndesiredStatusReportVoter implements TrustVoterInterface
{
    public function voteOnTrust(
        RegistrationResultInterface $registrationResult,
        TrustPathInterface $trustPath,
        ?MetadataInterface $metadata
    ): string {
        if ($metadata === null) {
            return self::VOTE_ABSTAIN;
        }

        foreach ($metadata->getStatusReports() as $sr) {
            if ($sr->hasUndesiredStatus()) {
                return self::VOTE_UNTRUSTED;
            }
        }

        return self::VOTE_ABSTAIN;
    }
}
