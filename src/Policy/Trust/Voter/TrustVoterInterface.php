<?php


namespace MadWizard\WebAuthn\Policy\Trust\Voter;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

interface TrustVoterInterface
{
    public const VOTE_TRUSTED = 'trusted';

    public const VOTE_UNTRUSTED = 'untrusted';

    public const VOTE_ABSTAIN = 'abstain';

    public function voteOnTrust(RegistrationResultInterface $registrationResult, TrustPathInterface $trustPath, ?MetadataInterface $metadata): string;
}
