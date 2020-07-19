<?php

namespace MadWizard\WebAuthn\Policy\Trust\Voter;

use MadWizard\WebAuthn\Attestation\TrustAnchor\MetadataInterface;
use MadWizard\WebAuthn\Attestation\TrustPath\TrustPathInterface;
use MadWizard\WebAuthn\Policy\Trust\TrustVote;
use MadWizard\WebAuthn\Server\Registration\RegistrationResultInterface;

interface TrustVoterInterface
{
    public function voteOnTrust(RegistrationResultInterface $registrationResult, TrustPathInterface $trustPath, ?MetadataInterface $metadata): TrustVote;
}
