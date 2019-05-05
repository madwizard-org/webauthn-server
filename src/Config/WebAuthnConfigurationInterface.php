<?php


namespace MadWizard\WebAuthn\Config;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialRpEntity;
use MadWizard\WebAuthn\Web\Origin;

interface WebAuthnConfigurationInterface
{
    /**
     * Returns the configured relying party id when set.
     * @return null|string
     */
    public function getRelyingPartyId(): ?string;

    /**
     * Returns the configured relying party id when set, otherwise the returned value will be the domain name
     * part of the relying party origin.
     * @return string
     */
    public function getEffectiveRelyingPartyId() : string;

    /**
     * Returns a PublicKeyCredentialRpEntity structure based on the configured values
     * @return PublicKeyCredentialRpEntity
     */
    public function getRelyingPartyEntity() : PublicKeyCredentialRpEntity;

    public function getRelyingPartyOrigin() : ?Origin;

    public function getChallengeLength(): int;

    public function getAllowedAlgorithms() : array;

    public function getRelyingPartyIconUrl() : ?string;
}
