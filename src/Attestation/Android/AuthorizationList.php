<?php


namespace MadWizard\WebAuthn\Attestation\Android;

use function in_array;

class AuthorizationList
{
    public const KM_ORIGIN_GENERATED = 0;

    public const KM_PURPOSE_SIGN = 2;

    /**
     * @var int[]
     */
    private $purposeList = [];

    /**
     * @var bool
     */
    private $allApplications = false;

    /**
     * @var int|null
     */
    private $origin;

    /**
     * @return bool
     */
    public function hasPurpose(int $purpose): bool
    {
        return in_array($purpose, $this->purposeList, true);
    }

    /**
     * @return int[]
     */
    public function getPurposeList(): array
    {
        return $this->purposeList;
    }

    public function addPurpose(int $purpose)
    {
        $this->purposeList[] = $purpose;
    }

    /**
     * @return bool
     */
    public function hasAllApplications(): bool
    {
        return $this->allApplications;
    }

    /**
     * @param bool $allApplications
     */
    public function setAllApplications(bool $allApplications): void
    {
        $this->allApplications = $allApplications;
    }

    /**
     * @return int|null
     */
    public function getOrigin(): ?int
    {
        return $this->origin;
    }

    /**
     * @param int|null $origin
     */
    public function setOrigin(?int $origin): void
    {
        $this->origin = $origin;
    }
}
