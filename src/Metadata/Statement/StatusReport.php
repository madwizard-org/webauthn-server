<?php

namespace MadWizard\WebAuthn\Metadata\Statement;

use MadWizard\WebAuthn\Format\DataValidator;

class StatusReport
{
    /**
     * @var string
     *
     * @see AuthenticatorStatus
     */
    private $status;

    /**
     * @var string|null
     */
    private $effectiveDate;

    /**
     * @var string|null
     */
    private $certificate;

    /**
     * @var string|null
     */
    private $url;

    /**
     * @var string|null
     */
    private $certificationDescriptor;

    /**
     * @var string|null
     */
    private $certificateNumber;

    /**
     * @var string|null
     */
    private $certificationPolicyVersion;

    /**
     * @var string|null
     */
    private $certificationRequirementsVersion;

    private function __construct(array $values)
    {
        $this->status = $values['status'];
        $this->effectiveDate = $values['effectiveDate'] ?? null;
        $this->certificate = $values['certificate'] ?? null;
        $this->url = $values['url'] ?? null;
        $this->certificationDescriptor = $values['certificationDescriptor'] ?? null;
        $this->certificateNumber = $values['certificateNumber'] ?? null;
        $this->certificationPolicyVersion = $values['certificationPolicyVersion'] ?? null;
        $this->certificationRequirementsVersion = $values['certificationRequirementsVersion'] ?? null;
    }

    public static function fromArray(array $report): self
    {
        DataValidator::checkArray($report, [
            'status' => 'string',
            'effectiveDate' => '?string',
            'certificate' => '?string',
            'url' => '?string',
            'certificationDescriptor' => '?string',
            'certificateNumber' => '?string',
            'certificationPolicyVersion' => '?string',
            'certificationRequirementsVersion' => '?string',
        ], false);

        return new StatusReport($report);
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function hasUndesiredStatus(): bool
    {
        return in_array($this->status, AuthenticatorStatus::LIST_UNDESIRED_STATUS, true);
    }

    public function getEffectiveDate(): ?string
    {
        return $this->effectiveDate;
    }

    public function getCertificate(): ?string
    {
        return $this->certificate;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function getCertificationDescriptor(): ?string
    {
        return $this->certificationDescriptor;
    }

    public function getCertificateNumber(): ?string
    {
        return $this->certificateNumber;
    }

    public function getCertificationPolicyVersion(): ?string
    {
        return $this->certificationPolicyVersion;
    }

    public function getCertificationRequirementsVersion(): ?string
    {
        return $this->certificationRequirementsVersion;
    }
}
