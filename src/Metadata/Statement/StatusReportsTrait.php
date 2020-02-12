<?php


namespace MadWizard\WebAuthn\Metadata\Statement;

trait StatusReportsTrait
{
    private $statusReports = [];

    /**
     * @return array
     */
    public function getStatusReports(): array
    {
        return $this->statusReports;
    }

    /**
     * @param array $statusReports
     */
    public function setStatusReports(array $statusReports): void
    {
        $this->statusReports = $statusReports;
    }
}
