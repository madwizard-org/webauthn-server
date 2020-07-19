<?php

namespace MadWizard\WebAuthn\Exception;

class UntrustedException extends VerificationException
{
    /**
     * @var string|null
     */
    private $reason;

    public function getReason(): ?string
    {
        return $this->reason;
    }

    public static function createWithReason(?string $reason): self
    {
        $e = new UntrustedException($reason === null ? 'Not trusted' : sprintf('Not trusted: %s', $reason));
        $e->reason = $reason;
        return $e;
    }
}
