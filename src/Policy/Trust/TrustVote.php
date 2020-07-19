<?php

namespace MadWizard\WebAuthn\Policy\Trust;

class TrustVote
{
    public const VOTE_ABSTAIN = 'abstain';

    public const VOTE_TRUSTED = 'trusted';

    public const VOTE_UNTRUSTED = 'untrusted';

    /**
     * @var string
     */
    private $type;

    /**
     * @var string|null
     */
    private $reason;

    private function __construct(string $type, ?string $reason = null)
    {
        $this->type = $type;
        $this->reason = $reason;
    }

    public function isAbstain(): bool
    {
        return $this->type === self::VOTE_ABSTAIN;
    }

    public function isTrusted(): bool
    {
        return $this->type === self::VOTE_TRUSTED;
    }

    public function isUntrusted(): bool
    {
        return $this->type === self::VOTE_UNTRUSTED;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }

    public static function trusted(): self
    {
        return new TrustVote(self::VOTE_TRUSTED);
    }

    public static function abstain(): self
    {
        return new TrustVote(self::VOTE_ABSTAIN);
    }

    public static function untrusted(?string $reason = null): self
    {
        return new TrustVote(self::VOTE_UNTRUSTED, $reason);
    }
}
