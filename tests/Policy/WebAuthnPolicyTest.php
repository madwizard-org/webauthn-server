<?php

namespace MadWizard\WebAuthn\Tests\Policy;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatRegistry;
use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Crypto\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use MadWizard\WebAuthn\Metadata\NullMetadataResolver;
use MadWizard\WebAuthn\Policy\Policy;
use MadWizard\WebAuthn\Policy\Trust\TrustDecisionManager;
use PHPUnit\Framework\TestCase;

class WebAuthnPolicyTest extends TestCase
{
    /**
     * @var Policy
     */
    private $policy;

    protected function setUp(): void
    {
        $this->policy = new Policy(new RelyingParty('rp', 'http://localhost'), new NullMetadataResolver(), new TrustDecisionManager(), new AttestationFormatRegistry());
    }

    public function testChallengeLength()
    {
        self::assertSame(Policy::DEFAULT_CHALLENGE_LENGTH, $this->policy->getChallengeLength());

        $this->policy->setChallengeLength(128);
        self::assertSame(128, $this->policy->getChallengeLength());
    }

    public function testShortChallenge()
    {
        $this->expectException(ConfigurationException::class);
        $this->policy->setChallengeLength(2);
    }

    public function testDefaultAlgorithms()
    {
        $default = $this->policy->getAllowedAlgorithms();
        self::assertContains(CoseAlgorithm::ES256, $default);
        self::assertContains(CoseAlgorithm::RS256, $default);
    }

    public function testSetAlgorithms()
    {
        $algorithms = [CoseAlgorithm::ES256];
        $this->policy->setAllowedAlgorithms($algorithms);
        self::assertSame($algorithms, $this->policy->getAllowedAlgorithms());
    }

    public function testInvalidAlgorithms()
    {
        $this->expectException(ConfigurationException::class);
        $algorithms = [1122334455];
        $this->policy->setAllowedAlgorithms($algorithms);
    }

    public function testInvalidAlgorithmType()
    {
        $this->expectException(ConfigurationException::class);
        $algorithms = [CoseAlgorithm::ES256, 'not valid'];
        $this->policy->setAllowedAlgorithms($algorithms);
    }
}
