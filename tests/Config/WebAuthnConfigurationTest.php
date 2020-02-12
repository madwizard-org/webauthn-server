<?php

namespace MadWizard\WebAuthn\Tests\Config;

use MadWizard\WebAuthn\Attestation\Registry\AttestationFormatInterface;
use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\ConfigurationException;
use PHPUnit\Framework\TestCase;

class WebAuthnConfigurationTest extends TestCase
{
    public function testChallengeLength()
    {
        $config = new WebAuthnConfiguration();
        $this->assertSame(WebAuthnConfiguration::DEFAULT_CHALLENGE_LENGTH, $config->getChallengeLength());

        $config->setChallengeLength(128);
        $this->assertSame(128, $config->getChallengeLength());
    }

    public function testShortChallenge()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $config->setChallengeLength(2);
    }

    public function testDefaultAlgorithms()
    {
        $config = new WebAuthnConfiguration();
        $default = $config->getAllowedAlgorithms();
        $this->assertContains(CoseAlgorithm::ES256, $default);
        $this->assertContains(CoseAlgorithm::RS256, $default);
    }

//    public function testDefaultFormats()
//    {
//        $config = new WebAuthnConfiguration();
//        $formats = $config->getAttestationFormats();
//        $formatIds = array_map(
//            function (AttestationFormatInterface $f) {
//                return $f->getFormatId();
//            },
//            $formats
//        );
//
//        $this->assertContains('none', $formatIds);
//        $this->assertContains('fido-u2f', $formatIds);
//    }

    public function testSetAlgorithms()
    {
        $config = new WebAuthnConfiguration();
        $algorithms = [CoseAlgorithm::ES256];
        $config->setAllowedAlgorithms($algorithms);
        $this->assertSame($algorithms, $config->getAllowedAlgorithms());
    }

    public function testInvalidAlgorithms()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $algorithms = [1122334455];
        $config->setAllowedAlgorithms($algorithms);
    }

    public function testInvalidAlgorithmType()
    {
        $this->expectException(ConfigurationException::class);
        $config = new WebAuthnConfiguration();
        $algorithms = [CoseAlgorithm::ES256, 'not valid'];
        $config->setAllowedAlgorithms($algorithms);
    }
}
