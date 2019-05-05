<?php

namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\AttestationConveyancePreference;
use MadWizard\WebAuthn\Dom\AuthenticatorSelectionCriteria;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use PHPUnit\Framework\TestCase;

class PublicKeyCredentialCreationOptionsTest extends TestCase
{
    use DomTestTrait;

    public function testMinimal()
    {
        $rp = $this->createRpEntity();
        $user = $this->createUserEntity();
        $challenge = $this->createChallenge();
        $options = new PublicKeyCredentialCreationOptions($rp, $user, $challenge, []);

        $this->assertSame($rp, $options->getRpEntity());
        $this->assertSame($user, $options->getUserEntity());
        $this->assertSame($challenge->getHex(), $options->getChallenge()->getHex());
        $this->assertEmpty($options->getCredentialParameters());

        $this->assertNull($options->getTimeout());
        $this->assertNull($options->getExcludeCredentials());
        $this->assertNull($options->getAuthenticatorSelection());
        $this->assertNull($options->getAttestation());

        $this->assertSame(
            [
                'rp' => [
                    'name' => 'RP',
                ],
                'user' => [
                    'name' => 'testuser',
                    'id' => 'EjQ',
                    'displayName' => 'Test user',
                ],
                'challenge' => 'ASNFZ4mrze8',
                'pubKeyCredParams' => [],
            ],
            $options->getJsonData()
        );
    }

    public function testSetters()
    {
        $rp = $this->createRpEntity();
        $user = $this->createUserEntity();
        $challenge = $this->createChallenge();
        $options = new PublicKeyCredentialCreationOptions($rp, $user, $challenge, []);

        $options->setAttestation(AttestationConveyancePreference::DIRECT);
        $this->assertSame(AttestationConveyancePreference::DIRECT, $options->getAttestation());

        $authSelection = new AuthenticatorSelectionCriteria();
        $authSelection->setUserVerification(UserVerificationRequirement::REQUIRED);

        $options->setAuthenticatorSelection($authSelection);
        $this->assertSame($authSelection, $options->getAuthenticatorSelection());


        $this->assertSame(
            [
                'rp' => [
                        'name' => 'RP',
                    ],
                'user' => [
                        'name' => 'testuser',
                        'id' => 'EjQ',
                        'displayName' => 'Test user',
                    ],
                'challenge' => 'ASNFZ4mrze8',
                'pubKeyCredParams' => [],
                'authenticatorSelection' => [
                        'userVerification' => 'required',
                    ],
                'attestation' => 'direct',
            ],
            $options->getJsonData()
        );
    }
}
