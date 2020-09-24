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

        self::assertSame($rp, $options->getRpEntity());
        self::assertSame($user, $options->getUserEntity());
        self::assertSame($challenge->getHex(), $options->getChallenge()->getHex());
        self::assertEmpty($options->getCredentialParameters());

        self::assertNull($options->getTimeout());
        self::assertNull($options->getExcludeCredentials());
        self::assertNull($options->getAuthenticatorSelection());
        self::assertNull($options->getAttestation());

        self::assertSame(
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
        self::assertSame(AttestationConveyancePreference::DIRECT, $options->getAttestation());

        $authSelection = new AuthenticatorSelectionCriteria();
        $authSelection->setUserVerification(UserVerificationRequirement::REQUIRED);

        $options->setAuthenticatorSelection($authSelection);
        self::assertSame($authSelection, $options->getAuthenticatorSelection());

        self::assertSame(
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
