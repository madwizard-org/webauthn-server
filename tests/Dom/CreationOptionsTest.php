<?php


namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\CredentialCreationOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use PHPUnit\Framework\TestCase;

class CreationOptionsTest extends TestCase
{
    use DomTestTrait;

    public function testMinimal()
    {
        $rp = $this->createRpEntity();
        $user = $this->createUserEntity();
        $challenge = $this->createChallenge();
        $pkOptions = new PublicKeyCredentialCreationOptions($rp, $user, $challenge, []);
        $options = new CredentialCreationOptions();
        $options->setPublicKeyOptions($pkOptions);

        $arr = $options->getJsonData();
        $this->assertSame(
            [
                'publicKey' =>
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
            ],
            $arr
        );
    }
}
