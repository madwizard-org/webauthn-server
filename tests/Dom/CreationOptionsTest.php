<?php


namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\CredentialCreationOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialCreationOptions;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialRpEntity;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Format\ByteBuffer;
use PHPUnit\Framework\TestCase;

class CreationOptionsTest extends TestCase
{
    public function testMinimal()
    {
        $rp = new PublicKeyCredentialRpEntity('RP');
        $user = new PublicKeyCredentialUserEntity('testuser', ByteBuffer::fromHex('1234'), 'Test user');
        $challenge = ByteBuffer::fromHex('0123456789abcdef');
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
                            '$buffer$id' => 'EjQ',
                            'displayName' => 'Test user',
                        ],
                        '$buffer$challenge' => 'ASNFZ4mrze8',
                        'pubKeyCredParams' => [],
                    ],
            ],
            $arr
        );
    }
}
