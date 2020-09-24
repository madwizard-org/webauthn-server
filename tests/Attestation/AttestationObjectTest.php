<?php

namespace MadWizard\WebAuthn\Tests\Attestation;

use MadWizard\WebAuthn\Attestation\AttestationObject;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;
use function bin2hex;

class AttestationObjectTest extends TestCase
{
    public function testInvalidEmpty()
    {
        $this->expectException(WebAuthnException::class);
        AttestationObject::parse(new ByteBuffer(''));
    }

    public function testInvalidType()
    {
        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~expecting.+Cbor map~i');
        AttestationObject::parse(ByteBuffer::fromHex('10'));
    }

    public function testFormatType()
    {
        $buf = HexData::buf(
            'A3                     # map(3)
                63                  # text(3)
                   666D74           # "fmt"
                10                  # unsigned(16)
                67                  # text(7)
                   61747453746D74   # "attStmt"
                A0                  # map(0)
                68                  # text(8)
                   6175746844617461 # "authData"
                41                  # bytes(1)
                   AA               # "\xAA"
            '
        );

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~expecting.+fmt.+string~i');
        AttestationObject::parse($buf);
    }

    public function testStatementType()
    {
        $buf = HexData::buf(
            'A3                     # map(3)
                63                  # text(3)
                   666D74           # "fmt"
                68                  # text(8)
                   6669646F2D753266 # "fido-u2f"
                67                  # text(7)
                   61747453746D74   # "attStmt"
                10                  # unsigned(16)
                68                  # text(8)
                   6175746844617461 # "authData"
                41                  # bytes(1)
                   AA               # "\xAA"
            '
        );

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~Expecting key "attStmt".+CborMap~i');
        AttestationObject::parse($buf);
    }

    public function testAuthDataType()
    {
        $buf = HexData::buf(
            'A3                     # map(3)
                63                  # text(3)
                   666D74           # "fmt"
                68                  # text(8)
                   6669646F2D753266 # "fido-u2f"
                67                  # text(7)
                   61747453746D74   # "attStmt"
                A0                  # map(0)
                68                  # text(8)
                   6175746844617461 # "authData"
                10                  # unsigned(16)
            '
        );

        $this->expectException(WebAuthnException::class);
        $this->expectExceptionMessageMatches('~expecting.+authData.+byte~i');
        AttestationObject::parse($buf);
    }

    public function testU2f()
    {
        $json = FixtureHelper::getJsonFixture('fido2-helpers/attestation.json');
        $message = $json['challengeResponseAttestationU2fMsgB64Url'];
        $message['type'] = 'public-key';
        $cred = JsonConverter::decodeAttestation($message);

        self::assertSame('Bo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IirQ', $cred->getId());

        self::assertSame(
            '{"challenge":"Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA",' .
            '"clientExtensions":{},"hashAlgorithm":"SHA-256","origin":"https://localhost:8443","type":"webauthn.create"}',
            $cred->getResponse()->getClientDataJson()
        );

        $response = $cred->getResponse()->asAttestationResponse();
        $buffer = $response->getAttestationObject();

        $decoded = AttestationObject::parse($buffer);

        self::assertSame('fido-u2f', $decoded->getFormat());
        $authData = HexData::bin(
            '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763
             41
             00000000
             0000000000000000000000000000000
             00040
             068f958c73a4259cbc0e39c226721cd0ec6df50033e6ea4c75227135b77e1b2
             028e8c348bcf05bf58b14944d1925a6965ed587e454323d2e9b4ff7baf7c222
             ada50102032620012158203573d008787e6c37ac7543edaa47bbf6e79b64786
             6d6b34102083c37e642460422582018d3531aee69d8c514c9d6951e6b3c9af6
             dec0494fda9ec58f4f09cf68f21993
            '
        );
        self::assertSame(bin2hex($authData), $decoded->getAuthenticatorData()->getHex());
        $statement = $decoded->getStatement();
        self::assertArrayHasKey('x5c', $statement);
    }
}
