<?php


namespace MadWizard\WebAuthn\Tests\Crypto;

use MadWizard\WebAuthn\Crypto\CoseKey;
use MadWizard\WebAuthn\Crypto\RsaKey;
use MadWizard\WebAuthn\Dom\CoseAlgorithm;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Tests\Helper\HexData;
use PHPUnit\Framework\TestCase;

class RsaKeyTest extends TestCase
{
    private const TEST_KEY_MODULUS =
        'aad13a1fa831fabdd755669ebcbf743e2e1f7221c88a136d607eac5ea76ad431' .
        'bb403ac5c36cd289e90ce64fc703472bb725996ae15d4883abd8c78365a293c3' .
        'c86dc8b09e0c6e8fe70562b1aa86185db54783108fcf6bc48cf625396ad71296' .
        'f2c513b01d999b8656977fcf519950f9308ae2efece92f21f5a67f0f4ea7ed36' .
        '75cdf1e6f4d89f184fd5da66de91764b483fdaf4c0d3b992a986ae4429888593' .
        '10f91bf8d09f15a8da69810930f2422d39703e2660907524a7dc9fe652ac874f' .
        'f56726a8b9f53df54b68ddfbf6999b18ca402003e478b5ccf074a423332595f4' .
        '9152242e1b5c435b6a54e2a873678b77a4d33dfa826026dd490548ca6dcca9ad';

    private const TEST_KEY_EXPONENT = '010001';

    public function testSignature()
    {
        $sigData = HexData::bin(
            '5C2462DE83AFE41C3D392CE09129396F5206C702022C276FE6C75325B89A0C24
             DD7E99CC6E5B60846C5F573EDC1132A2B0955E9B2EB69DF1E8506ED712776803
             E174311AA12FF0D602290FEAFA1C981EC56B870E2BD373738CA846F07F6C4F6F
             508997E334D44D691C157C2A484C9B1873A5BFC87607A5A70417F02FACBEAA70
             6AFC6E557FD4FCCA8A991F76005173EBCB3894DFB42B06678637C0E7DD13CF02
             C36972AE9B5FA209C2A93E0FF5FE4A83D80E5C5BADC3EC746C2699659EEBB0E8
             E7746866A2E14561F0608E50B2B47E4648AC2186EA0E833AADF55C35D8FE9F2B
             9809CE9ACE74C2D7BAF62F5F97F3704C2CADE07AD007D17D237746A4E4CF5F8D'
        );

        $signature = new ByteBuffer($sigData);

        // Change one byte
        $wrongData = $sigData;
        $wrongData[10] = "\x2B";
        $wrongSignature = new ByteBuffer($wrongData);


        $message = new ByteBuffer('testmessage');

        $key = $this->getKey();

        $valid = $key->verifySignature($message, $signature);
        $this->assertTrue($valid);


        $valid = $key->verifySignature($message, $wrongSignature);
        $this->assertFalse($valid);
    }

    public function testPEM()
    {
        $pem = $this->getKey()->asPem();

        $this->assertSame(
            "-----BEGIN PUBLIC KEY-----\n" .
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqtE6H6gx+r3XVWaevL90\n" .
            "Pi4fciHIihNtYH6sXqdq1DG7QDrFw2zSiekM5k/HA0crtyWZauFdSIOr2MeDZaKT\n" .
            "w8htyLCeDG6P5wVisaqGGF21R4MQj89rxIz2JTlq1xKW8sUTsB2Zm4ZWl3/PUZlQ\n" .
            "+TCK4u/s6S8h9aZ/D06n7TZ1zfHm9NifGE/V2mbekXZLSD/a9MDTuZKphq5EKYiF\n" .
            "kxD5G/jQnxWo2mmBCTDyQi05cD4mYJB1JKfcn+ZSrIdP9WcmqLn1PfVLaN379pmb\n" .
            "GMpAIAPkeLXM8HSkIzMllfSRUiQuG1xDW2pU4qhzZ4t3pNM9+oJgJt1JBUjKbcyp\n" .
            "rQIDAQAB\n" .
            "-----END PUBLIC KEY-----\n",
            $pem
        );
    }

    public function testProperties()
    {
        $key = $this->getKey();

        $this->assertSame(self::TEST_KEY_MODULUS, $key->getModulus()->getHex());
        $this->assertSame(self::TEST_KEY_EXPONENT, $key->getExponent()->getHex());

        $this->assertSame(CoseAlgorithm::RS256, $key->getAlgorithm());
    }

    public function testInvalidCbor()
    {
        $this->expectException(WebAuthnException::class);
        RsaKey::fromCborData([]);
    }

    public function testRemoveLeadingZeroes()
    {
        $mod = ByteBuffer::fromHex('000000000000' . self::TEST_KEY_MODULUS);
        $exp = ByteBuffer::fromHex('000000000000' . self::TEST_KEY_EXPONENT);
        $key = new RsaKey($mod, $exp, CoseAlgorithm::RS256);

        $this->assertSame(self::TEST_KEY_MODULUS, $key->getModulus()->getHex());
        $this->assertSame(self::TEST_KEY_EXPONENT, $key->getExponent()->getHex());
    }

    public function testCbor()
    {
        // Example key from webauthn spec
        $cbor = HexData::buf(
            sprintf(
                'A4        
             01  03          #   1:   3,    ; kty: RSA   key type
             03  39 0100     #   3:  -257,  ; alg: RS256 signature algorithm
             20  59 0100 %s  #  -1:   m,    ; modulus
             21  43 %s       #  -2:   e,    ; exponent',
                self::TEST_KEY_MODULUS,
                self::TEST_KEY_EXPONENT
        )
        );

        $key = CoseKey::parseCbor($cbor);
        $this->assertInstanceOf(RsaKey::class, $key);
        /** @var $key RsaKey */

        $this->assertSame(CoseAlgorithm::RS256, $key->getAlgorithm());
        $this->assertSame(self::TEST_KEY_MODULUS, $key->getModulus()->getHex());
        $this->assertSame(self::TEST_KEY_EXPONENT, $key->getExponent()->getHex());

        // Transform back
        $output = $key->getCbor();

        $this->assertSame($cbor->getHex(), $output->getHex());
    }

    private function getKey(): RsaKey
    {
        $mod = ByteBuffer::fromHex(self::TEST_KEY_MODULUS);
        $exp = ByteBuffer::fromHex(self::TEST_KEY_EXPONENT);
        return new RsaKey($mod, $exp, CoseAlgorithm::RS256);
    }
}
