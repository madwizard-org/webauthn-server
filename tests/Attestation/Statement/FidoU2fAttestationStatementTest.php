<?php


namespace MadWizard\WebAuthn\Tests\Attestation\Statement;

use MadWizard\WebAuthn\Attestation\Statement\FidoU2fAttestationStatement;
use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Tests\Helper\FixtureHelper;
use PHPUnit\Framework\TestCase;

class FidoU2fAttestationStatementTest extends TestCase
{
    public function testFidoU2fTest()
    {
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationU2fMsgB64Url');
        $chains = FixtureHelper::getFidoTestPlain('certChains');

        $statement = new FidoU2fAttestationStatement($attObj);

        $this->assertSame('fido-u2f', $statement->getFormatId());

        $certChain = $statement->getCertificates();
        $this->assertSame($chains['fido-u2f'], $certChain);

        $this->assertSame(
            '3046022100efbaf3721226129d9943e655b42e619b29f25903ed825c2271d2dd039f6eb8' .
            'a8022100ce0309e3df5c05ccc1c3cdbaaf59b9e4999df664f87758845d84bc15b227f0ca',
            $statement->getSignature()->getHex()
        );
    }

    public function testFidoU2fHypersecuTest()
    {
        $attObj = FixtureHelper::getFidoTestObject('challengeResponseAttestationU2fHypersecuB64UrlMsg');
        $chains = FixtureHelper::getFidoTestPlain('certChains');

        $statement = new FidoU2fAttestationStatement($attObj);

        $this->assertSame('fido-u2f', $statement->getFormatId());

        $certChain = $statement->getCertificates();

        $this->assertSame($chains['fido-u2f-hypersecu'], $certChain);

        $this->assertSame(
            '3046022100db3162cfa7b5dbd78c46864e5f93f757e6a124020b32c4997a73c2e22a4abc' .
            'd4022100daf9f1fdc3f80a4f404abb99ecd742b472a57827ddd0dc021dcbf670c8f5ef92',
            $statement->getSignature()->getHex()
        );
    }

    public function testWrongChainDataType()
    {
        $attObj = FixtureHelper::getFidoTestObject('invalidFidoU2fCertList');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~x5c should be array of binary data elements~');
        new FidoU2fAttestationStatement($attObj);
    }

    public function testInvalidStatementMap()
    {
        $attObj = FixtureHelper::getFidoTestObject('invalidFidoU2fStatementMap');
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageRegExp('~invalid .+ attestation statement~i');
        new FidoU2fAttestationStatement($attObj);
    }

    public function testCreateFormat()
    {
        $format = FidoU2fAttestationStatement::createFormat();
        $this->assertSame(FidoU2fAttestationStatement::FORMAT_ID, $format->getFormatId());
    }
}
