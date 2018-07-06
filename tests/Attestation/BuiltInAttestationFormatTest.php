<?php

namespace MadWizard\WebAuthn\Attestation;

use MadWizard\WebAuthn\Attestation\Registry\BuiltInAttestationFormat;
use MadWizard\WebAuthn\Attestation\Statement\AttestationStatementInterface;
use MadWizard\WebAuthn\Attestation\Verifier\StatementVerifierInterface;
use PHPUnit\Framework\TestCase;

class BuiltInAttestationFormatTest extends TestCase
{
    public function test()
    {
        $this->getMockBuilder(AttestationStatementInterface::class)
            ->setMockClassName('TestStatement')
            ->getMock();
        $this->getMockBuilder(StatementVerifierInterface::class)
            ->setMockClassName('TestVerifier')
            ->getMock();

        $format = new BuiltInAttestationFormat('testformat', 'TestStatement', 'TestVerifier');
        $this->assertSame('testformat', $format->getFormatId());

        /** @var AttestationObject $attObj */
        $attObj = $this->createMock(AttestationObject::class);

        $statement = $format->createStatement($attObj);
        $this->assertInstanceOf('TestStatement', $statement);
        $verifier = $format->getVerifier();
        $this->assertInstanceOf('TestVerifier', $verifier);
    }
}
