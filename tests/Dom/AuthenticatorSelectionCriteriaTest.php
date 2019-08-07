<?php

namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\AuthenticatorAttachment;
use MadWizard\WebAuthn\Dom\AuthenticatorSelectionCriteria;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use PHPUnit\Framework\TestCase;

class AuthenticatorSelectionCriteriaTest extends TestCase
{

    public function testDefault()
    {
        $criteria = new AuthenticatorSelectionCriteria();
        $this->assertNull($criteria->getAuthenticatorAttachment());
        $this->assertNull($criteria->getRequireResidentKey());
        $this->assertNull($criteria->getUserVerification());
    }

    public function testWrongAttachment()
    {
        $criteria = new AuthenticatorSelectionCriteria();
        $this->expectException(\InvalidArgumentException::class);
        $criteria->setAuthenticatorAttachment('invalid');
    }

    public function testWrongVerification()
    {
        $criteria = new AuthenticatorSelectionCriteria();
        $this->expectException(\InvalidArgumentException::class);
        $criteria->setUserVerification('invalid');
    }

    public function testFull()
    {
        $criteria = new AuthenticatorSelectionCriteria();
        $criteria->setUserVerification(UserVerificationRequirement::DISCOURAGED);
        $criteria->setAuthenticatorAttachment(AuthenticatorAttachment::CROSS_PLATFORM);
        $criteria->setRequireResidentKey(true);
        $this->assertSame(UserVerificationRequirement::DISCOURAGED, $criteria->getUserVerification());
        $this->assertSame(AuthenticatorAttachment::CROSS_PLATFORM, $criteria->getAuthenticatorAttachment());
        $this->assertTrue($criteria->getRequireResidentKey());
    }


}
