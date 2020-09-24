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
        self::assertNull($criteria->getAuthenticatorAttachment());
        self::assertNull($criteria->getRequireResidentKey());
        self::assertNull($criteria->getUserVerification());
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
        self::assertSame(UserVerificationRequirement::DISCOURAGED, $criteria->getUserVerification());
        self::assertSame(AuthenticatorAttachment::CROSS_PLATFORM, $criteria->getAuthenticatorAttachment());
        self::assertTrue($criteria->getRequireResidentKey());
    }
}
