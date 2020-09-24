<?php

namespace MadWizard\WebAuthn\Tests\Dom;

use MadWizard\WebAuthn\Dom\AttestationConveyancePreference;
use MadWizard\WebAuthn\Dom\AuthenticatorAttachment;
use MadWizard\WebAuthn\Dom\AuthenticatorTransport;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialType;
use MadWizard\WebAuthn\Dom\TokenBindingStatus;
use MadWizard\WebAuthn\Dom\UserVerificationRequirement;
use PHPUnit\Framework\TestCase;

class EnumerationTest extends TestCase
{
    public function testAttestationPreference()
    {
        self::assertTrue(AttestationConveyancePreference::isValidValue(AttestationConveyancePreference::NONE));
        self::assertTrue(AttestationConveyancePreference::isValidValue(AttestationConveyancePreference::DIRECT));
        self::assertTrue(AttestationConveyancePreference::isValidValue(AttestationConveyancePreference::INDRECT));

        self::assertFalse(AttestationConveyancePreference::isValidValue('xyz'));
    }

    public function testPublicKeyCredentialType()
    {
        self::assertTrue(PublicKeyCredentialType::isValidType(PublicKeyCredentialType::PUBLIC_KEY));
        self::assertFalse(PublicKeyCredentialType::isValidType('xyz'));
    }

    public function testUserVerificationRequirement()
    {
        self::assertTrue(UserVerificationRequirement::isValidValue(UserVerificationRequirement::REQUIRED));
        self::assertTrue(UserVerificationRequirement::isValidValue(UserVerificationRequirement::PREFERRED));
        self::assertTrue(UserVerificationRequirement::isValidValue(UserVerificationRequirement::DISCOURAGED));

        self::assertFalse(UserVerificationRequirement::isValidValue('xyz'));
    }

    public function testTransports()
    {
        $known = AuthenticatorTransport::allKnownTransports();
        self::assertContains(AuthenticatorTransport::USB, $known);
        self::assertContains(AuthenticatorTransport::NFC, $known);
        self::assertContains(AuthenticatorTransport::BLE, $known);
        // self::assertContains(AuthenticatorTransport::INTERNAL, $known);
    }

    public function testAttachment()
    {
        self::assertTrue(AuthenticatorAttachment::isValidValue(AuthenticatorAttachment::PLATFORM));
        self::assertTrue(AuthenticatorAttachment::isValidValue(AuthenticatorAttachment::CROSS_PLATFORM));
        self::assertFalse(AuthenticatorAttachment::isValidValue('xyz'));
    }

    public function testTokenBindingStatus()
    {
        self::assertTrue(TokenBindingStatus::isValidValue(TokenBindingStatus::SUPPORTED));
        self::assertTrue(TokenBindingStatus::isValidValue(TokenBindingStatus::PRESENT));
        self::assertFalse(TokenBindingStatus::isValidValue('xyz'));
    }

    public function testAuthenticatorTransport()
    {
        self::assertTrue(AuthenticatorTransport::isValidValue(AuthenticatorTransport::USB));
        self::assertFalse(AuthenticatorTransport::isValidValue('xyz'));
    }
}
