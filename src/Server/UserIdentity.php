<?php


namespace MadWizard\WebAuthn\Server;

use MadWizard\WebAuthn\Dom\PublicKeyCredentialUserEntity;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;

class UserIdentity
{
    /**
     * @var ByteBuffer
     */
    private $userHandle;

    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $displayName;

    public function __construct(ByteBuffer $userHandle, string $username, string $displayName)
    {
        $length = $userHandle->getLength();
        if ($length === 0 || $length > PublicKeyCredentialUserEntity::MAX_USER_HANDLE_BYTES) {
            throw new WebAuthnException('Invalid user handle length.');
        }

        $this->userHandle = $userHandle;
        $this->username = $username;
        $this->displayName = $displayName;
    }

    /**
     * @return ByteBuffer
     */
    public function getUserHandle(): ByteBuffer
    {
        return $this->userHandle;
    }

    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getDisplayName(): string
    {
        return $this->displayName;
    }
}
