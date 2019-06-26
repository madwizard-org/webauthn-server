<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

use RuntimeException;

class DefaultTrustAnchorFactory implements TrustAnchorFactoryInterface
{
    private $map;

    public function __construct()
    {
        $this->map = [
            'none' => function () {
                return new NoneTrustAnchor();
            },
            'self' => function () {
                return new SelfTrustAnchor();
            },
            'u2f-yubico' => function () {
                return new U2FMetadataAnchor(__DIR__ . '/../../../data/yubico/yubico-metadata.json');
            },
            'fido-mds1' => function (array $options) {
                return new MetadataServiceAnchor(1, $options);
            },
            'fido-mds2' => function (array $options) {
                return new MetadataServiceAnchor(2, $options);
            },
        ];
    }

    public function createTrustAnchor(string $name): TrustAnchorInterface
    {
        // TODO: Implement createTrustAnchor() method.
        throw new RuntimeException('Not implemented yet');
    }
}
