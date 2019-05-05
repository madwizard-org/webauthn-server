<?php


namespace MadWizard\WebAuthn\Attestation\TrustAnchor;

class DefaultTrustAnchorFactory implements TrustAnchorFactoryInterface
{
    private $map;

    public function __construct()
    {
        $this->map = [
            'none' => function (array $options) {
                return new NoneTrustAnchor();
            },
            'self' => function (array $options) {
                return new SelfTrustAnchor();
            },
            'u2f-yubico' => function (array $options) {
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
    }
}
