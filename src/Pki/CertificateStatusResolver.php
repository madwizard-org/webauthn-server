<?php


namespace MadWizard\WebAuthn\Pki;

use MadWizard\WebAuthn\Cache\CacheProviderInterface;
use MadWizard\WebAuthn\Exception\RemoteException;
use MadWizard\WebAuthn\Pki\Crl\CrlParser;
use MadWizard\WebAuthn\Remote\DownloaderInterface;
use Psr\Cache\CacheItemPoolInterface;
use X509\Certificate\Certificate;

final class CertificateStatusResolver implements CertificateStatusResolverInterface
{
    /** @var CacheItemPoolInterface  */
    private $cache;

    /**
     * @var DownloaderInterface
     */
    private $downloader;

    public function __construct(DownloaderInterface $downloader, CacheProviderInterface $cacheProvider)
    {
        $this->downloader = $downloader;
        $this->cache = $cacheProvider->getCachePool('crl');
    }

    public function isRevoked(X509Certificate $subject, X509Certificate $issuer): bool
    {
        // TODO: implement
        return false;
    }
}
