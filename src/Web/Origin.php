<?php


namespace MadWizard\WebAuthn\Web;

use MadWizard\WebAuthn\Exception\ParseException;
use function mb_strtolower;

class Origin // TODO serializable
{
    /**
     * @var string
     */
    private $scheme;

    /**
     * @var string
     */
    private $domain;

    /**
     * @var int
     */
    private $port;

    // TODO: add proper host/domain distinction according to spec
    //
    private function __construct(string $scheme, string $domain, int $port)
    {
        $this->scheme = $scheme;
        $this->domain = $domain;
        $this->port = $port;
    }

    public static function parse(string $origin)
    {
        $scheme = null;
        $domain = null;
        $port = null;
        $elements = parse_url($origin);
        foreach ($elements as $k => $v) {
            switch ($k) {
                case 'scheme':
                    $scheme = $v;
                    break;
                case 'host':
                    $domain = $v;
                    break;
                case 'port':
                    $port = (int) $port;
                    break;
                default:
                    throw new ParseException(sprintf("Unexpected component %s in origin string '%s'", $k, $origin));
            }
        }

        if ($scheme === null) {
            $scheme = 'http';
        } else {
            $scheme = mb_strtolower($scheme, 'UTF-8');
        }


        if ($port === null) {
            if ($scheme === 'https') {
                $port = 443;
            } elseif ($scheme === 'http') {
                $port = 80;
            }
        }

        if ($scheme === null || $domain === null || $port === null) {
            throw new ParseException(sprintf("Incomplete or unsupported origin '%s'.", $origin));
        }

        $domain = mb_strtolower($domain, 'UTF-8');
        return new Origin($scheme, $domain, $port);
    }

    public function equals(Origin $origin) : bool
    {
        return $this->domain === $origin->domain &&
            $this->port === $origin->port &&
            $this->scheme === $origin->scheme;
    }

    public function toString()
    {
        if ($this->usesDefaultPort()) {
            return sprintf('%s://%s', $this->scheme, $this->domain);
        }
        return sprintf('%s://%s:%d', $this->scheme, $this->domain, $this->port);
    }

    private function usesDefaultPort() : bool
    {
        if ($this->scheme === 'http' && $this->port === 80) {
            return true;
        }
        if ($this->scheme === 'https' && $this->port === 443) {
            return true;
        }
        return false;
    }

    /**
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain;
    }
}
