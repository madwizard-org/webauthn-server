<?php

namespace MadWizard\WebAuthn\Conformance;

use Psr\Log\AbstractLogger;

class ErrorLogger extends AbstractLogger
{
    public function log($level, $message, array $context = [])
    {
        error_log(sprintf('[%s] %s', $level, $this->interpolate($message, $context)));
    }

    private function interpolate($message, array $context = [])
    {
        //https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-3-logger-interface.md
        $replace = [];
        foreach ($context as $key => $val) {
            // check that the value can be cast to string
            if (!is_array($val) && (!is_object($val) || method_exists($val, '__toString'))) {
                $replace['{' . $key . '}'] = $val;
            }
        }

        return strtr($message, $replace);
    }
}
