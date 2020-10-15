<?php

namespace MadWizard\WebAuthn\Conformance;

use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\ConsoleOutput;

class ErrorLogger extends AbstractLogger
{
    private const COLOR_MAP =
        [
                LogLevel::EMERGENCY => 'red',
                LogLevel::ALERT => 'red',
                LogLevel::CRITICAL => 'red',
                LogLevel::ERROR => 'red',
                LogLevel::WARNING => 'yellow',
                LogLevel::NOTICE => 'cyan',
                LogLevel::INFO => 'green',
                LogLevel::DEBUG => 'blue',
        ];

    /**
     * @var ConsoleOutput
     */
    private $output;

    public function __construct()
    {
        $this->output = new ConsoleOutput();
    }

    public function log($level, $message, array $context = [])
    {
        $escapedMessage = OutputFormatter::escape($this->interpolate($message, $context));
        $formatted = isset(self::COLOR_MAP[$level]) ?
                    sprintf('<fg=%s>[%s] %s</>', self::COLOR_MAP[$level], $level, $escapedMessage) :
                    sprintf('[%s] %s', $level, $escapedMessage);
        $this->output->getErrorOutput()->writeln($formatted);
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
