<?php

use MadWizard\WebAuthn\Conformance\Router;

require __DIR__ . '/../vendor/autoload.php';

session_start();

$metadataDir = __DIR__ . '/metadata';
$varDir = dirname(__DIR__) . '/var';
$router = new Router($metadataDir, $varDir);

$router->run($_SERVER['REQUEST_URI']);

// TODO: https://github.com/fido-alliance/conformance-tools-issues/issues/387
