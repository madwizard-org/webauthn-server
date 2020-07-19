<?php

use MadWizard\WebAuthn\Conformance\Router;
use Symfony\Component\Dotenv\Dotenv;

require __DIR__ . '/../vendor/autoload.php';

session_start();

$dotenv = new Dotenv();
$dotenv->load(__DIR__ . '/.env');

$metadataDir = __DIR__ . '/metadata';
$varDir = dirname(__DIR__) . '/var';
$router = new Router($metadataDir, $varDir);

$router->run($_SERVER['REQUEST_URI']);

// TODO: https://github.com/fido-alliance/conformance-tools-issues/issues/387
