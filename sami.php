<?php

use Sami\Sami;
use Symfony\Component\Finder\Finder;

$iterator = Finder::create()
    ->files()
    ->name('*.php')
    ->in('src')
;

return new Sami($iterator, [
    'title' => 'WebAuthn PHP server documentation',
    'build_dir' => __DIR__ . '/sami/output/',
    'cache_dir' => __DIR__ . '/sami/cache/',
]);
