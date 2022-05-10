<?php
$finder = PhpCsFixer\Finder::create()
    ->exclude('vendor')
    ->in(__DIR__)
;

$config = new PhpCsFixer\Config();
return $config->setRules([
        '@PSR1'                  => true,
        '@PSR2'                  => true,
        'single_quote'           => true,
    ])
    ->setFinder($finder)
;
