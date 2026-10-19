<?php

declare(strict_types=1);

use Oki\People\Config;

it('carries the issuer the way tokens do, with no trailing slash', function () {
    expect((new Config('https://people.example.com/'))->issuer())->toBe('https://people.example.com');
});

it('refuses an issuer that is not an address', function () {
    new Config('people.example.com');
})->throws(InvalidArgumentException::class);

it('says when a client id is needed and missing', function () {
    (new Config(ISSUER))->clientId();
})->throws(InvalidArgumentException::class, 'client id');
