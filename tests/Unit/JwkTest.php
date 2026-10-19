<?php

declare(strict_types=1);

use Oki\People\Keys\Jwk;

it('reads a published key as the PEM that verifies with it', function () {
    expect(Jwk::read(jwk()))->toBe([KID, keypair()['public']]);
});

it('takes a key that leaves its use and algorithm unsaid', function () {
    expect(Jwk::read(jwk(overrides: ['use' => null, 'alg' => null])))->toBe([KID, keypair()['public']]);
});

it('passes over any key that is not an RSA signing key for RS256', function (array $overrides) {
    expect(Jwk::read(jwk(overrides: $overrides)))->toBeNull();
})->with([
    'another key type' => [['kty' => 'EC']],
    'an encryption key' => [['use' => 'enc']],
    'another algorithm' => [['alg' => 'RS512']],
    'no kid' => [['kid' => null]],
    'an empty kid' => [['kid' => '']],
    'no modulus' => [['n' => null]],
    'a modulus that is not base64url' => [['n' => '***']],
    'no exponent' => [['e' => null]],
    'a modulus under 2048 bits' => [['n' => rtrim(strtr(base64_encode(random_bytes(128)), '+/', '-_'), '=')]],
]);
