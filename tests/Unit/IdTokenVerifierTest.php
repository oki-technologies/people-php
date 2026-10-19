<?php

declare(strict_types=1);

use Oki\People\Exceptions\TokenRejected;
use Oki\People\Tokens\IdTokenVerifier;

function id_token(array $claims = []): string
{
    return signed($claims + [
        'aud' => [CLIENT],
        'nonce' => 'nonce-1',
        'at_hash' => IdTokenVerifier::atHash('access-1'),
        'name' => 'Ada Lovelace',
        'preferred_username' => 'ada',
        'picture' => 'https://cdn.example.com/ada.png',
        'email' => 'ada@example.com',
        'email_verified' => true,
        'scopes' => null,
        'client_id' => null,
    ]);
}

it('reads who signed in', function () {
    $identity = stage()->people->idTokens()->verify(id_token(), 'nonce-1', 'access-1');

    expect($identity->subject)->toBe('user-1')
        ->and($identity->name)->toBe('Ada Lovelace')
        ->and($identity->username)->toBe('ada')
        ->and($identity->picture)->toBe('https://cdn.example.com/ada.png')
        ->and($identity->email)->toBe('ada@example.com')
        ->and($identity->emailVerified)->toBeTrue()
        ->and($identity->claims['iat'])->toBeInt();
});

it('leaves out what the granted scopes did not release', function () {
    $identity = stage()->people->idTokens()->verify(id_token(['name' => null, 'email' => null, 'email_verified' => null]));

    expect($identity->name)->toBeNull()
        ->and($identity->email)->toBeNull()
        ->and($identity->emailVerified)->toBeFalse();
});

it('refuses, saying why', function (array $claims, ?string $nonce, ?string $access, string $reason) {
    expect(fn () => stage()->people->idTokens()->verify(id_token($claims), $nonce, $access))
        ->toThrow(TokenRejected::class, $reason);
})->with([
    'one issued to another client' => [['aud' => ['client-2']], null, null, 'issued to another client'],
    'one answering another sign-in' => [[], 'nonce-2', null, 'answers another sign-in'],
    'one with no nonce when one was sent' => [['nonce' => null], 'nonce-1', null, 'answers another sign-in'],
    'one belonging with another access token' => [[], null, 'access-2', 'belongs with another access token'],
    'one naming nobody' => [['sub' => null], null, null, 'names nobody'],
]);

it('computes at_hash the way OIDC does', function () {
    // The specification's own example: the left-most 128 bits of SHA-256, base64url.
    expect(IdTokenVerifier::atHash('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'))->toBe('77QmUPtjPfzWtF2AnpK9RQ');
});
