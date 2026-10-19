<?php

declare(strict_types=1);

use Oki\People\Exceptions\TokenRejected;

it('reads the key set once while it is fresh', function () {
    $stage = stage();

    $stage->people->accessTokens()->verify(signed());
    $stage->people->accessTokens()->verify(signed());

    expect($stage->http->asked('/oauth/jwks'))->toBe(1)
        ->and($stage->http->asked('/.well-known/openid-configuration'))->toBe(1);
});

it('reads the key set again once it is stale', function () {
    $stage = stage();

    $stage->people->accessTokens()->verify(signed());
    $stage->clock->travel(901);
    $stage->people->accessTokens()->verify(signed(now: $stage->clock->now()));

    expect($stage->http->asked('/oauth/jwks'))->toBe(2);
});

it('fetches a key the first time a token names it', function () {
    $next = keypair(fresh: true);
    $stage = stage();
    $stage->http->sequence('/oauth/jwks', [
        [200, ['keys' => [jwk()]]],
        [200, ['keys' => [jwk(), jwk($next['public'], 'key-2')]]],
    ]);

    $stage->people->accessTokens()->verify(signed());
    $stage->clock->travel(61);

    expect($stage->people->accessTokens()->verify(signed(kid: 'key-2', key: $next['private'], now: $stage->clock->now()))->subject)
        ->toBe('user-1');
});

it('stops trusting a key People has retired', function () {
    $stage = stage();
    $stage->http->sequence('/oauth/jwks', [
        [200, ['keys' => [jwk()]]],
        [200, ['keys' => [jwk(keypair(fresh: true)['public'], 'key-2')]]],
    ]);

    $stage->people->accessTokens()->verify(signed());
    $stage->clock->travel(901);

    expect(fn () => $stage->people->accessTokens()->verify(signed(now: $stage->clock->now())))
        ->toThrow(TokenRejected::class, 'a key People does not publish');
});

it('asks People at most once a minute however many unknown keys are named', function () {
    $stage = stage();

    foreach (['forged-1', 'forged-2', 'forged-3'] as $kid) {
        try {
            $stage->people->accessTokens()->verify(signed(kid: $kid));
        } catch (TokenRejected) {
        }
    }

    expect($stage->http->asked('/oauth/jwks'))->toBe(1);
});

it('stands on the last key set while People cannot be reached', function () {
    $stage = stage();
    $stage->people->accessTokens()->verify(signed());

    $stage->clock->travel(901);
    $stage->http->down('/oauth/jwks');

    expect($stage->people->accessTokens()->verify(signed(now: $stage->clock->now()))->subject)->toBe('user-1');
});

it('keeps the last key set when People publishes nothing usable', function () {
    $stage = stage();
    $stage->http->sequence('/oauth/jwks', [[200, ['keys' => [jwk()]]], [200, ['keys' => [jwk(overrides: ['kty' => 'EC'])]]]]);

    $stage->people->accessTokens()->verify(signed());
    $stage->clock->travel(901);

    expect($stage->people->accessTokens()->verify(signed(now: $stage->clock->now()))->subject)->toBe('user-1');
});

it('trusts nothing when People never answered', function () {
    $stage = stage();
    $stage->http->on('/oauth/jwks', ['message' => 'Unavailable.'], 503);

    $stage->people->accessTokens()->verify(signed());
})->throws(TokenRejected::class, 'a key People does not publish');
