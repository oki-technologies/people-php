<?php

declare(strict_types=1);

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Oki\People\Exceptions\TokenRejected;

it('reads who a genuine token is for, and what it may do', function () {
    $token = stage()->people->accessTokens()->verify(signed(['scopes' => ['openid', 'orders.read']]));

    expect($token->subject)->toBe('user-1')
        ->and($token->clientId)->toBe(CLIENT)
        ->and($token->scopes)->toBe(['openid', 'orders.read'])
        ->and($token->audiences)->toBe([CLIENT, AUDIENCE])
        ->and($token->can('orders.read'))->toBeTrue()
        ->and($token->can('orders.write'))->toBeFalse()
        ->and($token->isClientOnly())->toBeFalse()
        ->and($token->claims['client_id'])->toBe(CLIENT);
});

it('holds every scope for a token granted `*`', function () {
    expect(stage()->people->accessTokens()->verify(signed(['scopes' => ['*']]))->can('anything'))->toBeTrue();
});

it('knows a token a client holds for itself', function () {
    expect(stage()->people->accessTokens()->verify(signed(['sub' => CLIENT]))->isClientOnly())->toBeTrue();
});

it('keeps only the scopes and audiences that are names', function () {
    $token = stage()->people->accessTokens()->verify(signed(['scopes' => ['openid', 42]]));

    expect($token->scopes)->toBe(['openid']);
});

it('refuses, saying why', function (string $jwt, string $reason) {
    expect(fn () => stage()->people->accessTokens()->verify($jwt))->toThrow(TokenRejected::class, $reason);
})->with([
    'nothing' => fn () => ['', 'There is no token to verify.'],
    'something that is not a token' => fn () => ['not-a-token', 'The token could not be read.'],
    'a token signed by another key' => fn () => [signed(key: keypair(fresh: true)['private']), 'The token did not verify.'],
    'a token naming a key People does not publish' => fn () => [signed(kid: 'unknown'), 'The token was signed by a key People does not publish.'],
    'an expired token' => fn () => [signed(now: new DateTimeImmutable('-1 hour')), 'The token did not verify.'],
    'a token from another issuer' => fn () => [signed(['iss' => 'https://staging.people.example.com']), 'The token did not verify.'],
    'a token naming no issuer' => fn () => [signed(['iss' => null]), 'The token did not verify.'],
    'a token meant for another API' => fn () => [signed(['aud' => [CLIENT, 'api.elsewhere.com']]), 'The token was not meant for this API.'],
    'a token naming no audience' => fn () => [signed(['aud' => null]), 'The token names no audience.'],
    'a token naming nobody' => fn () => [signed(['sub' => null]), 'The token names nobody.'],
]);

it('refuses every access token when this application names no audience', function () {
    stage(audience: null)->people->accessTokens()->verify(signed());
})->throws(TokenRejected::class, 'configured with no audience');

it('refuses a token signed with the public key as an HMAC secret', function () {
    $forged = (new Builder(new JoseEncoder, ChainedFormatter::default()))
        ->withHeader('kid', KID)
        ->issuedBy(ISSUER)
        ->relatedTo('user-1')
        ->permittedFor(AUDIENCE)
        ->issuedAt(new DateTimeImmutable)
        ->canOnlyBeUsedAfter(new DateTimeImmutable)
        ->expiresAt(new DateTimeImmutable('+1 hour'))
        ->getToken(new Sha256, InMemory::plainText(keypair()['public']))
        ->toString();

    stage()->people->accessTokens()->verify($forged);
})->throws(TokenRejected::class);

it('verifies a token naming no key against every key People publishes', function () {
    expect(stage()->people->accessTokens()->verify(signed(kid: null))->subject)->toBe('user-1');
});
