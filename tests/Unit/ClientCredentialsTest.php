<?php

declare(strict_types=1);

use Oki\People\Exceptions\PeopleRefused;

it('asks People for a token the client holds for itself', function () {
    $stage = stage();
    $stage->http->on('/oauth/token', ['access_token' => 'client-token', 'expires_in' => 900]);

    expect($stage->people->clientCredentials()->token(['identity.events']))->toBe('client-token')
        ->and(form_of($stage->http->last('/oauth/token')))->toBe([
            'grant_type' => 'client_credentials',
            'client_id' => CLIENT,
            'client_secret' => SECRET,
            'scope' => 'identity.events',
        ]);
});

it('keeps the token until shortly before it expires', function () {
    $stage = stage();
    $stage->http->on('/oauth/token', ['access_token' => 'client-token', 'expires_in' => 900]);

    $stage->people->clientCredentials()->token(['identity.events']);
    $stage->clock->travel(860);
    $stage->people->clientCredentials()->token(['identity.events']);
    $stage->clock->travel(20);
    $stage->people->clientCredentials()->token(['identity.events']);

    expect($stage->http->asked('/oauth/token'))->toBe(2);
});

it('keeps one token per set of scopes, in any order', function () {
    $stage = stage();
    $stage->http->on('/oauth/token', ['access_token' => 'client-token', 'expires_in' => 900]);

    $stage->people->clientCredentials()->token(['b', 'a']);
    $stage->people->clientCredentials()->token(['a', 'b']);
    $stage->people->clientCredentials()->token(['a']);

    expect($stage->http->asked('/oauth/token'))->toBe(2);
});

it('does not keep a token about to expire', function () {
    $stage = stage();
    $stage->http->on('/oauth/token', ['access_token' => 'client-token', 'expires_in' => 10]);

    $stage->people->clientCredentials()->token(['identity.events']);
    $stage->people->clientCredentials()->token(['identity.events']);

    expect($stage->http->asked('/oauth/token'))->toBe(2);
});

it('asks again once a held token is given up', function () {
    $stage = stage();
    $stage->http->on('/oauth/token', ['access_token' => 'client-token', 'expires_in' => 900]);

    $stage->people->clientCredentials()->token(['identity.events']);
    $stage->people->clientCredentials()->forget(['identity.events']);
    $stage->people->clientCredentials()->token(['identity.events']);

    expect($stage->http->asked('/oauth/token'))->toBe(2);
});

it('cannot speak for a client with no secret', function () {
    stage(clientSecret: null)->people->clientCredentials()->token(['identity.events']);
})->throws(InvalidArgumentException::class, 'confidential');

it('says what People said when it would not issue one', function () {
    $stage = stage();
    $stage->http->on('/oauth/token', ['error' => 'invalid_scope', 'error_description' => 'Not that scope.'], 400);

    $stage->people->clientCredentials()->token(['admin']);
})->throws(PeopleRefused::class, 'Not that scope.');
