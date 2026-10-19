<?php

declare(strict_types=1);

use Oki\People\Exceptions\PeopleUnreachable;

it('reads an endpoint from the discovery document', function () {
    expect(stage()->people->discovery()->endpoint('token_endpoint'))->toBe(ISSUER.'/oauth/token');
});

it('refuses a document that names another issuer', function () {
    $stage = stage();
    $stage->http->on('/.well-known/openid-configuration', ['issuer' => 'https://evil.example.com'] + discovery_document());

    $stage->people->discovery()->document();
})->throws(PeopleUnreachable::class);

it('says so when the document names no such endpoint', function () {
    stage()->people->discovery()->endpoint('device_authorization_endpoint');
})->throws(PeopleUnreachable::class, 'names no device_authorization_endpoint');

it('says so when People has never answered', function () {
    $stage = stage();
    $stage->http->down('/.well-known/openid-configuration');

    $stage->people->discovery()->document();
})->throws(PeopleUnreachable::class);

it('stands on the last document while People cannot be reached', function () {
    $stage = stage();
    $stage->people->discovery()->document();

    $stage->clock->travel(901);
    $stage->http->down('/.well-known/openid-configuration');

    expect($stage->people->discovery()->endpoint('jwks_uri'))->toBe(ISSUER.'/oauth/jwks');
});
