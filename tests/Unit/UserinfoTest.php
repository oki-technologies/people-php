<?php

declare(strict_types=1);

use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Tests\Support\FakePeople;

it('asks People who an access token belongs to', function () {
    $stage = stage();
    $stage->http->on('/oauth/userinfo', ['sub' => 'user-1', 'name' => 'Ada Lovelace']);

    $identity = $stage->people->userinfo()->of('access-1');

    expect($identity->subject)->toBe('user-1')
        ->and($identity->name)->toBe('Ada Lovelace')
        ->and($stage->http->last('/oauth/userinfo')?->getHeaderLine('Authorization'))->toBe('Bearer access-1');
});

it('says so when the token is no longer good', function () {
    $stage = stage();
    $stage->http->on('/oauth/userinfo', ['message' => 'Unauthenticated.'], 401);

    $stage->people->userinfo()->of('access-1');
})->throws(PeopleRefused::class, 'Unauthenticated.');

it('says so when People answers with something that is not an answer', function () {
    $stage = stage();
    $stage->http->on('/oauth/userinfo', fn () => FakePeople::json([], 500));

    $stage->people->userinfo()->of('access-1');
})->throws(PeopleUnreachable::class);

it('says so when People cannot be reached', function () {
    $stage = stage();
    $stage->http->down('/oauth/userinfo');

    $stage->people->userinfo()->of('access-1');
})->throws(PeopleUnreachable::class);
