<?php

declare(strict_types=1);

use Nyholm\Psr7\Factory\Psr17Factory;
use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Testing\PeopleFake;
use Oki\People\Tests\Support\ArrayCache;
use Oki\People\Tests\Support\FrozenClock;

function fake_people(?array $keys = null): array
{
    $factory = new Psr17Factory;
    $fake = new PeopleFake($factory, keys: $keys);
    $clock = new FrozenClock;

    return [$fake, $fake->people(new ArrayCache($clock), $clock, $factory)];
}

it('issues tokens the SDK verifies, with nothing going over the network', function () {
    [$fake, $people] = fake_people();

    $token = $people->accessTokens()->verify($fake->token('user-9', ['scopes' => ['orders.read']]));

    expect($token->subject)->toBe('user-9')
        ->and($token->can('orders.read'))->toBeTrue()
        ->and($token->clientId)->toBe('client-1')
        ->and($fake->sent)->toHaveCount(2);
});

it('signs with the keypair it is given', function () {
    [$fake] = fake_people(keypair());

    expect($fake->keys)->toBe(keypair());
});

it('answers whatever else it is told to', function () {
    [$fake, $people] = fake_people();
    $fake->on('/oauth/userinfo', ['sub' => 'user-9', 'name' => 'Ada']);

    expect($people->userinfo()->of('access')->name)->toBe('Ada');
});

it('knows nothing it was not told', function () {
    [$fake, $people] = fake_people();

    $people->userinfo()->of('access');
})->throws(PeopleRefused::class);

it('refuses to issue a token for nobody', function () {
    [$fake] = fake_people();

    $fake->token('');
})->throws(RuntimeException::class);

it('refuses a keypair that is not RSA', function () {
    $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']) ?: throw new RuntimeException('No key.');
    openssl_pkey_export($ec, $private);
    [$fake, $people] = fake_people(['private' => $private, 'public' => openssl_pkey_get_details($ec)['key']]);

    $fake->sendRequest((new Psr17Factory)->createRequest('GET', 'https://people.example.com/oauth/jwks'));
})->throws(RuntimeException::class, 'not an RSA key');
