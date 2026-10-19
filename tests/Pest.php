<?php

declare(strict_types=1);

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use Oki\People\Config;
use Oki\People\Tests\Support\ArrayCache;
use Oki\People\Tests\Support\FakePeople;
use Oki\People\Tests\Support\FrozenClock;
use Oki\People\Tests\Support\Stage;

const ISSUER = 'https://people.example.com';
const CLIENT = 'client-1';
const SECRET = 'client-secret';
const AUDIENCE = 'api.example.com';
const KID = 'key-1';

/**
 * A keypair, generated once for the suite unless a fresh one is asked for.
 *
 * @return array{private: non-empty-string, public: non-empty-string}
 */
function keypair(bool $fresh = false): array
{
    static $suite = null;

    if (! $fresh && $suite !== null) {
        return $suite;
    }

    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]) ?: throw new RuntimeException('No key.');
    openssl_pkey_export($key, $private);
    $details = openssl_pkey_get_details($key);

    if (! is_string($private) || $private === '' || ! is_array($details) || ! is_string($details['key']) || $details['key'] === '') {
        throw new RuntimeException('The keypair could not be read.');
    }

    $pair = ['private' => $private, 'public' => $details['key']];

    return $fresh ? $pair : $suite = $pair;
}

/**
 * A public key as People publishes it.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function jwk(?string $public = null, string $kid = KID, array $overrides = []): array
{
    $details = openssl_pkey_get_details(openssl_pkey_get_public($public ?? keypair()['public']) ?: throw new RuntimeException('No key.'));
    $encode = fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

    return ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $kid, 'n' => $encode($details['rsa']['n']), 'e' => $encode($details['rsa']['e']), ...$overrides];
}

/** @return array<string, mixed> */
function discovery_document(): array
{
    return [
        'issuer' => ISSUER,
        'authorization_endpoint' => ISSUER.'/oauth/authorize',
        'token_endpoint' => ISSUER.'/oauth/token',
        'jwks_uri' => ISSUER.'/oauth/jwks',
        'userinfo_endpoint' => ISSUER.'/oauth/userinfo',
        'end_session_endpoint' => ISSUER.'/oauth/logout',
    ];
}

/** The SDK against a People that publishes its discovery document and the suite's key. */
function stage(?string $clientSecret = SECRET, ?string $audience = AUDIENCE): Stage
{
    $clock = new FrozenClock;
    $http = (new FakePeople)
        ->on('/.well-known/openid-configuration', discovery_document())
        ->on('/oauth/jwks', ['keys' => [jwk()]]);

    return new Stage($http, $clock, new ArrayCache($clock), new Config(
        issuer: ISSUER,
        clientId: CLIENT,
        clientSecret: $clientSecret,
        audience: $audience,
    ));
}

/**
 * A token as People signs one.
 *
 * @param  array<string, mixed>  $claims  Overrides; a null value leaves the claim out.
 */
function signed(array $claims = [], ?string $kid = KID, ?string $key = null, ?DateTimeImmutable $now = null): string
{
    // A minute back, so a token signed after the stage was set up is never from its future.
    $now ??= new DateTimeImmutable('@'.(time() - 60));
    $claims += [
        'iss' => ISSUER,
        'sub' => 'user-1',
        'aud' => [CLIENT, AUDIENCE],
        'client_id' => CLIENT,
        'scopes' => ['openid'],
        'exp' => $now->modify('+15 minutes'),
    ];

    $builder = (new Builder(new JoseEncoder, ChainedFormatter::default()))
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->identifiedBy('token-1');

    if ($kid !== null) {
        $builder = $builder->withHeader('kid', $kid);
    }

    foreach ($claims as $name => $value) {
        $builder = match (true) {
            $value === null => $builder,
            $name === 'iss' => $builder->issuedBy($value),
            $name === 'sub' => $builder->relatedTo($value),
            $name === 'aud' => $builder->permittedFor(...(array) $value),
            $name === 'exp' => $builder->expiresAt($value),
            default => $builder->withClaim($name, $value),
        };
    }

    return $builder->getToken(new Sha256, InMemory::plainText($key ?? keypair()['private']))->toString();
}
