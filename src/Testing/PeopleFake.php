<?php

declare(strict_types=1);

namespace Oki\People\Testing;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use Oki\People\Config;
use Oki\People\People;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

/**
 * People, in memory, for an application's own tests.
 *
 * Publishes a discovery document and a key it really signs with, so a token
 * from `token()` verifies exactly as a real one would — and nothing goes over
 * the network. Answer any other endpoint with `on()`.
 *
 *     $fake = new PeopleFake($psr17);
 *     $people = $fake->people($cache, $clock, $psr17);
 *     $people->accessTokens()->verify($fake->token('user-1'));
 */
final class PeopleFake implements ClientInterface
{
    /** @var array<string, array{int, array<mixed>}> */
    private array $answers = [];

    /** @var list<RequestInterface> */
    public array $sent = [];

    /** @var array{private: non-empty-string, public: non-empty-string} */
    public readonly array $keys;

    /**
     * @param  non-empty-string  $issuer
     * @param  non-empty-string  $clientId
     * @param  non-empty-string  $audience
     * @param  array{private: non-empty-string, public: non-empty-string}|null  $keys  The keypair to sign with; a fresh one when null.
     */
    public function __construct(
        private readonly ResponseFactoryInterface&StreamFactoryInterface $factory,
        public readonly string $issuer = 'https://people.example.com',
        public readonly string $clientId = 'client-1',
        public readonly string $audience = 'api.example.com',
        public readonly string $kid = 'people-fake',
        ?array $keys = null,
    ) {
        $this->keys = $keys ?? self::keypair();
    }

    /** The SDK, configured as this fake's client and talking only to it. */
    public function people(CacheInterface $cache, ClockInterface $clock, RequestFactoryInterface $requests, ?string $clientSecret = 'client-secret'): People
    {
        return new People(
            new Config(issuer: $this->issuer, clientId: $this->clientId, clientSecret: $clientSecret, audience: $this->audience),
            $this,
            $requests,
            $this->factory,
            $cache,
            $clock,
        );
    }

    /**
     * An access token as People would issue it to this fake's client, for its audience.
     *
     * @param  array<string, mixed>  $claims  Extra claims, or replacements for `scopes` and `client_id`.
     */
    public function token(string $subject = 'user-1', array $claims = [], ?DateTimeImmutable $now = null): string
    {
        $now ??= new DateTimeImmutable('-1 minute');
        $claims += ['scopes' => ['*'], 'client_id' => $this->clientId];

        $builder = (new Builder(new JoseEncoder, ChainedFormatter::default()))
            ->withHeader('kid', $this->kid)
            ->issuedBy($this->issuer)
            ->relatedTo($subject !== '' ? $subject : throw new RuntimeException('A token names somebody.'))
            ->permittedFor($this->clientId, $this->audience)
            ->identifiedBy(bin2hex(random_bytes(8)))
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify('+15 minutes'));

        foreach ($claims as $name => $value) {
            if ($name !== '') {
                $builder = $builder->withClaim($name, $value);
            }
        }

        return $builder->getToken(new Sha256, InMemory::plainText($this->keys['private']))->toString();
    }

    /**
     * Answers a path with JSON.
     *
     * @param  array<mixed>  $body
     */
    public function on(string $path, array $body, int $status = 200): self
    {
        $this->answers[$path] = [$status, $body];

        return $this;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->sent[] = $request;

        [$status, $body] = $this->answers[$request->getUri()->getPath()] ?? match ($request->getUri()->getPath()) {
            '/.well-known/openid-configuration' => [200, $this->discovery()],
            '/oauth/jwks' => [200, ['keys' => [$this->jwk()]]],
            default => [404, ['message' => 'Not found.']],
        };

        return $this->factory->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->factory->createStream((string) json_encode($body)));
    }

    /** @return array<string, string> */
    private function discovery(): array
    {
        return [
            'issuer' => rtrim($this->issuer, '/'),
            'authorization_endpoint' => $this->issuer.'/oauth/authorize',
            'token_endpoint' => $this->issuer.'/oauth/token',
            'jwks_uri' => $this->issuer.'/oauth/jwks',
            'userinfo_endpoint' => $this->issuer.'/oauth/userinfo',
            'end_session_endpoint' => $this->issuer.'/oauth/logout',
        ];
    }

    /** @return array<string, string> */
    private function jwk(): array
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($this->keys['public']) ?: throw new RuntimeException('The public key could not be read.'));

        if (! is_array($details) || ! is_string($details['rsa']['n'] ?? null) || ! is_string($details['rsa']['e'] ?? null)) {
            throw new RuntimeException('The public key is not an RSA key.');
        }

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->kid,
            'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
        ];
    }

    /** @return array{private: non-empty-string, public: non-empty-string} */
    private static function keypair(): array
    {
        static $pair = null;

        if ($pair !== null) {
            return $pair;
        }

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]) ?: throw new RuntimeException('No RSA keypair could be generated.');
        openssl_pkey_export($key, $private);
        $public = openssl_pkey_get_details($key)['key'] ?? null;

        return is_string($private) && $private !== '' && is_string($public) && $public !== '' ? $pair = ['private' => $private, 'public' => $public] : throw new RuntimeException('The generated keypair could not be read.');
    }
}
