# People for PHP

Sign people in with People, verify their tokens, and keep a copy of their identities
current.

People is an OpenID Connect provider. This SDK is a convenience over that protocol,
never a replacement for it: everything it does goes through a documented endpoint,
and any certified OpenID Connect library can do the same. See
[Without the SDK](#without-the-sdk).

```bash
composer require okitechnologies/people-php
```

PHP 8.3+. Bring your own HTTP client (PSR-18), message factories (PSR-17), cache
(PSR-16) and clock (PSR-20). On Laravel, use
`okitechnologies/people-laravel` instead, which wires all of this up.

## Before you start

Register your application at People. You get:

- a **client id**;
- a **client secret**, if your application runs on a server. A browser or mobile app
  gets none and relies on PKCE alone;
- the **redirect URIs** People may send people back to;
- the **audiences** your tokens may be presented at — the hostnames of the APIs that
  will accept them, e.g. `api.example.com`. Add People's own hostname to read
  identity events.

## Setup

```php
use Oki\People\Config;
use Oki\People\People;

$people = new People(
    new Config(
        issuer: 'https://people.example.com',
        clientId: 'your-client-id',
        clientSecret: getenv('PEOPLE_CLIENT_SECRET'),
        audience: 'api.example.com', // this API's hostname, to verify access tokens
    ),
    $httpClient,      // Psr\Http\Client\ClientInterface
    $requestFactory,  // Psr\Http\Message\RequestFactoryInterface
    $streamFactory,   // Psr\Http\Message\StreamFactoryInterface
    $cache,           // Psr\SimpleCache\CacheInterface — shared across requests
    $clock,           // Psr\Clock\ClockInterface
);
```

Use a cache shared across requests and processes. The key set and the discovery
document are cached there; a cache that lives for one request means a call to People
on every request.

## Verifying an access token

For an API that accepts tokens issued by People:

```php
use Oki\People\Exceptions\TokenRejected;

try {
    $token = $people->accessTokens()->verify($bearerToken);
} catch (TokenRejected $e) {
    // 401. $e->getMessage() says why, for your log — not for the caller.
}

$token->subject;   // People's user id — the same in every application
$token->can('orders.read');
```

Checked locally, with no call to People: the signature against People's published
keys (chosen by the token's `kid`, RS256 only), the expiry, the issuer, and that the
token's `aud` names your `audience`. A token meant for another API is refused, and so
is one naming no audience at all.

What a local check cannot know is revocation: a token People revoked still verifies
until it expires. People's access tokens are short-lived for that reason.

**A token proves who is calling, never what they may do.** Decide that from your own
records.

Key rotation needs nothing from you. A `kid` not seen before is fetched the first time
a token names it (at most once a minute); a key People stops publishing stops
verifying within `keysTtl` seconds (15 minutes by default). While People is
unreachable, the last keys fetched keep working.

## Signing somebody in

Authorization code with PKCE (S256), the only flow People offers people:

```php
// 1. Send them to People.
$request = $people->authorization()->begin('https://app.example.com/callback');
$_SESSION['people'] = serialize($request); // state, nonce and verifier — server side only
header('Location: '.$request->url);

// 2. When they come back.
$tokens = $people->authorization()->exchange($_GET, unserialize($_SESSION['people']));

$tokens->accessToken;
$tokens->refreshToken;
$tokens->identity?->subject;  // the verified id_token
$tokens->identity?->name;
```

`exchange()` checks the `state`, trades the code with the verifier, and verifies the
`id_token`: addressed to your client, carrying your `nonce`, bound to the access token
by `at_hash`.

```php
$tokens = $people->authorization()->refresh($refreshToken);
$url = $people->authorization()->signOutUrl($idToken, 'https://app.example.com/');
$identity = $people->userinfo()->of($accessToken); // a round trip; use sparingly
```

## Keeping identities current

A confidential client can read what happened to the people who signed in to it — a
changed name, a suspension, a deletion — and nobody else:

```php
$page = $people->identityEvents()->after($lastSequence);

foreach ($page->events as $event) {
    match ($event->type) {
        IdentityEvent::UPDATED => $users->rename($event->subject, $event->payload['name']),
        IdentityEvent::DELETED => $users->erase($event->subject),
        default => null,
    };
}

if ($page->next !== null) {
    $lastSequence = $page->next; // store it once the page is applied
}
```

Apply events in order. Delivery is at least once, so applying one must be safe to
repeat — `eventId` is there to dedupe on. Once somebody disconnects your application
at People, you hear nothing more about them except their deletion, which you must act
on.

The SDK reads the feed on a token your client holds for itself (the
client-credentials grant, scope `identity.events`). Your client's audiences must
include People's own hostname.

## Without the SDK

Everything above is plain OpenID Connect and REST:

| What | Where |
| --- | --- |
| Discovery | `GET {issuer}/.well-known/openid-configuration` |
| Keys | `jwks_uri` from discovery |
| Sign in | `authorization_endpoint`, then `token_endpoint` — authorization code, PKCE S256 |
| Who is signed in | `userinfo_endpoint`, or the `id_token` |
| Sign out | `end_session_endpoint` |
| A client's own token | `token_endpoint`, `grant_type=client_credentials` |
| Identity events | `GET {issuer}/v1/identity/events?after={sequence}&limit={n}` on a client's own token with `identity.events` |

## Versioning

Semantic versioning. A breaking change is a new major version, and People keeps
serving the previous one through a published deprecation window.

## Security

Report a vulnerability privately, through this repository's security advisories,
rather than in a public issue.

## Licence

MIT.
