<?php

declare(strict_types=1);

use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Exceptions\TokenRejected;
use Oki\People\OAuth\AuthorizationRequest;
use Oki\People\Tokens\IdTokenVerifier;
use Psr\Http\Message\RequestInterface;

const RETURN_TO = 'https://app.example.com/callback';

/** @return array<string, string> */
function query_of(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    return array_map(strval(...), $query);
}

/** @return array<string, string> */
function form_of(?RequestInterface $request): array
{
    parse_str((string) $request?->getBody(), $form);

    return array_map(strval(...), $form);
}

describe('beginning a sign-in', function () {
    it('sends somebody to People with PKCE, a state and a nonce', function () {
        $request = stage()->people->authorization()->begin(RETURN_TO);
        $query = query_of($request->url);

        expect($request->url)->toStartWith(ISSUER.'/oauth/authorize?')
            ->and($query)->toMatchArray([
                'response_type' => 'code',
                'client_id' => CLIENT,
                'redirect_uri' => RETURN_TO,
                'scope' => 'openid profile email',
                'state' => $request->state,
                'nonce' => $request->nonce,
                'code_challenge_method' => 'S256',
            ])
            ->and($query['code_challenge'])->toBe(rtrim(strtr(base64_encode(hash('sha256', $request->codeVerifier, true)), '+/', '-_'), '='));
    });

    it('asks for the scopes it is given', function () {
        expect(query_of(stage()->people->authorization()->begin(RETURN_TO, ['openid'])->url)['scope'])->toBe('openid');
    });

    it('never begins two sign-ins alike', function () {
        $authorization = stage()->people->authorization();

        expect($authorization->begin(RETURN_TO)->state)->not->toBe($authorization->begin(RETURN_TO)->state);
    });
});

describe('finishing a sign-in', function () {
    beforeEach(function () {
        $this->stage = stage();
        $this->request = new AuthorizationRequest('', 'state-1', 'nonce-1', 'verifier-1', RETURN_TO);
        $this->stage->http->on('/oauth/token', [
            'token_type' => 'Bearer',
            'access_token' => 'access-1',
            'refresh_token' => 'refresh-1',
            'expires_in' => 900,
            'scope' => 'openid profile',
            'id_token' => signed(['aud' => [CLIENT], 'nonce' => 'nonce-1', 'at_hash' => IdTokenVerifier::atHash('access-1'), 'name' => 'Ada']),
        ]);
    });

    it('trades the code for tokens, with the verifier and the secret', function () {
        $tokens = $this->stage->people->authorization()->exchange(['code' => 'code-1', 'state' => 'state-1'], $this->request);

        expect($tokens->accessToken)->toBe('access-1')
            ->and($tokens->refreshToken)->toBe('refresh-1')
            ->and($tokens->expiresIn)->toBe(900)
            ->and($tokens->scopes)->toBe(['openid', 'profile'])
            ->and($tokens->identity?->name)->toBe('Ada')
            ->and(form_of($this->stage->http->last('/oauth/token')))->toBe([
                'client_id' => CLIENT,
                'client_secret' => SECRET,
                'grant_type' => 'authorization_code',
                'code' => 'code-1',
                'redirect_uri' => RETURN_TO,
                'code_verifier' => 'verifier-1',
            ]);
    });

    it('sends no secret for a public client', function () {
        $stage = stage(clientSecret: null);
        $stage->http->on('/oauth/token', ['access_token' => 'access-1', 'expires_in' => 900]);

        $stage->people->authorization()->exchange(['code' => 'code-1', 'state' => 'state-1'], $this->request);

        expect(form_of($stage->http->last('/oauth/token')))->not->toHaveKey('client_secret');
    });

    it('refuses a callback answering another sign-in', function () {
        $this->stage->people->authorization()->exchange(['code' => 'code-1', 'state' => 'state-2'], $this->request);
    })->throws(TokenRejected::class, 'answers another sign-in');

    it('refuses a callback with no state', function () {
        $this->stage->people->authorization()->exchange(['code' => 'code-1'], $this->request);
    })->throws(TokenRejected::class);

    it('says what People said when the sign-in was turned down', function () {
        $this->stage->people->authorization()->exchange(['error' => 'access_denied', 'error_description' => 'They said no.', 'state' => 'state-1'], $this->request);
    })->throws(PeopleRefused::class, 'They said no.');

    it('refuses a callback with no code', function () {
        $this->stage->people->authorization()->exchange(['state' => 'state-1'], $this->request);
    })->throws(PeopleRefused::class, 'no code');

    it('refuses an id_token answering another sign-in', function () {
        $request = new AuthorizationRequest('', 'state-1', 'nonce-2', 'verifier-1', RETURN_TO);

        $this->stage->people->authorization()->exchange(['code' => 'code-1', 'state' => 'state-1'], $request);
    })->throws(TokenRejected::class, 'answers another sign-in');

    it('says what People said when the code was refused', function () {
        $this->stage->http->on('/oauth/token', ['error' => 'invalid_grant', 'error_description' => 'The code has been used.'], 400);

        try {
            $this->stage->people->authorization()->exchange(['code' => 'code-1', 'state' => 'state-1'], $this->request);
        } catch (PeopleRefused $refused) {
            expect($refused->error)->toBe('invalid_grant')
                ->and($refused->status)->toBe(400)
                ->and($refused->getMessage())->toBe('The code has been used.');

            return;
        }

        $this->fail('The refusal was not raised.');
    });
});

describe('refreshing', function () {
    it('trades a refresh token for fresh tokens', function () {
        $stage = stage();
        $stage->http->on('/oauth/token', ['access_token' => 'access-2', 'refresh_token' => 'refresh-2', 'expires_in' => 900]);

        $tokens = $stage->people->authorization()->refresh('refresh-1');

        expect($tokens->accessToken)->toBe('access-2')
            ->and($tokens->identity)->toBeNull()
            ->and(form_of($stage->http->last('/oauth/token')))->toMatchArray(['grant_type' => 'refresh_token', 'refresh_token' => 'refresh-1']);
    });
});

describe('signing out', function () {
    it('sends somebody to People to sign out there too', function () {
        $url = stage()->people->authorization()->signOutUrl('id-token', 'https://app.example.com/', 'state-1');

        expect($url)->toStartWith(ISSUER.'/oauth/logout?')
            ->and(query_of($url))->toBe([
                'client_id' => CLIENT,
                'id_token_hint' => 'id-token',
                'post_logout_redirect_uri' => 'https://app.example.com/',
                'state' => 'state-1',
            ]);
    });

    it('leaves out what it was not given', function () {
        expect(query_of(stage()->people->authorization()->signOutUrl()))->toBe(['client_id' => CLIENT]);
    });
});

it('says so when the token endpoint answers with no access token', function () {
    $stage = stage();
    $stage->http->on('/oauth/token', ['token_type' => 'Bearer']);

    $stage->people->authorization()->refresh('refresh-1');
})->throws(PeopleUnreachable::class, 'no access token');
