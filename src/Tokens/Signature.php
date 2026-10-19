<?php

declare(strict_types=1);

namespace Oki\People\Tokens;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Oki\People\Config;
use Oki\People\Exceptions\TokenRejected;
use Oki\People\Keys\KeySet;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * A token People signed, unexpired, issued by the People this application trusts.
 *
 * RS256 is pinned here rather than read off the token, so nothing can ask to
 * be verified with a public key as an HMAC secret.
 */
final readonly class Signature
{
    public function __construct(
        private Config $config,
        private KeySet $keys,
        private ClockInterface $clock,
    ) {}

    /**
     * @throws TokenRejected
     */
    public function verify(string $jwt, Constraint ...$constraints): UnencryptedToken
    {
        if ($jwt === '') {
            throw new TokenRejected('There is no token to verify.');
        }

        $keys = $this->keys->for($this->kid($jwt));

        if ($keys === []) {
            throw new TokenRejected('The token was signed by a key People does not publish.');
        }

        $failure = null;

        foreach ($keys as $key) {
            try {
                return (new JwtFacade)->parse(
                    $jwt,
                    new SignedWith(new Sha256, InMemory::plainText($key)),
                    new StrictValidAt($this->clock),
                    new IssuedBy($this->issuer()),
                    ...$constraints,
                );
            } catch (Throwable $e) {
                $failure = $e;
            }
        }

        throw new TokenRejected('The token did not verify.', previous: $failure);
    }

    /** @return non-empty-string */
    private function issuer(): string
    {
        $issuer = $this->config->issuer();

        return $issuer !== '' ? $issuer : throw new TokenRejected('No issuer is configured to trust.');
    }

    /**
     * The `kid` the token says it was signed with, read before anything is trusted.
     *
     * It only chooses which key to check against; the signature still decides.
     *
     * @param  non-empty-string  $jwt
     */
    private function kid(string $jwt): ?string
    {
        try {
            /** @var mixed $kid */
            $kid = (new Parser(new JoseEncoder))->parse($jwt)->headers()->get('kid');
        } catch (Throwable $e) {
            throw new TokenRejected('The token could not be read.', previous: $e);
        }

        return is_string($kid) && $kid !== '' ? $kid : null;
    }
}
