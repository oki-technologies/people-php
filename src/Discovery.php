<?php

declare(strict_types=1);

namespace Oki\People;

use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Http\Transport;
use Oki\People\Support\Remembered;

/**
 * People's OpenID Connect discovery document.
 *
 * Every endpoint this SDK calls is read from here rather than assumed, so an
 * endpoint People moves is followed without a release.
 */
final readonly class Discovery
{
    private const string KEY = 'oki-technologies.people.discovery';

    public function __construct(
        private Config $config,
        private Transport $http,
        private Remembered $remembered,
    ) {}

    /**
     * The address of one endpoint: `token_endpoint`, `jwks_uri`, `userinfo_endpoint`…
     *
     * @throws PeopleUnreachable when discovery has never been read and cannot be now.
     */
    public function endpoint(string $name): string
    {
        $value = $this->document()[$name] ?? null;

        return is_string($value) && $value !== ''
            ? $value
            : throw new PeopleUnreachable("People's discovery document names no {$name}.");
    }

    /**
     * The whole document.
     *
     * @return array<mixed>
     *
     * @throws PeopleUnreachable
     */
    public function document(): array
    {
        $document = $this->remembered->get(self::KEY, function (): array {
            $document = $this->http->get($this->config->issuer().'/.well-known/openid-configuration');

            // A document claiming to be somebody else's is not People's, however it was reached.
            if (($document['issuer'] ?? null) !== $this->config->issuer()) {
                throw new PeopleUnreachable('The discovery document names another issuer.');
            }

            return $document;
        });

        return $document ?? throw new PeopleUnreachable('People\'s discovery document could not be read.');
    }
}
