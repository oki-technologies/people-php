<?php

declare(strict_types=1);

namespace Oki\People;

use Oki\People\Exceptions\PeopleRefused;
use Oki\People\Exceptions\PeopleUnreachable;
use Oki\People\Http\Transport;
use Oki\People\Tokens\Identity;

/**
 * Who a person's access token belongs to, asked of People.
 *
 * A round trip, unlike the `id_token`: use it when the identity has to be
 * current, not on every request.
 */
final readonly class Userinfo
{
    public function __construct(
        private Discovery $discovery,
        private Transport $http,
    ) {}

    /**
     * @throws PeopleRefused when the token is no longer good.
     * @throws PeopleUnreachable
     */
    public function of(string $accessToken): Identity
    {
        return Identity::from($this->http->get(
            $this->discovery->endpoint('userinfo_endpoint'),
            ['Authorization' => 'Bearer '.$accessToken],
        ));
    }
}
