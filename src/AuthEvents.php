<?php

namespace Cube\Packages\Auth;

readonly class AuthEvents
{
    /**
     * @var string Event name for event dispatched when user is authenticated
     */
    public const AUTHENTICATED = 'onAuthenticated';

    /**
     * @var string Event name for event dispatched when user signs out
     */
    public const LOGGED_OUT = 'onLoggedOut';
}
