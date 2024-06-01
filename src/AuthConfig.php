<?php

namespace Cube\Packages\Auth;

readonly class AuthConfig
{
    public const COMBINATION = 'combinations';

    /**
     * @var string Authentication failed error message
     */
    public const ERROR_MESSAGE = 'error_msg';

    /**
     * @var string Password has method
     */
    public const HASH_METHOD = 'hash_method';

    /**
     * @var string User model class
     */
    public const MODEL = 'instance';

    /**
     * @var string Auth Json Web Token config
     */
    public const JWT = 'json_web_token';

    /**
     * @var string No. of days cookie will expire
     */
    public const COOKIE_EXPIRY = 'cookie_expiry_days';
}
