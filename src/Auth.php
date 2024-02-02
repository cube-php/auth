<?php

namespace Cube\Packages\Auth;

use Cube\App\App;
use Cube\Exceptions\AuthException;
use Cube\Http\Cookie;
use Cube\Http\Session;
use Cube\Interfaces\ModelInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Auth
{
    /**
     * Error message when authentication fails
     */
    public const CONFIG_ERROR_MSG = 'error_msg';

    /**
     * Password hash method
     */
    public const CONFIG_HASH_METHOD = 'hash_method';

    /**
     * Authenticaton attempt combination
     */
    public const CONFIG_COMBINATION = 'combinations';

    /**
     * Users model class
     */
    public const CONFIG_MODEL = 'instance';

    /**
     * JWT Config
     */
    public const CONFIG_JWT = 'jwt';

    /**
     * No. of days it will take an auth token to expire
     */
    public const CONFIG_COOKIE_EXPIRY_DAYS = 'cookie_expiry_days';

    /**
     * Event dispatched when user is authenticated
     */
    public const EVENT_ON_AUTHENTICATED = 'authenticated';

    /**
     * Event dispatched when user is logged out
     */
    public const EVENT_ON_LOGGED_OUT    = 'loggedout';

    /**
     * Auth session name
     *
     * @var string
     */
    private static $auth_name = 'AuthSession';

    /**
     * Authenticated user
     *
     * @var ModelInterface|null
     */
    private static $auth_user = null;

    /**
     * Auth Config
     *
     * @var mixed
     */
    private static $config;

    /**
     * Attempt to log user in
     *
     * @param string $field
     * @param string $secret
     * @param boolean $remember
     * @return boolean
     */
    public static function attempt(string $field, string $secret, bool $remember = false): bool
    {
        $user = self::auth($field, $secret);

        $expiry = self::getConfigField(self::CONFIG_COOKIE_EXPIRY_DAYS);
        $model = self::getConfigField(self::CONFIG_MODEL);

        $primary_key_name = $model::getPrimaryKey();
        $primary_key = $user->{$primary_key_name};

        Session::set(
            self::$auth_name,
            $primary_key
        );

        if ($remember) {
            Cookie::set(
                expires: getdays($expiry),
                name: self::$auth_name,
                value: $primary_key,
            );
        }

        self::$auth_user = $user;
        return true;
    }

    /**
     * Auth user by jwt
     *
     * @param string $token
     * @return AuthJwtResult
     */
    public static function attemptJwt(string $token): AuthJwtResult
    {
        [$key_str, $alg] = self::getJwtConfig();
        $config = self::getConfig();

        $key = new Key(
            $key_str,
            $alg
        );

        $payload = JWT::decode(
            $token,
            $key
        );

        $model = $config[self::CONFIG_MODEL];
        $user = $model::find($payload->id);

        $content = (array) $payload;
        unset($content['id']);

        return new AuthJwtResult(
            $user,
            $content
        );
    }

    /**
     * Attempt authorization and return jwt token
     *
     * @param string $field
     * @param string $secret
     * @param array $params
     * @return string
     */
    public static function attempt2json(string $field, string $secret, array $params = []): string
    {
        [$key, $alg] = self::getJwtConfig();
        $config = self::getConfig();

        $primary_key_name = $config[self::CONFIG_MODEL]::getPrimaryKey();
        $user = self::auth($field, $secret);
        $primary_key = array(
            'id' => $user->{$primary_key_name}
        );

        $payload = array_merge(
            $primary_key,
            $params
        );

        return JWT::encode(
            $payload,
            $key,
            $alg
        );
    }

    /**
     * Auth user by key
     *
     * @param mixed $value
     * @param boolean $remember
     * @return boolean
     */
    public static function authByKey($value, bool $remember = false): bool
    {
        Session::set(self::$auth_name, $value);

        if ($remember) {
            Cookie::set(self::$auth_name, $value);
        }

        return true;
    }

    /**
     * User
     *
     * @return ModelInterface|null
     */
    public static function user(): ?ModelInterface
    {
        if (self::$auth_user) {
            return self::$auth_user;
        }

        $auth_id = Session::get(self::$auth_name);

        if (!$auth_id) {
            return self::getAuthUserFromCookie();
        }

        $model = self::getConfigField(self::CONFIG_MODEL);
        $user = $model::find($auth_id);

        if (!$user) {
            return null;
        }

        self::$auth_user = $user;
        return $user;
    }

    /**
     * Log user out
     *
     * @return bool
     */
    public static function logout(): bool
    {
        Session::remove(self::$auth_name);
        Cookie::remove(self::$auth_name);
        return true;
    }

    /**
     * Get authenticated user from session
     *
     * @return ModelInterface|null
     */
    protected static function getAuthUserFromCookie(): ?ModelInterface
    {
        $auth_id = Cookie::get(self::$auth_name);

        if (!$auth_id) {
            return null;
        }

        $model = self::getConfigField(self::CONFIG_MODEL);
        $user = $model::find($auth_id);

        if (!$user) {
            return null;
        }

        $primary_key_name = $model::getPrimaryKey();
        $primary_key = $user->{$primary_key_name};

        Session::set(self::$auth_name, $$primary_key);
        return $user;
    }

    /**
     * Perform authentication
     *
     * @param string $field
     * @param string $secret
     * @return mixed
     */
    protected static function auth(string $field, string $secret)
    {
        $combinations = self::getConfigField(self::CONFIG_COMBINATION);
        $hash_method = self::getConfigField(self::CONFIG_HASH_METHOD);
        $error_msg = self::getConfigField(self::CONFIG_ERROR_MSG);
        $model = self::getConfigField(self::CONFIG_MODEL);

        if (!$error_msg) {
            throw new AuthSetupException('Authentication failed error message not set');
        }

        if (!$hash_method) {
            throw new AuthSetupException('Hash method not specified');
        }

        if (!$model) {
            throw new AuthSetupException('Auth model not set');
        }

        if (!$combinations) {
            throw new AuthSetupException('Auth combinations not set');
        }

        $auth_fields = $combinations['fields'] ?? null;

        if (!$auth_fields) {
            throw new AuthSetupException('"fields" not declared on "config.auth.combinations"');
        }

        $auth_field_names = array_keys($auth_fields);
        $auth_field_name = null;

        if (!$field) {
            throw new AuthException(
                concat('Enter ', implode(' or', $auth_field_names), ' to login')
            );
        }

        foreach ($auth_fields as $field_name => $fn) {
            if ($fn && $fn($field)) {
                $auth_field_name = $field_name;
                break;
            }

            if (!$fn) {
                $auth_field_name = $field_name;
                continue;
            }
        }

        $secret_key_name = $combinations['secret_key'] ?? null;

        if (!$secret_key_name) {
            throw new AuthSetupException('"secret_key" not specified on "config.auth.combinations"');
        }

        $query = $model::findBy($auth_field_name, $field);

        if (!$query) {
            throw new AuthException($error_msg);
        }

        $server_secret = $query->{$secret_key_name};

        if (!$hash_method($secret, $server_secret)) {
            throw new AuthException($error_msg);
        }

        return $query;
    }

    /**
     * Get app config for auth
     *
     * @return array
     */
    protected static function getConfig(): array
    {
        if (self::$config) {
            return self::$config;
        }

        $config_data = App::getConfig('auth');

        if (!$config_data) {
            throw new AuthSetupException('Invalid Auth Configuration');
        }

        self::$config = $config_data;
        return $config_data;
    }

    /**
     * Get config field value
     *
     * @param string $name
     * @return mixed
     */
    protected static function getConfigField(string $name): mixed
    {
        return self::getConfig()[$name] ?? null;
    }

    /**
     * Get JWT Config
     *
     * @return array
     */
    protected static function getJwtConfig(): array
    {
        $config = self::getConfig();
        $jwt_config = $config[self::CONFIG_JWT] ?? null;

        if (!$jwt_config) {
            throw new AuthSetupException('Auth JWT not configured');
        }

        $key = $jwt_config['key'];
        $alg = $jwt_config['alg'];

        return [$key, $alg];
    }
}
