<?php

namespace Cube\Packages\Auth;

use Cube\App\App;
use Cube\Http\Cookie;
use Cube\Http\Session;
use Cube\Interfaces\ModelInterface;
use Cube\Misc\EventManager;
use Cube\Packages\Auth\Exceptions\AuthException;
use Cube\Packages\Auth\Exceptions\AuthSetupException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Auth
{
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

        $expiry = self::getConfigField(AuthConfig::COOKIE_EXPIRY);
        $model = self::getConfigField(AuthConfig::MODEL);

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
        self::dispatchAuthEvent($user);
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

        $key = new Key(
            $key_str,
            $alg
        );

        $payload = JWT::decode(
            $token,
            $key
        );

        $model = self::getConfigField(AuthConfig::MODEL);
        $user = $model::find($payload->id);

        if (!$user) {
            throw new AuthException(
                self::getConfigField(AuthConfig::ERROR_MESSAGE)
            );
        }

        $content = (array) $payload;

        if (isset($content['id'])) {
            unset($content['id']);
        }

        return new AuthJwtResult(
            $user,
            $content
        );
    }

    /**
     * Attempt authorization and return jwt token
     *
     * @param string $field Model field name
     * @param string $secret Password
     * @param array $options Other options to add to jwt
     * @return string
     */
    public static function attempt2json(string $field, string $secret, array $options = []): string
    {
        [$key, $alg] = self::getJwtConfig();
        $config = self::getConfig();

        $primary_key_name = $config[AuthConfig::MODEL]::getPrimaryKey();
        $user = self::auth($field, $secret);

        $primary_key = array(
            'id' => $user->{$primary_key_name}
        );

        $payload = array_merge(
            $primary_key,
            $options
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

        $model = self::getConfigField(AuthConfig::MODEL);
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
     * Perform authentication
     *
     * @param string $field
     * @param string $secret
     * @return mixed
     */
    public static function auth(string $field, string $secret)
    {
        $combinations = self::getConfigField(AuthConfig::COMBINATION);
        $hash_method = self::getConfigField(AuthConfig::HASH_METHOD);
        $error_msg = self::getConfigField(AuthConfig::ERROR_MESSAGE);
        $model = self::getConfigField(AuthConfig::MODEL);

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

        self::dispatchAuthEvent($query);
        return $query;
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

        $model = self::getConfigField(AuthConfig::MODEL);
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
    protected static function getConfigField(string $config): mixed
    {
        $value = self::getConfig()[$config] ?? null;

        if (!$value) {
            throw new AuthSetupException(
                sprintf('Auth config "%s" not found', $config)
            );
        }

        return $value;
    }

    /**
     * Get JWT Config
     *
     * @return array
     */
    protected static function getJwtConfig(): array
    {
        $config = self::getConfig();
        $jwt_config = $config[AuthConfig::JWT] ?? null;

        if (!$jwt_config) {
            throw new AuthSetupException('Auth JWT not configured');
        }

        $key = $jwt_config['key'];
        $alg = $jwt_config['alg'];

        return [$key, $alg];
    }

    /**
     * Dispatch authenitcated event
     *
     * @param ModelInterface $user
     * @return void
     */
    protected static function dispatchAuthEvent(ModelInterface $user)
    {
        EventManager::dispatchEvent(
            handler: AuthEvents::AUTHENTICATED,
            arg: $user
        );
    }
}
