# PHP Cube Authentication

This package helps integrate Authentication into Cube

- Install package:

```
composer require cube-php/auth
```

- After installing package, you will need to setup

```
php cube auth:setup
```

Running the above command will create the authentication config file in `config/auth.php` and authentication middleware in `app/Middlewares/Authentication.php`

Auth away!
