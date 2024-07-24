<?php

namespace Cube\Packages\Auth;

use Cube\Interfaces\ModelInterface;

readonly class AuthJwtAttemptResult
{
    public function __construct(
        public ModelInterface $user,
        public string $token
    ) {
    }
}
