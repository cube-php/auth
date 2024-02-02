<?php

namespace Cube\Packages\Auth;

use Cube\Interfaces\ModelInterface;

readonly class AuthJwtResult
{
    public function __construct(public ModelInterface $user, public array $params = [])
    {
    }
}
