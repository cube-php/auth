<?php

namespace Cube\Packages\Auth;

enum AuthTokenType: string
{
    case BEARER = 'Bearer';
    case BASIC = 'Basic';
}
