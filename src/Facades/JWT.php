<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Laravel facade exposing the package-level JwtFacade singleton.
 *
 * This gives framework consumers a familiar static API while still delegating to
 * the container-managed runtime assembled by JwtServiceProvider.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @see \Cline\JWT\JwtFacade
 */
final class JWT extends Facade
{
    /**
     * Return the container binding name registered by JwtServiceProvider.
     */
    protected static function getFacadeAccessor(): string
    {
        return 'jwt';
    }
}
