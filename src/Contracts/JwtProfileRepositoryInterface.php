<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Cline\JWT\JwtProfile;

/**
 * Contract for resolving named JWT profiles.
 *
 * Repositories hide where profile definitions come from, whether configuration,
 * a database, or another source, while still returning the strongly typed
 * JwtProfile model used by the facade.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface JwtProfileRepositoryInterface
{
    /**
     * Return the default profile chosen by the repository implementation.
     */
    public function default(): JwtProfile;

    /**
     * Resolve a named profile, or the repository default when null is provided.
     */
    public function get(?string $name = null): JwtProfile;
}
