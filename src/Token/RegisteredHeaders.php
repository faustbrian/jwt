<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Token;

/**
 * Canonical names for the JOSE header parameters used by the package.
 *
 * Centralizing these strings keeps header parsing and typed accessors aligned with
 * the RFC-defined names without scattering literals across the token layer.
 *
 * @author Brian Faust <brian@cline.sh>
 * @see https://datatracker.ietf.org/doc/html/rfc7515#section-4.1
 */
final class RegisteredHeaders
{
    public const string ALGORITHM = 'alg';

    public const string CONTENT_TYPE = 'cty';

    public const string KEY_ID = 'kid';

    public const string TYPE = 'typ';

    /**
     * Prevent instantiation of this constant-only utility type.
     */
    private function __construct() {}
}
