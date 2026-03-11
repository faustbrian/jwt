<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Token;

/**
 * Canonical names for the registered JWT claims understood by the package.
 *
 * These constants anchor both builder APIs and validation logic so registered
 * claims are referenced consistently across the codebase. The grouped `ALL` and
 * `DATE_CLAIMS` lists are used to protect reserved names and apply formatter
 * rules selectively.
 *
 * @author Brian Faust <brian@cline.sh>
 * @see https://tools.ietf.org/html/rfc7519#section-4.1
 */
final class RegisteredClaims
{
    public const array ALL = [
        self::AUDIENCE,
        self::EXPIRATION_TIME,
        self::ID,
        self::ISSUED_AT,
        self::ISSUER,
        self::NOT_BEFORE,
        self::SUBJECT,
    ];

    public const array DATE_CLAIMS = [
        self::ISSUED_AT,
        self::NOT_BEFORE,
        self::EXPIRATION_TIME,
    ];

    /**
     * Identifies the recipients that the JWT is intended for.
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public const string AUDIENCE = 'aud';

    /**
     * Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.4
     */
    public const string EXPIRATION_TIME = 'exp';

    /**
     * Provides a unique identifier for the JWT.
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    public const string ID = 'jti';

    /**
     * Identifies the time at which the JWT was issued.
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.6
     */
    public const string ISSUED_AT = 'iat';

    /**
     * Identifies the principal that issued the JWT.
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public const string ISSUER = 'iss';

    /**
     * Identifies the time before which the JWT MUST NOT be accepted for processing.
     *
     * https://tools.ietf.org/html/rfc7519#section-4.1.5
     */
    public const string NOT_BEFORE = 'nbf';

    /**
     * Identifies the principal that is the subject of the JWT.
     *
     * https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public const string SUBJECT = 'sub';

    /**
     * Prevent instantiation of this constant-only utility type.
     */
    private function __construct() {}
}
