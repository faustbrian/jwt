<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Carbon\CarbonInterface;
use Cline\JWT\Contracts\HeadersInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Token\Headers;

/**
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class UnsupportedParser implements ParserInterface
{
    public function parse(string $jwt): TokenInterface
    {
        return new class() implements TokenInterface
        {
            public function headers(): HeadersInterface
            {
                return new Headers([], '');
            }

            public function isPermittedFor(string $audience): bool
            {
                return false;
            }

            public function isIdentifiedBy(string $id): bool
            {
                return false;
            }

            public function isRelatedTo(string $subject): bool
            {
                return false;
            }

            public function hasBeenIssuedBy(string ...$issuers): bool
            {
                return false;
            }

            public function hasBeenIssuedBefore(CarbonInterface $now): bool
            {
                return false;
            }

            public function isMinimumTimeBefore(CarbonInterface $now): bool
            {
                return false;
            }

            public function isExpired(CarbonInterface $now): bool
            {
                return false;
            }

            public function toString(): string
            {
                return 'unsupported-parser';
            }
        };
    }
}
