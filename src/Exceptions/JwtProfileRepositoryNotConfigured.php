<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use Facade\IgnitionContracts\BaseSolution;
use Facade\IgnitionContracts\ProvidesSolution;
use Facade\IgnitionContracts\Solution;
use RuntimeException;

/**
 * Signals that profile-based APIs were used before a repository was configured.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class JwtProfileRepositoryNotConfigured extends RuntimeException implements ExceptionInterface, JwtException, ProvidesSolution
{
    public static function missingBinding(): self
    {
        return new self('JWT profile repository is not configured');
    }

    public function getSolution(): Solution
    {
        /** @var BaseSolution $solution */
        $solution = BaseSolution::create('Configure the JWT profile repository');

        return $solution->setSolutionDescription(<<<'TEXT'
Register the package service provider and define at least one profile in
your `jwt.profiles` configuration array before calling `JWT::profile()`
or `JWT::issueFor()`.
TEXT);
    }
}
