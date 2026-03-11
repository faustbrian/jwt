<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use InvalidArgumentException;
use Throwable;

/**
 * Signals that key material could not be loaded from a filesystem path.
 *
 * This exception is raised by in-memory key factories that accept file paths.
 * It keeps file access failures inside the package's exception hierarchy while
 * preserving the original throwable so callers can distinguish missing files,
 * permission errors, and other I/O problems when needed.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class FileCouldNotBeRead extends InvalidArgumentException implements ExceptionInterface
{
    /**
     * Create an exception for an unreadable or invalid key file.
     *
     * The original throwable is attached when file opening fails so debugging
     * can still reach the underlying SPL or filesystem error.
     *
     * @param non-empty-string $path
     */
    public static function onPath(string $path, ?Throwable $cause = null): self
    {
        return new self(
            message: 'The path "'.$path.'" does not contain a valid key file',
            previous: $cause,
        );
    }
}
