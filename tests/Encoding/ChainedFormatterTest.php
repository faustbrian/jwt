<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\Attributes\Test;

test('format claims should apply all configured formatters', function (): void {
    $expiration = CarbonImmutable::createFromFormat('U.u', '1487285080.123456');
    expect($expiration)->toBeInstanceOf(CarbonImmutable::class);

    $claims = [
        RegisteredClaims::AUDIENCE => ['test'],
        RegisteredClaims::EXPIRATION_TIME => $expiration,
    ];

    $formatter = ChainedFormatter::default();
    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::AUDIENCE])->toBe('test');
    expect($formatted[RegisteredClaims::EXPIRATION_TIME])->toEqualWithDelta(1_487_285_080.123_456, \PHP_FLOAT_EPSILON);

    $formatter = ChainedFormatter::withUnixTimestampDates();
    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::AUDIENCE])->toBe('test');
    expect($formatted[RegisteredClaims::EXPIRATION_TIME])->toBe(1_487_285_080);
});
