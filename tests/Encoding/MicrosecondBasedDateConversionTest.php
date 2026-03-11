<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Cline\JWT\Encoding\MicrosecondBasedDateConversion;
use Cline\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\Attributes\Test;

test('date claims have microseconds or seconds', function (): void {
    $issuedAt = CarbonImmutable::parse('@1487285080');
    $notBefore = CarbonImmutable::createFromFormat('U.u', '1487285080.000123');
    $expiration = CarbonImmutable::createFromFormat('U.u', '1487285080.123456');

    expect($notBefore)->toBeInstanceOf(CarbonImmutable::class);
    expect($expiration)->toBeInstanceOf(CarbonImmutable::class);

    $claims = [
        RegisteredClaims::ISSUED_AT => $issuedAt,
        RegisteredClaims::NOT_BEFORE => $notBefore,
        RegisteredClaims::EXPIRATION_TIME => $expiration,
        'testing' => 'test',
    ];

    $formatter = new MicrosecondBasedDateConversion();
    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::ISSUED_AT])->toBe(1_487_285_080);
    expect($formatted[RegisteredClaims::NOT_BEFORE])->toEqualWithDelta(1_487_285_080.000_123, \PHP_FLOAT_EPSILON);
    expect($formatted[RegisteredClaims::EXPIRATION_TIME])->toEqualWithDelta(1_487_285_080.123_456, \PHP_FLOAT_EPSILON);
    expect($formatted['testing'])->toBe('test');
    // this should remain untouched
});
test('not all date claims need to be configured', function (): void {
    $issuedAt = CarbonImmutable::parse('@1487285080');
    $expiration = CarbonImmutable::createFromFormat('U.u', '1487285080.123456');

    $claims = [
        RegisteredClaims::ISSUED_AT => $issuedAt,
        RegisteredClaims::EXPIRATION_TIME => $expiration,
        'testing' => 'test',
    ];

    $formatter = new MicrosecondBasedDateConversion();
    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::ISSUED_AT])->toBe(1_487_285_080);
    expect($formatted[RegisteredClaims::EXPIRATION_TIME])->toEqualWithDelta(1_487_285_080.123_456, \PHP_FLOAT_EPSILON);
    expect($formatted['testing'])->toBe('test');
    // this should remain untouched
});
