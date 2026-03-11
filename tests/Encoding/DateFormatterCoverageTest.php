<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Cline\JWT\Encoding\MicrosecondBasedDateConversion;
use Cline\JWT\Encoding\UnixTimestampDates;
use Cline\JWT\Token\RegisteredClaims;

test('microsecond based date conversion leaves non carbon registered dates unchanged', function (): void {
    $formatter = new MicrosecondBasedDateConversion();
    $claims = [
        RegisteredClaims::ISSUED_AT => '1700000000',
        RegisteredClaims::NOT_BEFORE => CarbonImmutable::createFromFormat('U.u', '1700000000.123456'),
    ];

    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::ISSUED_AT])->toBe('1700000000')
        ->and($formatted[RegisteredClaims::NOT_BEFORE])->toBe(1_700_000_000.123_456);
});

test('unix timestamp dates leaves non carbon registered dates unchanged', function (): void {
    $formatter = new UnixTimestampDates();
    $claims = [
        RegisteredClaims::EXPIRATION_TIME => '1700000000',
        RegisteredClaims::ISSUED_AT => CarbonImmutable::createFromFormat('U', '1700000001'),
    ];

    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::EXPIRATION_TIME])->toBe('1700000000')
        ->and($formatted[RegisteredClaims::ISSUED_AT])->toBe(1_700_000_001);
});
