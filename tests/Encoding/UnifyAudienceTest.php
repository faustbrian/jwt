<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\JWT\Encoding\UnifyAudience;
use Cline\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\Attributes\Test;

test('nothing should be done when audience is not set', function (): void {
    $claims = ['testing' => 'test'];

    $formatter = new UnifyAudience();
    $formatted = $formatter->formatClaims($claims);

    expect($formatted['testing'])->toBe('test');
});
test('audience should be formatted as single string when one value is used', function (): void {
    $claims = [
        RegisteredClaims::AUDIENCE => ['test1'],
        'testing' => 'test',
    ];

    $formatter = new UnifyAudience();
    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::AUDIENCE])->toBe('test1');
    expect($formatted['testing'])->toBe('test');
    // this should remain untouched
});
test('audience should be formatted as array when multiple values are used', function (): void {
    $claims = [
        RegisteredClaims::AUDIENCE => ['test1', 'test2', 'test3'],
        'testing' => 'test',
    ];

    $formatter = new UnifyAudience();
    $formatted = $formatter->formatClaims($claims);

    expect($formatted[RegisteredClaims::AUDIENCE])->toBe(['test1', 'test2', 'test3']);
    expect($formatted['testing'])->toBe('test');
    // this should remain untouched
});
