<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\JWT\Exceptions\CannotDecodeContent;
use Cline\JWT\Exceptions\FileCouldNotBeRead;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\Attributes\Test;

test('exception should be raised when invalid base64 chars are used', function (): void {
    $this->expectException(CannotDecodeContent::class);
    $this->expectExceptionMessage('Error while decoding from Base64Url, invalid base64 characters detected');

    InMemory::base64Encoded('ááá');
});
test('base64 encoded should decode key contents', function (): void {
    $key = InMemory::base64Encoded(base64_encode('testing'));

    expect($key->contents())->toBe('testing');
});
test('exception should be raised when file does not exists', function (): void {
    $path = __DIR__.'/not-found.pem';

    $this->expectException(FileCouldNotBeRead::class);
    $this->expectExceptionMessage('The path "'.$path.'" does not contain a valid key file');
    $this->expectExceptionCode(0);

    InMemory::file($path);
});
test('exception should be raised when file is empty', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('Key cannot be empty');

    InMemory::file(__DIR__.'/empty.pem');
});
test('contents should return configured data', function (): void {
    $key = InMemory::plainText('testing', 'test');

    expect($key->contents())->toBe('testing');
});
test('contents should return file contents when file path has been passed', function (): void {
    $key = InMemory::file(__DIR__.'/test.pem');

    expect($key->contents())->toBe('testing');
});
test('passphrase should return configured data', function (): void {
    $key = InMemory::plainText('testing', 'test');

    expect($key->passphrase())->toBe('test');
});
test('empty plain text content should raise exception', function (): void {
    $this->expectException(InvalidKeyProvided::class);

    // @phpstan-ignore-next-line
    InMemory::plainText('');
});
test('empty base64 content should raise exception', function (): void {
    $this->expectException(InvalidKeyProvided::class);

    // @phpstan-ignore-next-line
    InMemory::base64Encoded('');
});
