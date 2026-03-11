<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Exceptions\CannotDecodeContent;
use Cline\JWT\Exceptions\CannotEncodeContent;
use PHPUnit\Framework\Attributes\Test;

test('json encode must return ajson string', function (): void {
    $encoder = new JoseEncoder();

    expect($encoder->jsonEncode(['test' => 'test']))->toBe('{"test":"test"}');
});
test('json encode should not escape unicode', function (): void {
    $encoder = new JoseEncoder();

    expect($encoder->jsonEncode('汉语'))->toBe('"汉语"');
});
test('json encode should not escape slashes', function (): void {
    $encoder = new JoseEncoder();

    expect($encoder->jsonEncode('https://google.com'))->toBe('"https://google.com"');
});
test('json encode must raise exception when an error has occurred', function (): void {
    $encoder = new JoseEncoder();

    $this->expectException(CannotEncodeContent::class);
    $this->expectExceptionCode(0);
    $this->expectExceptionMessage('Error while encoding to JSON');

    $encoder->jsonEncode("\xB1\x31");
});
test('json decode must return the decoded data', function (): void {
    $decoder = new JoseEncoder();

    expect($decoder->jsonDecode('{"test":{"test":{}}}'))->toBe(['test' => ['test' => []]]);
});
test('json decode must raise exception when an error has occurred', function (): void {
    $decoder = new JoseEncoder();

    $this->expectException(CannotDecodeContent::class);
    $this->expectExceptionCode(0);
    $this->expectExceptionMessage('Error while decoding from JSON');

    $decoder->jsonDecode('{"test":\'test\'}');
});
test('base64 url encode must return a url safe base64', function (): void {
    $data = base64_decode('0MB2wKB+L3yvIdzeggmJ+5WOSLaRLTUPXbpzqUe0yuo=', true);
    assert(is_string($data));

    $encoder = new JoseEncoder();
    expect($encoder->base64UrlEncode($data))->toBe('0MB2wKB-L3yvIdzeggmJ-5WOSLaRLTUPXbpzqUe0yuo');
});
test('base64 url encode must encode bilbo message properly', function (): void {
    /** @see https://tools.ietf.org/html/rfc7520#section-4 */
    $message = 'It’s a dangerous business, Frodo, going out your door. You step '
               ."onto the road, and if you don't keep your feet, there’s no knowing "
               .'where you might be swept off to.';

    $expected = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH'
                .'lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk'
                .'b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm'
                .'UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';

    $encoder = new JoseEncoder();
    expect($encoder->base64UrlEncode($message))->toBe($expected);
});
test('base64 url decode must raise exception when invalid base64 chars are used', function (): void {
    $decoder = new JoseEncoder();

    $this->expectException(CannotDecodeContent::class);
    $this->expectExceptionCode(0);
    $this->expectExceptionMessage('Error while decoding from Base64Url, invalid base64 characters detected');

    $decoder->base64UrlDecode('ááá');
});
test('base64 url decode must return the right data', function (): void {
    $data = base64_decode('0MB2wKB+L3yvIdzeggmJ+5WOSLaRLTUPXbpzqUe0yuo=', true);

    $decoder = new JoseEncoder();
    expect($decoder->base64UrlDecode('0MB2wKB-L3yvIdzeggmJ-5WOSLaRLTUPXbpzqUe0yuo'))->toBe($data);
});
test('base64 url decode must decode bilbo message properly', function (): void {
    /** @see https://tools.ietf.org/html/rfc7520#section-4 */
    $message = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH'
               .'lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk'
               .'b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm'
               .'UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';

    $expected = 'It’s a dangerous business, Frodo, going out your door. You step '
                ."onto the road, and if you don't keep your feet, there’s no knowing "
                .'where you might be swept off to.';

    $encoder = new JoseEncoder();
    expect($encoder->base64UrlDecode($message))->toBe($expected);
});
