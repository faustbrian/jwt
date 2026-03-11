<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\JWT\Contracts\ExceptionInterface;
use Cline\JWT\Exceptions\CannotDecodeContent;
use Cline\JWT\Exceptions\ConversionFailed;
use Cline\JWT\Exceptions\EmptyKeyProvided;
use Cline\JWT\Exceptions\IncompatibleKeyLengthProvided;
use Cline\JWT\Exceptions\IncompatibleKeyTypeProvided;
use Cline\JWT\Exceptions\InvalidAsn1Integer;
use Cline\JWT\Exceptions\InvalidAsn1StartSequence;
use Cline\JWT\Exceptions\InvalidBase64UrlContent;
use Cline\JWT\Exceptions\InvalidJsonContent;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Exceptions\InvalidSignatureLength;
use Cline\JWT\Exceptions\InvalidTokenStructure;
use Cline\JWT\Exceptions\JwtException;
use Cline\JWT\Exceptions\JwtProfileRepositoryNotConfigured;
use Cline\JWT\Exceptions\MissingClaimsPart;
use Cline\JWT\Exceptions\MissingHeaderPart;
use Cline\JWT\Exceptions\MissingSignaturePart;
use Cline\JWT\Exceptions\MissingTokenSeparators;
use Cline\JWT\Exceptions\ParserMustReturnUnencryptedToken;
use Cline\JWT\Exceptions\TokenPartMustBeArray;
use Cline\JWT\Exceptions\TooShortKeyProvided;
use Cline\JWT\Exceptions\UnparseableDateClaimValue;
use Cline\JWT\Exceptions\UnparseableKeyProvided;

test('package exception contract extends the jwt marker interface', function (): void {
    expect(is_subclass_of(ExceptionInterface::class, JwtException::class))->toBeTrue();
});

test('split package exception bases remain abstract', function (): void {
    expect(
        new ReflectionClass(CannotDecodeContent::class)->isAbstract(),
    )->toBeTrue()
        ->and(
            new ReflectionClass(ConversionFailed::class)->isAbstract(),
        )->toBeTrue()
        ->and(
            new ReflectionClass(InvalidKeyProvided::class)->isAbstract(),
        )->toBeTrue()
        ->and(
            new ReflectionClass(InvalidTokenStructure::class)->isAbstract(),
        )->toBeTrue();
});

test('concrete exceptions extend their new base classes', function (string $className, string $baseClass): void {
    expect(is_subclass_of($className, $baseClass))->toBeTrue()
        ->and(is_subclass_of($className, JwtException::class))->toBeTrue();
})->with([
    [InvalidJsonContent::class, CannotDecodeContent::class],
    [InvalidBase64UrlContent::class, CannotDecodeContent::class],
    [InvalidSignatureLength::class, ConversionFailed::class],
    [InvalidAsn1StartSequence::class, ConversionFailed::class],
    [InvalidAsn1Integer::class, ConversionFailed::class],
    [UnparseableKeyProvided::class, InvalidKeyProvided::class],
    [IncompatibleKeyTypeProvided::class, InvalidKeyProvided::class],
    [IncompatibleKeyLengthProvided::class, InvalidKeyProvided::class],
    [EmptyKeyProvided::class, InvalidKeyProvided::class],
    [TooShortKeyProvided::class, InvalidKeyProvided::class],
    [MissingTokenSeparators::class, InvalidTokenStructure::class],
    [MissingHeaderPart::class, InvalidTokenStructure::class],
    [MissingClaimsPart::class, InvalidTokenStructure::class],
    [MissingSignaturePart::class, InvalidTokenStructure::class],
    [TokenPartMustBeArray::class, InvalidTokenStructure::class],
    [UnparseableDateClaimValue::class, InvalidTokenStructure::class],
]);

test('new facade guard exceptions are package exceptions', function (): void {
    expect(is_subclass_of(JwtProfileRepositoryNotConfigured::class, JwtException::class))->toBeTrue()
        ->and(is_subclass_of(ParserMustReturnUnencryptedToken::class, JwtException::class))->toBeTrue();
});
