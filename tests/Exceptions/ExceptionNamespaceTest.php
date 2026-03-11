<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\JWT\Exceptions\CannotDecodeContent;
use Cline\JWT\Exceptions\CannotEncodeContent;
use Cline\JWT\Exceptions\CannotSignPayload;
use Cline\JWT\Exceptions\CannotValidateARegisteredClaim;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\ConversionFailed;
use Cline\JWT\Exceptions\EmptyKeyProvided;
use Cline\JWT\Exceptions\FileCouldNotBeRead;
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
use Cline\JWT\Exceptions\LeewayCannotBeNegative;
use Cline\JWT\Exceptions\MissingClaimsPart;
use Cline\JWT\Exceptions\MissingHeaderPart;
use Cline\JWT\Exceptions\MissingSignaturePart;
use Cline\JWT\Exceptions\MissingTokenSeparators;
use Cline\JWT\Exceptions\NoConstraintsGiven;
use Cline\JWT\Exceptions\ParserMustReturnUnencryptedToken;
use Cline\JWT\Exceptions\RegisteredClaimGiven;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;
use Cline\JWT\Exceptions\TokenPartMustBeArray;
use Cline\JWT\Exceptions\TooShortKeyProvided;
use Cline\JWT\Exceptions\UnparseableDateClaimValue;
use Cline\JWT\Exceptions\UnparseableKeyProvided;
use Cline\JWT\Exceptions\UnsupportedHeaderFound;

test('exception symbols are available from the shared namespace', function (string $symbol, string $type): void {
    expect(match ($type) {
        'class' => class_exists($symbol),
        'interface' => interface_exists($symbol),
    })->toBeTrue($symbol.' should autoload from src/Exceptions');
})->with('provideException_classes_are_available_from_the_shared_namespaceCases');

/**
 * @return iterable<array{class-string|interface-string, 'class'|'interface'}>
 */
dataset('provideException_classes_are_available_from_the_shared_namespaceCases', function () {
    yield [CannotDecodeContent::class, 'class'];

    yield [CannotEncodeContent::class, 'class'];

    yield [CannotSignPayload::class, 'class'];

    yield [CannotValidateARegisteredClaim::class, 'class'];

    yield [ConstraintViolation::class, 'class'];

    yield [ConversionFailed::class, 'class'];

    yield [EmptyKeyProvided::class, 'class'];

    yield [FileCouldNotBeRead::class, 'class'];

    yield [InvalidAsn1Integer::class, 'class'];

    yield [InvalidAsn1StartSequence::class, 'class'];

    yield [InvalidBase64UrlContent::class, 'class'];

    yield [IncompatibleKeyLengthProvided::class, 'class'];

    yield [IncompatibleKeyTypeProvided::class, 'class'];

    yield [InvalidJsonContent::class, 'class'];

    yield [InvalidKeyProvided::class, 'class'];

    yield [InvalidSignatureLength::class, 'class'];

    yield [InvalidTokenStructure::class, 'class'];

    yield [JwtException::class, 'interface'];

    yield [JwtProfileRepositoryNotConfigured::class, 'class'];

    yield [LeewayCannotBeNegative::class, 'class'];

    yield [MissingClaimsPart::class, 'class'];

    yield [MissingHeaderPart::class, 'class'];

    yield [MissingSignaturePart::class, 'class'];

    yield [MissingTokenSeparators::class, 'class'];

    yield [NoConstraintsGiven::class, 'class'];

    yield [ParserMustReturnUnencryptedToken::class, 'class'];

    yield [RegisteredClaimGiven::class, 'class'];

    yield [RequiredConstraintsViolated::class, 'class'];

    yield [TokenPartMustBeArray::class, 'class'];

    yield [TooShortKeyProvided::class, 'class'];

    yield [UnparseableDateClaimValue::class, 'class'];

    yield [UnparseableKeyProvided::class, 'class'];

    yield [UnsupportedHeaderFound::class, 'class'];
});
