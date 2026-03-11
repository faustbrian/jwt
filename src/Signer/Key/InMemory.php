<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Key;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Exceptions\EmptyKeyProvided;
use Cline\JWT\Exceptions\FileCouldNotBeRead;
use SensitiveParameter;
use SplFileObject;
use Throwable;

use function assert;
use function is_string;

/**
 * In-memory representation of signer key material.
 *
 * This value object is the default bridge between configuration and the signer
 * layer. It can be created from literal key contents, base64-encoded secrets, or
 * files on disk, while preserving an optional passphrase for encrypted private
 * keys. Empty inputs are rejected early so signers only receive usable material.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class InMemory implements KeyInterface
{
    /**
     * @param non-empty-string $contents   Raw key contents as they should be passed to cryptographic backends
     * @param string           $passphrase Optional passphrase used when opening encrypted private keys
     */
    private function __construct(
        #[SensitiveParameter()]
        public string $contents,
        #[SensitiveParameter()]
        public string $passphrase,
    ) {}

    /**
     * Create a key directly from plaintext contents already held by the caller.
     *
     * @param non-empty-string $contents
     */
    public static function plainText(
        #[SensitiveParameter()]
        string $contents,
        #[SensitiveParameter()]
        string $passphrase = '',
    ): self {
        self::guardAgainstEmptyKey($contents); // @phpstan-ignore staticMethod.alreadyNarrowedType

        return new self($contents, $passphrase);
    }

    /**
     * Create a key from base64-encoded contents.
     *
     * This is primarily useful for environment-variable transport where raw key
     * bytes are awkward to embed directly.
     *
     * @param non-empty-string $contents
     */
    public static function base64Encoded(
        #[SensitiveParameter()]
        string $contents,
        #[SensitiveParameter()]
        string $passphrase = '',
    ): self {
        $decoded = SodiumBase64Polyfill::base642bin(
            $contents,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL,
        );

        self::guardAgainstEmptyKey($decoded); // @phpstan-ignore staticMethod.alreadyNarrowedType

        return new self($decoded, $passphrase);
    }

    /**
     * Load key contents from disk and keep the optional passphrase alongside them.
     *
     * @param non-empty-string $path
     *
     * @throws FileCouldNotBeRead
     */
    public static function file(
        string $path,
        #[SensitiveParameter()]
        string $passphrase = '',
    ): self {
        try {
            $file = new SplFileObject($path);
        } catch (Throwable $throwable) {
            throw FileCouldNotBeRead::onPath($path, $throwable);
        }

        $fileSize = $file->getSize();
        $contents = $fileSize > 0 ? $file->fread($file->getSize()) : '';
        assert(is_string($contents));

        self::guardAgainstEmptyKey($contents);

        return new self($contents, $passphrase);
    }

    /**
     * Return the raw key contents supplied at construction time.
     */
    public function contents(): string
    {
        return $this->contents;
    }

    /**
     * Return the passphrase to use when the key represents an encrypted private key.
     */
    public function passphrase(): string
    {
        return $this->passphrase;
    }

    /**
     * Reject empty key payloads before they can reach the signer backend.
     *
     * @phpstan-assert non-empty-string $contents
     */
    private static function guardAgainstEmptyKey(string $contents): void
    {
        if ($contents === '') {
            throw EmptyKeyProvided::detected();
        }
    }
}
