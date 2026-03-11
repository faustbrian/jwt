<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer;

use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Signer\Blake2bSigner;
use Cline\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use function hash_equals;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Blake2bSigner::class)]
#[UsesClass(InMemory::class)]
#[UsesClass(InvalidKeyProvided::class)]
#[UsesClass(SodiumBase64Polyfill::class)]
final class Blake2bTest extends TestCase
{
    private const string KEY_ONE = 'GOu4rLyVCBxmxP+sbniU68ojAja5PkRdvv7vNvBCqDQ=';

    private const string KEY_TWO = 'Pu7gywseH+R5HLIWnMll4rEg1ltjUPq/P9WwEzAsAb8=';

    private const string CONTENTS = 'test';

    private const string EXPECTED_HASH_WITH_KEY_ONE = '/TG5kmkav/YGl3I9uQiv4cm1VN6Q0zPCom4G7+p74JU=';

    private const string SHORT_KEY = 'PIBQuM5PopdMxtmTWmyvNA==';

    private InMemory $keyOne;

    private InMemory $keyTwo;

    /** @var non-empty-string */
    private string $expectedHashWithKeyOne;

    #[Before()]
    public function initializeKey(): void
    {
        $this->keyOne = InMemory::base64Encoded(self::KEY_ONE);
        $this->keyTwo = InMemory::base64Encoded(self::KEY_TWO);

        $this->expectedHashWithKeyOne = SodiumBase64Polyfill::base642bin(
            self::EXPECTED_HASH_WITH_KEY_ONE,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL,
        );
    }

    #[Test()]
    public function algorithm_id_must_be_correct(): void
    {
        $signer = new Blake2bSigner();

        $this->assertSame('BLAKE2B', $signer->algorithmId());
    }

    #[Test()]
    public function generated_signature_must_be_successfully_verified(): void
    {
        $signer = new Blake2bSigner();

        $this->assertTrue(hash_equals($this->expectedHashWithKeyOne, $signer->sign(self::CONTENTS, $this->keyOne)));
        $this->assertTrue($signer->verify($this->expectedHashWithKeyOne, self::CONTENTS, $this->keyOne));
    }

    #[Test()]
    public function sign_should_reject_short_keys(): void
    {
        $signer = new Blake2bSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 256 bits, only 128 bits provided');

        $signer->sign(self::CONTENTS, InMemory::base64Encoded(self::SHORT_KEY));
    }

    #[Test()]
    public function verify_should_return_false_when_expected_hash_was_not_created_with_same_information(): void
    {
        $signer = new Blake2bSigner();

        $this->assertFalse(hash_equals($this->expectedHashWithKeyOne, $signer->sign(self::CONTENTS, $this->keyTwo)));
        $this->assertFalse($signer->verify($this->expectedHashWithKeyOne, self::CONTENTS, $this->keyTwo));
    }
}
