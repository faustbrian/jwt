<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer;

use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Signer\EdDsaSigner;
use Cline\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Keys;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(EdDsaSigner::class)]
#[UsesClass(InMemory::class)]
#[UsesClass(JoseEncoder::class)]
#[UsesClass(SodiumBase64Polyfill::class)]
final class EdDsaTest extends TestCase
{
    use Keys;

    #[Test()]
    public function algorithm_id_must_be_correct(): void
    {
        $this->assertSame('EdDSA', new EdDsaSigner()->algorithmId());
    }

    #[Test()]
    public function sign_should_return_a_valid_eddsa_signature(): void
    {
        $payload = 'testing';

        $signer = new EdDsaSigner();
        $signature = $signer->sign($payload, self::$edDsaKeys['private']);

        $publicKey = self::$edDsaKeys['public1']->contents();

        $this->assertTrue(sodium_crypto_sign_verify_detached($signature, $payload, $publicKey));
    }

    #[Test()]
    public function sign_should_raise_an_exception_when_key_is_invalid(): void
    {
        $signer = new EdDsaSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES');

        $signer->sign('testing', InMemory::plainText('tooshort'));
    }

    #[Test()]
    public function verify_should_return_true_when_signature_is_valid(): void
    {
        $payload = 'testing';
        $signature = sodium_crypto_sign_detached($payload, self::$edDsaKeys['private']->contents());
        $signer = new EdDsaSigner();

        $this->assertTrue($signer->verify($signature, $payload, self::$edDsaKeys['public1']));
    }

    #[Test()]
    public function verify_should_raise_an_exception_when_key_is_not_parseable(): void
    {
        $signer = new EdDsaSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_BYTES');

        $signer->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    /**
     * @see https://tools.ietf.org/html/rfc8037#appendix-A.4
     */
    #[Test()]
    public function signature_of_rfc_example(): void
    {
        $signer = new EdDsaSigner();
        $encoder = new JoseEncoder();

        $decoded = $encoder->base64UrlDecode('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A');
        $key = InMemory::plainText(
            $decoded
            .$encoder->base64UrlDecode('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'),
        );
        $payload = $encoder->base64UrlEncode('{"alg":"EdDSA"}')
            .'.'
            .$encoder->base64UrlEncode('Example of Ed25519 signing');
        $signature = $signer->sign($payload, $key);

        $this->assertSame('eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc', $payload);
        $this->assertSame('hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg', $encoder->base64UrlEncode($signature));
    }

    /**
     * @see https://tools.ietf.org/html/rfc8037#appendix-A.5
     */
    #[Test()]
    public function verification_of_rfc_example(): void
    {
        $signer = new EdDsaSigner();
        $encoder = new JoseEncoder();

        $decoded = $encoder->base64UrlDecode('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo');

        $key = InMemory::plainText($decoded);
        $payload = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = $encoder->base64UrlDecode(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg',
        );

        $this->assertTrue($signer->verify($signature, $payload, $key));
    }
}
