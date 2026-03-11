<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\JWT\Configuration;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Signer\AbstractEcdsaSigner;
use Cline\JWT\Signer\Ecdsa\Sha512 as ES512;
use Cline\JWT\Signer\Hmac\Sha256 as HS512;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Parser;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Tests\Keys;

use const PHP_EOL;

use function explode;
use function hash_hmac;
use function implode;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Configuration::class)]
#[CoversClass(JoseEncoder::class)]
#[CoversClass(Parser::class)]
#[CoversClass(Plain::class)]
#[CoversClass(Claims::class)]
#[CoversClass(Headers::class)]
#[CoversClass(Signature::class)]
#[CoversClass(AbstractEcdsaSigner::class)]
#[CoversClass(ES512::class)]
#[CoversClass(HS512::class)]
#[CoversClass(InMemory::class)]
#[CoversClass(SodiumBase64Polyfill::class)]
#[CoversClass(ConstraintViolation::class)]
#[CoversClass(Validator::class)]
#[CoversClass(SignedWith::class)]
final class MaliciousTamperingPreventionTest extends TestCase
{
    use Keys;

    private Configuration $config;

    #[Before()]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new ES512(),
            InMemory::plainText('my-private-key'),
            InMemory::plainText(
                '-----BEGIN PUBLIC KEY-----'.PHP_EOL
                .'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4'.PHP_EOL
                .'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU'.PHP_EOL
                .'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs'.PHP_EOL
                .'mZudf1zCUZ8/4eodlHU='.PHP_EOL
                .'-----END PUBLIC KEY-----',
            ),
        );
    }

    #[Test()]
    public function prevent_regressions_that_allows_malicious_tampering(): void
    {
        $data = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
            .'AQx1MqdTni6KuzfOoedg2-7NUiwe-b88SWbdmviz40GTwrM0Mybp1i1tVtm'
            .'TSQ91oEXGXBdtwsN6yalzP9J-sp2YATX_Tv4h-BednbdSvYxZsYnUoZ--ZU'
            .'dL10t7g8Yt3y9hdY_diOjIptcha6ajX8yzkDGYG42iSe3f5LywSuD6FO5c';

        // Let's let the attacker tamper with our message!
        $bad = $this->createMaliciousToken($data);

        /**
         * At this point, we have our forged message in $bad for testing...
         *
         * Now, if we allow the attacker to dictate what Signer we use
         * (e.g. HMAC-SHA512 instead of ECDSA), they can forge messages!
         */
        $token = $this->config->parser()->parse($bad);
        $this->assertInstanceOf(Plain::class, $token);

        $this->assertSame('world', $token->claims()->get('hello'), 'The claim content should not be modified');

        $validator = $this->config->validator();

        $this->assertFalse($validator->validate($token, new SignedWith(
            new HS512(),
            $this->config->verificationKey(),
        )), 'Using the attackers signer should make things unsafe');

        $this->assertFalse($validator->validate(
            $token,
            new SignedWith(
                $this->config->signer(),
                $this->config->verificationKey(),
            ),
        ), 'But we know which Signer should be used so the attack fails');
    }

    /**
     * @return non-empty-string
     */
    private function createMaliciousToken(string $token): string
    {
        $dec = new JoseEncoder();
        $asplode = explode('.', $token);

        // The user is lying; we insist that we're using HMAC-SHA512, with the
        // public key as the HMAC secret key. This just builds a forged message:
        $asplode[0] = $dec->base64UrlEncode('{"alg":"HS512","typ":"JWT"}');

        $hmac = hash_hmac(
            'sha512',
            $asplode[0].'.'.$asplode[1],
            $this->config->verificationKey()->contents(),
            true,
        );

        $asplode[2] = $dec->base64UrlEncode($hmac);

        return implode('.', $asplode);
    }
}
