<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer\Ecdsa;

use Cline\JWT\Exceptions\ConversionFailed;
use Cline\JWT\Signer\Ecdsa\MultibyteStringConverter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

use function bin2hex;
use function hex2bin;
use function mb_strlen;

/**
 * @coversDefaultClass \Cline\JWT\Signer\Ecdsa\MultibyteStringConverter
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(MultibyteStringConverter::class)]
#[CoversClass(ConversionFailed::class)]
final class MultibyteStringConverterTest extends TestCase
{
    /**
     * @param non-empty-string $r
     * @param non-empty-string $s
     * @param non-empty-string $asn1
     */
    #[Test()]
    #[DataProvider('pointsConversionData')]
    public function to_asn1_should_return_the_points_in_an_asn1_sequence_format(
        string $r,
        string $s,
        string $asn1,
    ): void {
        $converter = new MultibyteStringConverter();
        $message = hex2bin($r.$s);
        $this->assertIsString($message);
        $this->assertNotSame('', $message);

        $this->assertSame($asn1, bin2hex($converter->toAsn1($message, mb_strlen($r))));
    }

    #[Test()]
    public function to_asn1_should_raise_exception_when_points_do_not_have_correct_length(): void
    {
        $converter = new MultibyteStringConverter();

        $this->expectException(ConversionFailed::class);
        $this->expectExceptionMessage('Invalid signature length');
        $converter->toAsn1('a very wrong string', 64);
    }

    #[Test()]
    #[DataProvider('pointsConversionData')]
    public function from_asn1_should_return_the_concatenated_points(string $r, string $s, string $asn1): void
    {
        $converter = new MultibyteStringConverter();
        $message = hex2bin($asn1);
        $this->assertIsString($message);
        $this->assertNotSame('', $message);

        $this->assertSame($r.$s, bin2hex($converter->fromAsn1($message, mb_strlen($r))));
    }

    /**
     * @return array<array<string>>
     */
    public static function pointsConversionData(): iterable
    {
        yield [
            'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
            'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
            '3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7'
            .'a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
        ];

        yield [
            '94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46',
            '99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8',
            '306602310094edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fa'
            .'be4602310099ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38'
            .'628ac8',
        ];

        yield [
            '00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7'
            .'d4e8455cc91f9b15bf05ec36e377fa',
            '00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20'
            .'f8ccb1dccc43997f1ee0e44da4a67a',
            '308187024200c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add15'
            .'2b534931d7d4e8455cc91f9b15bf05ec36e377fa0241617cce7cf5064806c467f678d3b4080d6f1cc50af26ca20941730828'
            .'1b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a',
        ];
    }

    #[Test()]
    #[DataProvider('provideFrom_asn1_should_raise_exception_on_invalid_messageCases')]
    public function from_asn1_should_raise_exception_on_invalid_message(string $message, string $expectedMessage): void
    {
        $converter = new MultibyteStringConverter();
        $message = hex2bin($message);
        $this->assertIsString($message);

        $this->expectException(ConversionFailed::class);
        $this->expectExceptionMessage($expectedMessage);
        $converter->fromAsn1($message, 64);
    }

    /**
     * @return array<array<string>>
     */
    public static function provideFrom_asn1_should_raise_exception_on_invalid_messageCases(): iterable
    {
        yield 'Not a sequence' => ['', 'Should start with a sequence'];

        yield 'Sequence without length' => ['30', 'Should contain an integer'];

        yield 'Only one string element' => ['3006030204f0', 'Should contain an integer'];

        yield 'Only one integer element' => ['3004020101', 'Should contain an integer'];

        yield 'Integer+string elements' => ['300a020101030204f0', 'Should contain an integer'];
    }
}
