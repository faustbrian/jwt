<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\CodingStandard\EasyCodingStandard\Factory;
use PhpCsFixer\Fixer\Alias\MbStrFunctionsFixer;

return Factory::create(
    paths: [__DIR__.'/src', __DIR__.'/tests'],
    skip: [
        MbStrFunctionsFixer::class => [
            __DIR__.'/src/Signer/AbstractHmacSigner.php',
            __DIR__.'/src/Signer/Blake2bSigner.php',
            __DIR__.'/tests/Signer/Hmac/HmacTestCase.php',
        ],
    ],
);
