<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
use Cline\CodingStandard\Rector\Factory;
use PhpCsFixer\Fixer\Alias\MbStrFunctionsFixer;
use Rector\CodingStyle\Rector\ClassLike\NewlineBetweenClassLikeStmtsRector;
use RectorLaravel\Rector\MethodCall\ContainerBindConcreteWithClosureOnlyRector;
use Rector\DeadCode\Rector\Expression\RemoveDeadStmtRector;
use Rector\DeadCode\Rector\Stmt\RemoveUnreachableStatementRector;

return Factory::create(
    paths: [__DIR__.'/src', __DIR__.'/tests'],
    skip: [
        __DIR__.'/tests/Signer/Hmac/HmacTestCase.php',
        RemoveUnreachableStatementRector::class => [__DIR__.'/tests'],
        RemoveDeadStmtRector::class => [__DIR__.'/tests'],
        ContainerBindConcreteWithClosureOnlyRector::class,
        NewlineBetweenClassLikeStmtsRector::class,
        MbStrFunctionsFixer::class => [
            __DIR__.'/src/Signer/AbstractHmacSigner.php',
            __DIR__.'/src/Signer/Blake2bSigner.php',
            __DIR__.'/tests/Signer/Hmac/HmacTestCase.php',
        ],
    ],
);
