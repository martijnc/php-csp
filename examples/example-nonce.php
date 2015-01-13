<?php
/**
 * Copyright 2015, Martijn Croonen.
 * All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
include '../src/Phpcsp/Security/ContentSecurityPolicyHeaderBuilder.php';

use Phpcsp\Security\ContentSecurityPolicyHeaderBuilder;

$policy = new ContentSecurityPolicyHeaderBuilder();

// Set the default-src directive to 'none'
$policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_DEFAULT_SRC, 'none');

$myScriptNonce = 'thisShouldBeRandom';

// Add the nonce to the script-src directive
$policy->addNonce(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_SCRIPT_SRC, $myScriptNonce);

$headers = $policy->getHeaders(false);

foreach ($headers as $header) {
    header(sprintf('%s: %s', $header['name'], $header['value']));
}
