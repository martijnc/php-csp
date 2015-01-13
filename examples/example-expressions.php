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

// Add a single origin for the script-src directive
$policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_SCRIPT_SRC, 'https://example.com/scripts/');

// Add a single origin for the style-src directive
$policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_STYLE_SRC, 'https://example.com/style/');

// Get your CSP headers
$headers = $policy->getHeaders(false);

foreach ($headers as $header) {
    header(sprintf('%s: %s', $header['name'], $header['value']));
}
