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

// Define two source sets
$policy->defineSourceSet('my-scripts-cdn', [
    'https://cdn-scripts1.example.com/scripts/',
    'https://cdn-scripts2.example.com/scripts/'
]);

$policy->defineSourceSet('my-style-cdn', [
    'https://cdn-style1.example.com/css/',
    'https://cdn-style2.example.com/css/'
]);

// Add both to a directive
$policy->addSourceSet(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_SCRIPT_SRC, 'my-scripts-cdn');
$policy->addSourceSet(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_STYLE_SRC, 'my-style-cdn');

// Get your CSP headers
$headers = $policy->getHeaders(false);

foreach ($headers as $header) {
    header(sprintf('%s: %s', $header['name'], $header['value']));
}
