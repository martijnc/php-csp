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

// Set the script-src directive to 'none'
$policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_SCRIPT_SRC, 'none');

// Enable the browsers xss blocking features
$policy->setReflectedXssPolicy(ContentSecurityPolicyHeaderBuilder::REFLECTED_XSS_BLOCK);

// Set the 'X-Frame-Options' header
$policy->setFrameOptions(ContentSecurityPolicyHeaderBuilder::FRAME_OPTION_SAME_ORIGIN);

// Set a report URL
$policy->setReportUri('https://example.com/csp/report.php');

// Get your CSP headers
$headers = $policy->getHeaders(true);

foreach ($headers as $header) {
    header(sprintf('%s: %s', $header['name'], $header['value']));
}
