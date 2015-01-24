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

$script = "alert('Hello, world.');";

$policy->addHash(
    ContentSecurityPolicyHeaderBuilder::HASH_SHA_256,
    hash(ContentSecurityPolicyHeaderBuilder::HASH_SHA_256, $script, true)
);

// Get your CSP headers
$headers = $policy->getHeaders(false);
foreach ($headers as $header) {
    header(sprintf('%s: %s', $header['name'], $header['value']));
}
?>

<html>
<body>
<!-- Script will work -->
<script type="text/javascript"><?php echo $script; ?></script>
</body>
</html>