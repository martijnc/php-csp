<?php
/**
 * Copyright 2015, Martijn Croonen.
 * All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
namespace Phpcsp\Security;

/**
 * Class ContentSecurityPolicyHeaderBuilderTest
 */
class ContentSecurityPolicyHeaderBuilderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Tests the referrer policy 'none' value.
     *
     * @throws InvalidValueException
     */
    public function testReferrerDirectiveValueNone()
    {
        $policy = $this->getNewInstance();
        $policy->setReferrerPolicy(ContentSecurityPolicyHeaderBuilder::REFERRER_NONE);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('referrer none;', $headers[0]['value']);
    }

    /**
     * Tests the referrer policy 'origin' value.
     *
     * @throws InvalidValueException
     */
    public function testReferrerDirectiveValueOrigin()
    {
        $policy = $this->getNewInstance();
        $policy->setReferrerPolicy(ContentSecurityPolicyHeaderBuilder::REFERRER_ORIGIN);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('referrer origin;', $headers[0]['value']);
    }

    /**
     * Tests the referrer policy 'none-when-downgrade' value.
     *
     * @throws InvalidValueException
     */
    public function testReferrerDirectiveValueDowngrade()
    {
        $policy = $this->getNewInstance();
        $policy->setReferrerPolicy(ContentSecurityPolicyHeaderBuilder::REFERRER_NONE_WHEN_DOWNGRADE);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('referrer none-when-downgrade;', $headers[0]['value']);
    }

    /**
     * Tests the referrer policy 'origin-when-cross-origin' value.
     *
     * @throws InvalidValueException
     */
    public function testReferrerDirectiveValueCrossOrigin()
    {
        $policy = $this->getNewInstance();
        $policy->setReferrerPolicy(ContentSecurityPolicyHeaderBuilder::REFERRER_ORIGIN_WHEN_CROSS_ORIGIN);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('referrer origin-when-cross-origin;', $headers[0]['value']);
    }

    /**
     * Tests the referrer policy 'unsafe-url' value.
     *
     * @throws InvalidValueException
     */
    public function testReferrerDirectiveValueUnsafeUrl()
    {
        $policy = $this->getNewInstance();
        $policy->setReferrerPolicy(ContentSecurityPolicyHeaderBuilder::REFERRER_UNSAFE_URL);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('referrer unsafe-url;', $headers[0]['value']);
    }

    /**
     * Tests the reflected-xss policy 'allow' value.
     *
     * @throws InvalidValueException
     */
    public function testReflectedXssDirectiveValueAllow()
    {
        $policy = $this->getNewInstance();
        $policy->setReflectedXssPolicy(ContentSecurityPolicyHeaderBuilder::REFLECTED_XSS_ALLOW);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('reflected-xss allow;', $headers[0]['value']);
    }

    /**
     * Tests the reflected-xss policy 'filter' value.
     *
     * @throws InvalidValueException
     */
    public function testReflectedXssDirectiveValueFilter()
    {
        $policy = $this->getNewInstance();
        $policy->setReflectedXssPolicy(ContentSecurityPolicyHeaderBuilder::REFLECTED_XSS_FILTER);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('reflected-xss filter;', $headers[0]['value']);
    }

    /**
     * Tests the reflected-xss policy 'block' value.
     *
     * @throws InvalidValueException
     */
    public function testReflectedXssDirectiveValueBlock()
    {
        $policy = $this->getNewInstance();
        $policy->setReflectedXssPolicy(ContentSecurityPolicyHeaderBuilder::REFLECTED_XSS_BLOCK);

        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('reflected-xss block;', $headers[0]['value']);
    }

    /**
     * Tests source-set functionality.
     *
     * @throws InvalidDirectiveException
     * @throws SourceSetNotFoundException
     */
    public function testSourceSets()
    {
        $policy = $this->getNewInstance();
        $policy->defineSourceSet('test-set', ['example.com', 'self']);
        $headers = $policy->getHeaders(false);
        $this->assertEmpty($headers, 'Policy is not empty when no directives have been set');

        $policy->addSourceSet(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_SCRIPT_SRC, 'test-set');
        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('script-src example.com \'self\';', $headers[0]['value']);

        $policy->defineSourceSet('test-set', ['self']);
        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('script-src \'self\';', $headers[0]['value']);
    }

    /**
     * Tests (report-only) functionality by checking the header name.
     *
     * @throws InvalidDirectiveException
     */
    public function testHeaderName()
    {
        $policy = $this->getNewInstance();
        $policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_SCRIPT_SRC, 'example.com');
        $headers = $policy->getHeaders(false);
        $this->assertEquals('Content-Security-Policy', $headers[0]['name']);

        $policy->enforcePolicy(false);
        $headers = $policy->getHeaders(false);
        $this->assertEquals('Content-Security-Policy-Report-Only', $headers[0]['name']);
    }

    /**
     * Test for the report-uri functionality.
     */
    public function testReportUri()
    {
        $policy = $this->getNewInstance();
        $policy->setReportUri('https://example.com/csp/report.php');
        $headers = $policy->getHeaders(false);
        $this->assertEquals('report-uri https://example.com/csp/report.php;', $headers[0]['value']);
    }

    /**
     * Tests the proper encoding of tokens defined by the CSP specification.
     *
     * @throws InvalidDirectiveException
     * @throws SourceSetNotFoundException
     */
    public function testTokenEncoding()
    {
        $policy = $this->getNewInstance();
        $policy->defineSourceSet('test-set', ['self', 'unsafe-redirect', 'none']);
        $policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_STYLE_SRC, 'unsafe-inline');
        $policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_STYLE_SRC, 'unsafe-eval');
        $policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_STYLE_SRC, 'https');
        $policy->addSourceExpression(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_STYLE_SRC, 'http://example.com');
        $policy->addSourceSet(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_STYLE_SRC, 'test-set');
        $headers = $policy->getHeaders(false);
        $this->assertEquals(
            "style-src 'unsafe-inline' 'unsafe-eval' https http://example.com 'self' 'unsafe-redirect' 'none';",
            $headers[0]['value']
        );
    }

    /**
     * Tests the legacy headers.
     *
     * @throws InvalidValueException
     */
    public function testLegacyHeaders()
    {
        $policy = $this->getNewInstance();
        $policy->setReflectedXssPolicy(ContentSecurityPolicyHeaderBuilder::REFLECTED_XSS_BLOCK);
        $headers = $policy->getHeaders(true);
        $this->assertEquals(2, count($headers));
        $this->assertEquals('reflected-xss block;', $headers[0]['value']);
        $this->assertEquals('X-XSS-Protection', $headers[1]['name']);
        $this->assertEquals('1; mode=block', $headers[1]['value']);
    }

    /**
     * Tests the nonce functionality.
     *
     * @throws \Exception
     */
    public function testNonce()
    {
        $policy = $this->getNewInstance();
        $policy->addNonce(ContentSecurityPolicyHeaderBuilder::DIRECTIVE_SCRIPT_SRC, 'Nc3n83cnSAd3wc3Sasdfn939hc3');
        $headers = $policy->getHeaders(false);
        $this->assertEquals(1, count($headers));
        $this->assertEquals('script-src \'nonce-Nc3n83cnSAd3wc3Sasdfn939hc3\';', $headers[0]['value']);
    }

    /**
     * Creates fresh instances of the helper.
     *
     * @return ContentSecurityPolicyHeaderBuilder
     */
    protected function getNewInstance()
    {
        return new ContentSecurityPolicyHeaderBuilder();
    }
}
