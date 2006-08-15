<?php

/**
 * Routines for XRI resolution.
 *
 * @package Yadis
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

require_once 'Services/Yadis/Misc.php';
require_once 'Services/Yadis/Yadis.php';
require_once 'Services/Yadis/XRDS.php';
require_once 'Auth/OpenID.php';

$DEFAULT_PROXY = 'http://proxy.xri.net/';
$XRI_AUTHORITIES = array('!', '=', '@', '+', '$', '(');

$parts = array();
foreach (array_merge($__UCSCHAR, $__IPRIVATE) as $pair) {
    list($m, $n) = $pair;
    $parts[] = sprintf("%s-%s", chr($m), chr($n));
}

$_escapeme_re = sprintf('/[%s]/', implode('', $parts));
$_xref_re = '/\((.*?)\)/';

function Services_Yadis_identifierScheme($identifier)
{
    global $XRI_AUTHORITIES;

    if (_startswith($identifier, 'xri://') ||
        (in_array($identifier[0], $XRI_AUTHORITIES))) {
        return "XRI";
    } else {
        return "URI";
    }
}

function Services_Yadis_toIRINormal($xri)
{
    if (!_startswith($xri, 'xri://')) {
        $xri = 'xri://' . $xri;
    }

    return Services_Yadis_escapeForIRI($xri);
}

function _escape_xref($xref_match)
{
    $xref = $xref_match[0];
    $xref = str_replace('/', '%2F', $xref);
    $xref = str_replace('?', '%3F', $xref);
    $xref = str_replace('#', '%23', $xref);
    return $xref;
}

function Services_Yadis_escapeForIRI($xri)
{
    global $_xref_re, $_escapeme_re;

    $xri = str_replace('%', '%25', $xri);
    $xri = preg_replace_callback($_xref_re, '_escape_xref', $xri);
    return $xri;
}

function Services_Yadis_toURINormal($xri)
{
    return Services_Yadis_iriToURI(Services_Yadis_toIRINormal($xri));
}

function Services_Yadis_iriToURI($iri)
{
    if (1) {
        return $iri;
    } else {
        global $_escapeme_re;
        // According to RFC 3987, section 3.1, "Mapping of IRIs to URIs"
        return preg_replace_callback($_escapeme_re,
                                     '_pct_escape_unicode', $iri);
    }
}

class Services_Yadis_ProxyResolver {
    function Services_Yadis_ProxyResolver(&$fetcher, $proxy_url = null)
    {
        global $DEFAULT_PROXY;

        $this->fetcher =& $fetcher;
        $this->proxy_url = $proxy_url;
        if (!$this->proxy_url) {
            $this->proxy_url = $DEFAULT_PROXY;
        }
    }

    function queryURL($xri, $service_type)
    {
        // trim off the xri:// prefix
        $qxri = substr(Services_Yadis_toURINormal($xri), 6);
        $hxri = $this->proxy_url . $qxri;
        $args = array(
                      '_xrd_r' => 'application/xrds+xml',
                      '_xrd_t' => $service_type
                      );
        $query = Services_Yadis_XRIAppendArgs($hxri, $args);
        return $query;
    }

    function query($xri, $service_types, $filters = array())
    {
        $services = array();
        foreach ($service_types as $service_type) {
            $url = $this->queryURL($xri, $service_type);
            $response = $this->fetcher->get($url);
            if ($response->status != 200) {
                continue;
            }
            $xrds = Services_Yadis_XRDS::parseXRDS($response->body);
            if (!$xrds) {
                continue;
            }
            $some_services = $xrds->services($filters);
            $services = array_merge($services, $some_services);
            // TODO:
            //  * If we do get hits for multiple service_types, we're
            //    almost certainly going to have duplicated service
            //    entries and broken priority ordering.
        }
        return $services;
    }
}

function Services_Yadis_XRIAppendArgs($url, $args)
{
    // Append some arguments to an HTTP query.  Yes, this is just like
    // OpenID's appendArgs, but with special seasoning for XRI
    // queries.

    if (count($args) == 0) {
        return $url;
    }

    // Non-empty array; if it is an array of arrays, use multisort;
    // otherwise use sort.
    if (array_key_exists(0, $args) &&
        is_array($args[0])) {
        // Do nothing here.
    } else {
        $keys = array_keys($args);
        sort($keys);
        $new_args = array();
        foreach ($keys as $key) {
            $new_args[] = array($key, $args[$key]);
        }
        $args = $new_args;
    }

    // According to XRI Resolution section "QXRI query parameters":
    //
    // "If the original QXRI had a null query component (only a
    //  leading question mark), or a query component consisting of
    //  only question marks, one additional leading question mark MUST
    //  be added when adding any XRI resolution parameters."
    if (strpos(rtrim($url, '?'), '?') !== false) {
        $sep = '&';
    } else {
        $sep = '?';
    }

    return $url . $sep . Auth_OpenID::httpBuildQuery($args);
}

?>