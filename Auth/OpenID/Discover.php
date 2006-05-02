<?php

require_once "Auth/OpenID.php";

// If the Yadis library is available, use it. Otherwise, only use
// old-style discovery.
/*
try:
    import yadis
except ImportError:
    yadis_available = False

    oidutil.log('Consumer operating without Yadis support '
                '(failed to import Yadis library)')

    class DisccoveryFailure(RuntimeError):
        """Stand-in in case we don't have Yadis"""
else:
    yadis_available = True
    from yadis.etxrd import nsTag, XRDSError
    from yadis.services import applyFilter as extractServices
    from yadis.discover import discover as yadisDiscover
    from yadis.discover import DiscoveryFailure
*/

require_once "Auth/OpenID/Parse.php"; // need Auth_OpenID_legacy_discover

define('_OPENID_1_0_NS', 'http://openid.net/xmlns/1.0');
define('_OPENID_1_2_TYPE', 'http://openid.net/signon/1.2');
define('_OPENID_1_1_TYPE', 'http://openid.net/signon/1.1');
define('_OPENID_1_0_TYPE', 'http://openid.net/signon/1.0');

/**
 * Object representing an OpenID service endpoint.
 */
class Auth_OpenID_ServiceEndpoint {
    var $openid_type_uris;

    function __init__()
    {
        $this->openid_type_uris = array(_OPENID_1_2_TYPE,
                                        _OPENID_1_1_TYPE,
                                        _OPENID_1_0_TYPE);

        $this->identity_url = null;
        $this->server_url = null;
        $this->type_uris = array();
        $this->delegate = null;
        $this->used_yadis = false; // whether this came from an XRDS
    }

    function usesExtension($extension_uri)
    {
        return in_array($extension_uri, $this->type_uris);
    }

    function parseService($yadis_url, $uri, $type_uris, $service_element)
    {
        // Set the state of this object based on the contents of the
        // service element.
        $this->type_uris = $type_uris;
        $this->identity_url = $yadis_url;
        $this->server_url = $uri;
        $this->delegate = findDelegate($service_element);
        $this->used_yadis = true;
    }

    function getServerID()
    {
        // Return the identifier that should be sent as the
        // openid.identity_url parameter to the server.
        if ($this->delegate === null) {
            return $this->identity_url;
        } else {
            return $this->delegate;
        }
    }

    function fromBasicServiceEndpoint(&$endpoint)
    {
        // Create a new instance of this class from the endpoint
        // object passed in.

        $type_uris = $endpoint->matchTypes($this->openid_type_uris);

        // If any Type URIs match and there is an endpoint URI
        // specified, then this is an OpenID endpoint
        if ($type_uris &&
            ($endpoint->uri !== null)) {
            $openid_endpoint = new Auth_OpenID_ServiceEndpoint();
            $openid_endpoint->parseService($endpoint->yadis_url,
                                           $endpoint->uri,
                                           $endpoint->type_uris,
                                           $endpoint->service_element);
        } else {
            $openid_endpoint = null;
        }

        return $openid_endpoint;
    }

    function fromHTML($uri, $html)
    {
        // Parse the given document as HTML looking for an OpenID <link
        // rel=...>
        $urls = Auth_OpenID_legacy_discover($html);
        if ($urls === false) {
            return null;
        }

        list($delegate_url, $server_url) = $urls;
        $service = new Auth_OpenID_ServiceEndpoint();
        $service->identity_url = $uri;
        $service->delegate = $delegate_url;
        $service->server_url = $server_url;
        $service->type_uris = array(_OPENID_1_0_TYPE);
        return $service;
    }
}

function findDelegate($service_element)
{
    // Extract a openid:Delegate value from a Yadis Service element
    // represented as an ElementTree Element object. If no delegate is
    // found, returns null.

    // XXX: should this die if there is more than one delegate element?
    $delegate_tag = nsTag(_OPENID_1_0_NS, 'Delegate');

    /*
    // FIX THIS ONCE YADIS SUPPORT IS AVAILABLE!
    $delegates = $service_element->findall($delegate_tag);
    for delegate_element in delegates:
        delegate = delegate_element.text
        break
    else:
        delegate = null

    return delegate
    */
}

/*
function discoverYadis(uri):
    """Discover OpenID services for a URI. Tries Yadis and falls back
    on old-style <link rel='...'> discovery if Yadis fails.

    @param uri: normalized identity URL
    @type uri: str

    @return: (identity_url, services)
    @rtype: (str, list(OpenIDServiceEndpoint))

    @raises: DiscoveryFailure
    """
    # Might raise a yadis.discover.DiscoveryFailure if no document
    # came back for that URI at all.  I don't think falling back
    # to OpenID 1.0 discovery on the same URL will help, so don't
    # bother to catch it.
    response = yadisDiscover(uri)

    identity_url = response.normalized_uri
    try:
        openid_services = extractServices(
            response.normalized_uri, response.response_text,
            OpenIDServiceEndpoint)
    except XRDSError:
        # Does not parse as a Yadis XRDS file
        openid_services = []

    if not openid_services:
        # Either not an XRDS or there are no OpenID services.

        if response.isXRDS():
            # if we got the Yadis content-type or followed the Yadis
            # header, re-fetch the document without following the Yadis
            # header, with no Accept header.
            return discoverNoYadis(uri)
        else:
            body = response.response_text

        # Try to parse the response as HTML to get OpenID 1.0/1.1
        # <link rel="...">
        try:
            service = OpenIDServiceEndpoint.fromHTML(identity_url, body)
        except ParseError:
            pass # Parsing failed, so return an empty list
        else:
            openid_services = [service]

    return (identity_url, openid_services)
*/

function Auth_OpenID_discover($uri, $fetcher)
{
    $http_resp = $fetcher->get($uri);
    list($code, $url, $body) = $http_resp;

    if ($code != 200) {
        // raise DiscoveryFailure(
        //             'HTTP Response status from identity URL host is not 200. '
        // 'Got status %r' % (http_resp.status,), http_resp)
        return null;
    }

    $identity_url = $url;

    // Try to parse the response as HTML to get OpenID 1.0/1.1 <link
    // rel="...">
    $endpoint =& new Auth_OpenID_ServiceEndpoint();
    $service = $endpoint->fromHTML($identity_url, $body);
    if ($service === null) {
        $openid_services = array();
    } else {
        $openid_services = array($service);
    }

    return array($identity_url, $openid_services);
}

/*
if yadis_available:
    discover = discoverYadis
else:
    discover = discoverWithoutYadis
*/

?>