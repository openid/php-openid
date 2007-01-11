<?php

/**
 * The OpenID and Yadis discovery implementation for OpenID 1.2.
 */

require_once "Auth/OpenID.php";
require_once "Auth/OpenID/Parse.php";
require_once "Auth/OpenID/Message.php";
require_once "Services/Yadis/XRIRes.php";
require_once "Services/Yadis/Yadis.php";

// XML namespace value
define('Auth_OpenID_XMLNS_1_0', 'http://openid.net/xmlns/1.0');

// Yadis service types
define('Auth_OpenID_TYPE_1_2', 'http://openid.net/signon/1.2');
define('Auth_OpenID_TYPE_1_1', 'http://openid.net/signon/1.1');
define('Auth_OpenID_TYPE_1_0', 'http://openid.net/signon/1.0');
define('Auth_OpenID_TYPE_2_0_IDP', 'http://openid.net/server/2.0');
define('Auth_OpenID_TYPE_2_0', 'http://openid.net/signon/2.0');

/**
 * Object representing an OpenID service endpoint.
 */
class Auth_OpenID_ServiceEndpoint {
    function Auth_OpenID_ServiceEndpoint()
    {
        $this->claimed_id = null;
        $this->server_url = null;
        $this->type_uris = array();
        $this->local_id = null;
        $this->canonicalID = null;
        $this->used_yadis = false; // whether this came from an XRDS
    }

    function usesExtension($extension_uri)
    {
        return in_array($extension_uri, $this->type_uris);
    }

    function preferredNamespace()
    {
        if (in_array(Auth_OpenID_TYPE_2_0_IDP, $this->type_uris) ||
            in_array(Auth_OpenID_TYPE_2_0, $this->type_uris)) {
            return Auth_OpenID_OPENID2_NS;
        } else {
            return Auth_OpenID_OPENID1_NS;
        }
    }

    function supportsType($type_uri)
    {
        // Does this endpoint support this type?
        return ((($type_uri == Auth_OpenID_OPENID2_NS) &&
                 (in_array(Auth_OpenID_TYPE_2_0_IDP, $this->type_uris))) or
                $this->usesExtension($type_uri));
    }

    function compatibilityMode()
    {
        return $this->preferredNamespace() != Auth_OpenID_OPENID2_NS;
    }

    function isOPIdentifier()
    {
        return in_array(Auth_OpenID_TYPE_2_0_IDP, $this->type_uris);
    }

    function fromOPEndpointURL($op_endpoint_url)
    {
        // Construct an OP-Identifier OpenIDServiceEndpoint object for
        // a given OP Endpoint URL
        $obj = new Auth_OpenID_ServiceEndpoint();
        $obj->server_url = $op_endpoint_url;
        $obj->type_uris = array(Auth_OpenID_TYPE_2_0_IDP);
        return $obj;
    }

    function parseService($yadis_url, $uri, $type_uris, $service_element)
    {
        // Set the state of this object based on the contents of the
        // service element.  Return true if successful, false if not
        // (if findOPLocalIdentifier returns false).
        $this->type_uris = $type_uris;
        $this->server_url = $uri;
        $this->used_yadis = true;

        if (!$this->isOPIdentifier()) {
            $this->claimed_id = $yadis_url;
            $this->local_id = Auth_OpenID_findOPLocalIdentifier($service_element,
                                                                $this->type_uris);
            if ($this->local_id === false) {
                return false;
            }
        }

        return true;
    }

    function getLocalID()
    {
        // Return the identifier that should be sent as the
        // openid.identity_url parameter to the server.
        if ($this->local_id === null && $this->canonicalID === null) {
            return $this->claimed_id;
        } else {
            if ($this->local_id) {
                return $this->local_id;
            } else {
                return $this->canonicalID;
            }
        }
    }

    function fromHTML($uri, $html)
    {
        $discovery_types = array(
                                 array(Auth_OpenID_TYPE_2_0,
                                       'openid2.provider', 'openid2.local_id'),
                                 array(Auth_OpenID_TYPE_1_1,
                                       'openid.server', 'openid.delegate')
                                 );

        $services = array();

        foreach ($discovery_types as $triple) {
            list($type_uri, $server_rel, $delegate_rel) = $triple;

            $urls = Auth_OpenID_legacy_discover($html, $server_rel,
                                                $delegate_rel);

            if ($urls === false) {
                continue;
            }

            list($delegate_url, $server_url) = $urls;

            $service = new Auth_OpenID_ServiceEndpoint();
            $service->claimed_id = $uri;
            $service->local_id = $delegate_url;
            $service->server_url = $server_url;
            $service->type_uris = array($type_uri);

            $services[] = $service;
        }

        return $services;
    }
}

function Auth_OpenID_findOPLocalIdentifier($service, $type_uris)
{
    // Extract a openid:Delegate value from a Yadis Service element.
    // If no delegate is found, returns null.  Returns false on
    // discovery failure (when multiple delegate/localID tags have
    // different values).

    $service->parser->registerNamespace('openid',
                                        Auth_OpenID_XMLNS_1_0);

    $service->parser->registerNamespace('xrd',
                                        Services_Yadis_XMLNS_XRD_2_0);

    $parser =& $service->parser;

    $permitted_tags = array();

    if (in_array(Auth_OpenID_TYPE_1_1, $type_uris) ||
        in_array(Auth_OpenID_TYPE_1_0, $type_uris)) {
        $permitted_tags[] = 'openid:Delegate';
    }

    if (in_array(Auth_OpenID_TYPE_2_0, $type_uris)) {
        $permitted_tags[] = 'xrd:LocalID';
    }

    $local_id = null;

    foreach ($permitted_tags as $tag_name) {
        $tags = $service->getElements($tag_name);

        foreach ($tags as $tag) {
            if ($local_id === null) {
                $local_id = $parser->content($tag);
            } else if ($local_id != $parser->content($tag)) {
                // format = 'More than one %r tag found in one service element'
                // message = format % (local_id_tag,)
                // raise DiscoveryFailure(message, None)
                return false;
            }
        }
    }

    return $local_id;
}

function filter_MatchesAnyOpenIDType(&$service)
{
    $uris = $service->getTypes();

    foreach ($uris as $uri) {
        if (in_array($uri,
                     array(Auth_OpenID_TYPE_1_0,
                           Auth_OpenID_TYPE_1_1,
                           Auth_OpenID_TYPE_1_2,
                           Auth_OpenID_TYPE_2_0,
                           Auth_OpenID_TYPE_2_0_IDP))) {
            return true;
        }
    }

    return false;
}

function Auth_OpenID_makeOpenIDEndpoints($uri, $endpoints)
{
    $s = array();

    if (!$endpoints) {
        return $s;
    }

    foreach ($endpoints as $service) {
        $type_uris = $service->getTypes();
        $uris = $service->getURIs();

        // If any Type URIs match and there is an endpoint URI
        // specified, then this is an OpenID endpoint
        if ($type_uris &&
            $uris) {

            foreach ($uris as $service_uri) {
                $openid_endpoint = new Auth_OpenID_ServiceEndpoint();
                if ($openid_endpoint->parseService($uri,
                                                   $service_uri,
                                                   $type_uris,
                                                   $service)) {
                    $s[] = $openid_endpoint;
                }
            }
        }
    }

    return $s;
}

function Auth_OpenID_discoverWithYadis($uri, &$fetcher)
{
    // Discover OpenID services for a URI. Tries Yadis and falls back
    // on old-style <link rel='...'> discovery if Yadis fails.

    // Might raise a yadis.discover.DiscoveryFailure if no document
    // came back for that URI at all.  I don't think falling back to
    // OpenID 1.0 discovery on the same URL will help, so don't bother
    // to catch it.
    $openid_services = array();

    $http_response = null;
    $response = Services_Yadis_Yadis::discover($uri, $http_response,
                                               $fetcher);

    if ($response) {
        $identity_url = $response->uri;
        $openid_services =
            $response->xrds->services(array('filter_MatchesAnyOpenIDType'));
    }

    if (!$openid_services) {
        return @Auth_OpenID_discoverWithoutYadis($uri,
                                                 $fetcher);
    }

    if (!$openid_services) {
        $body = $response->body;

        // Try to parse the response as HTML to get OpenID 1.0/1.1
        // <link rel="...">
        $openid_services = Auth_OpenID_ServiceEndpoint::fromHTML($identity_url,
                                                         $body);
    } else {
        $openid_services = Auth_OpenID_makeOpenIDEndpoints($response->uri,
                                                           $openid_services);
    }

    return array($identity_url, $openid_services, $http_response);
}

function _Auth_OpenID_discoverServiceList($uri, &$fetcher)
{
    list($url, $services, $resp) = Auth_OpenID_discoverWithYadis($uri,
                                                                 $fetcher);

    return $services;
}

function _Auth_OpenID_discoverXRIServiceList($uri, &$fetcher)
{
    list($url, $services, $resp) = _Auth_OpenID_discoverXRI($uri,
                                                            $fetcher);
    return $services;
}

function Auth_OpenID_discoverWithoutYadis($uri, &$fetcher)
{
    $http_resp = @$fetcher->get($uri);

    if ($http_resp->status != 200) {
        return array(null, array(), $http_resp);
    }

    $identity_url = $http_resp->final_url;

    // Try to parse the response as HTML to get OpenID 1.0/1.1 <link
    // rel="...">
    $endpoint =& new Auth_OpenID_ServiceEndpoint();
    $openid_services = $endpoint->fromHTML($identity_url, $http_resp->body);

    return array($identity_url, $openid_services, $http_resp);
}

function _Auth_OpenID_discoverXRI($iname, &$fetcher)
{
    $services = new Services_Yadis_ProxyResolver($fetcher);
    list($canonicalID, $service_list) = $services->query($iname,
                                                  array(Auth_OpenID_TYPE_1_0,
                                                        Auth_OpenID_TYPE_1_1,
                                                        Auth_OpenID_TYPE_1_2,
                                                        Auth_OpenID_TYPE_2_0,
                                                        Auth_OpenID_TYPE_2_0_IDP),
                                     array('filter_MatchesAnyOpenIDType'));

    $endpoints = Auth_OpenID_makeOpenIDEndpoints($iname, $service_list);

    for ($i = 0; $i < count($endpoints); $i++) {
        $endpoints[$i]->canonicalID = $canonicalID;
    }

    // FIXME: returned xri should probably be in some normal form
    return array($iname, $endpoints, null);
}

function Auth_OpenID_discover($uri, &$fetcher)
{
    return @Auth_OpenID_discoverWithYadis($uri, $fetcher);
}

?>