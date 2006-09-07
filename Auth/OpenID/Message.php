<?php

/**
 * Extension argument processing code
 */

// import urllib

require_once 'Auth/OpenID.php';
require_once 'Auth/OpenID/KVForm.php';
require_once 'Services/Yadis/XML.php';

// This doesn't REALLY belong here, but where is better?
$Auth_OpenID_IDENTIFIER_SELECT = "http://openid.net/identifier_select/2.0";

// URI for Simple Registration extension, the only commonly deployed
// OpenID 1.x extension, and so a special case
$Auth_OpenID_SREG_URI = 'http://openid.net/sreg/1.0';

// The OpenID 1.X namespace URI
$Auth_OpenID_OPENID1_NS = 'http://openid.net/sso/1.0';

// The OpenID 2.0 namespace URI
// XXX: not official (yet)
$Auth_OpenID_OPENID2_NS = 'http://openid.net/specs/2.0/base';

// The namespace consisting of pairs with keys that are prefixed with
// "openid."  but not in another namespace.
$Auth_OpenID_NULL_NAMESPACE = 'Null namespace';

// The null namespace, when it is an allowed OpenID namespace
$Auth_OpenID_OPENID_NS = 'OpenID namespace';

// The top-level namespace, excluding all pairs with keys that start
// with "openid."
$Auth_OpenID_BARE_NS = 'Bare namespace';

class Auth_OpenID_Mapping {
    function Auth_OpenID_Mapping($classic_array = null)
    {
        $this->keys = array();
        $this->values = array();

        if (is_array($classic_array)) {
            foreach ($classic_array as $key => $value) {
                $this->set($key, $value);
            }
        }
    }

    function isA($thing)
    {
        return (is_object($thing) &&
                strtolower(get_class($thing)) == 'auth_openid_mapping');
    }

    function keys()
    {
        return $this->keys;
    }

    function values()
    {
        return $this->values;
    }

    function items()
    {
        $temp = array();
        for ($i = 0; $i < count($this->keys); $i++) {
            $temp[] = array($this->keys[$i],
                            $this->values[$i]);
        }
    }

    function len()
    {
        return count($this->keys);
    }

    function set($key, $value)
    {
        $index = array_search($key, $this->keys);

        if ($index !== false) {
            $this->values[$index] = $value;
        } else {
            $this->keys[] = $key;
            $this->values[] = $value;
        }
    }

    function get($key, $default = null)
    {
        $index = array_search($key, $this->keys);

        if ($index !== false) {
            return $this->values[$index];
        } else {
            return $default;
        }
    }

    function del($key)
    {
        $index = array_search($key, $this->keys);

        if ($index !== false) {
            unset($this->keys[$index]);
            unset($this->values[$index]);
        }
    }

    function contains($value)
    {
        return (array_search($value, $this->values) !== false);
    }
}

/**
 * Maintains a bijective map between namespace uris and aliases.
 */
class Auth_OpenID_NamespaceMap {
    function Auth_OpenID_NamespaceMap()
    {
        global $Auth_OpenID_SREG_URI;

        $this->default_aliases = array($Auth_OpenID_SREG_URI => 'sreg');
        $this->alias_to_namespace = new Auth_OpenID_Mapping();
        $this->namespace_to_alias = new Auth_OpenID_Mapping();
    }

    function getAlias($namespace_uri)
    {
        return $this->namespace_to_alias->get($namespace_uri);
    }

    function getNamespaceURI($alias)
    {
        return $this->alias_to_namespace->get($alias);
    }

    function iterNamespaceURIs()
    {
        // Return an iterator over the namespace URIs
        return $this->namespace_to_alias->keys();
    }

    function iterAliases()
    {
        // Return an iterator over the aliases"""
        return $this->alias_to_namespace->keys();
    }

    function iteritems()
    {
        return $this->namespace_to_alias->items();
    }

    function addAlias($namespace_uri, $desired_alias)
    {
        global $Auth_OpenID_NULL_NAMESPACE;
        // Add an alias from this namespace URI to the desired alias

        // Check that there is not a namespace already defined for the
        // desired alias
        $current_namespace_uri =
            $this->alias_to_namespace->get($desired_alias);

        if (($current_namespace_uri !== null) &&
            ($current_namespace_uri != $namespace_uri)) {
            // Cannot map because previous mapping exists
            return null;
        }

        // Check that there is not already a (different) alias for
        // this namespace URI
        $alias = $this->namespace_to_alias->get($namespace_uri);

        if (($alias !== null) && ($alias != $desired_alias)) {
            // fmt = ('Cannot map %r to alias %r. '
            //        'It is already mapped to alias %r')
            // raise KeyError(fmt % (namespace_uri, desired_alias, alias))
            return null;
        }

        assert(($NULL_NAMESPACE === $desired_alias) ||
               is_string($desired_alias));

        $this->alias_to_namespace->set($desired_alias, $namespace_uri);
        $this->namespace_to_alias->set($namespace_uri, $desired_alias);
        return $desired_alias;
    }

    function add($namespace_uri)
    {
        // Add this namespace URI to the mapping, without caring what
        // alias it ends up with

        // See if this namespace is already mapped to an alias
        $alias = $this->namespace_to_alias->get($namespace_uri);

        if ($alias !== null) {
            return $alias;
        }

        // See if there is a default alias for this namespace
        $default_alias = $this->default_aliases->get($namespace_uri);

        if ($default_alias !== null) {
            if ($this->addAlias($namespace_uri, $default_alias) !== null) {
                return $default_alias;
            }
        }

        // Fall back to generating a numerical alias
        $i = 0;
        while (1) {
            $alias = strval($i);
            if ($this->addAlias($namespace_uri, strval($i)) === null) {
                $i += 1;
            } else {
                return $alias;
            }
        }

        // Should NEVER be reached!
        return null;
    }

    function isDefined($namespace_uri)
    {
        return $this->namespace_to_alias->contains($namespace_uri);
    }
}

/**
 * In the implementation of this object, null represents the global
 * namespace as well as a namespace with no key.
 */
class Auth_OpenID_Message {

    function Auth_OpenID_Message($openid_namespace = null)
    {
        global $Auth_OpenID_OPENID1_NS,
            $Auth_OpenID_OPENID2_NS,
            $Auth_OpenID_SREG_URI;

        // Create an empty Message
        $this->allowed_openid_namespaces = array(
                               $Auth_OpenID_OPENID1_NS,
                               $Auth_OpenID_OPENID2_NS);

        $this->default_namespaces = array(
                       'sreg' => $Auth_OpenID_SREG_URI
                                          );

        $this->args = new Auth_OpenID_Mapping();
        $this->namespaces = new Auth_OpenID_NamespaceMap();
        if ($openid_namespace === null) {
            $this->_openid_ns_uri = null;
        } else {
            $this->setOpenIDNamespace($openid_namespace);
        }
    }

    function fromPostArgs($args)
    {
        global $Auth_OpenID_BARE_NS;

        // Construct a Message containing a set of POST arguments
        $obj = new Auth_OpenID_Message();

        // Partition into "openid." args and bare args
        $openid_args = array();
        foreach ($args as $key => $value) {

            $parts = explode('.', $key, 2);

            if (count($parts) == 2) {
                list($prefix, $rest) = $parts;
            } else {
                $prefix = null;
            }

            if ($prefix != 'openid') {
                $obj->args->set(array($Auth_OpenID_BARE_NS, $key), $value);
            } else {
                $openid_args[$rest] = $value;
            }
        }

        $obj->_fromOpenIDArgs($openid_args);

        return $obj;
    }

    function fromOpenIDArgs($openid_args)
    {
        // Takes an array.

        // Construct a Message from a parsed KVForm message
        $obj = new Auth_OpenID_Message();
        $obj->_fromOpenIDArgs($openid_args);
        return $obj;
    }

    function _fromOpenIDArgs($openid_args)
    {
        // Takes an Auth_OpenID_Mapping instance OR an array.
        global $Auth_OpenID_NULL_NAMESPACE,
            $Auth_OpenID_OPENID1_NS;

        if (!Auth_OpenID_Mapping::isA($openid_args)) {
            $openid_args = new Auth_OpenID_Mapping($openid_args);
        }

        $ns_args = array();

        // Resolve namespaces
        foreach ($openid_args->items() as $pair) {
            list($rest, $value) = $pair;

            $parts = explode('.', $rest, 2);

            if (count($parts) == 2) {
                list($ns_alias, $ns_key) = $parts;
            } else {
                $ns_alias = $Auth_OpenID_NULL_NAMESPACE;
                $ns_key = $rest;
            }

            if ($ns_alias == 'ns') {
                $this->namespaces->addAlias($value, $ns_key);
            } else if (($ns_alias == $Auth_OpenID_NULL_NAMESPACE) &&
                       ($ns_key == 'ns')) {
                // null namespace
                $this->namespaces->addAlias($value,
                                            $Auth_OpenID_NULL_NAMESPACE);
            } else {
                $ns_args[] = array($ns_alias, $ns_key, $value);
            }
        }

        // Ensure that there is an OpenID namespace definition
        $openid_ns_uri =
            $this->namespaces->getNamespaceURI($Auth_OpenID_NULL_NAMESPACE);

        if ($openid_ns_uri === null) {
            $openid_ns_uri = $Auth_OpenID_OPENID1_NS;
        }

        $this->setOpenIDNamespace($openid_ns_uri);

        // Actually put the pairs into the appropriate namespaces
        foreach ($ns_args as $triple) {
            list($ns_alias, $ns_key, $value) = $triple;
            $ns_uri = $this->namespaces->getNamespaceURI($ns_alias);
            if ($ns_uri === null) {
                // Only try to map an alias to a default if it's an
                // OpenID 1.x message.
                if ($openid_ns_uri == $Auth_OpenID_OPENID1_NS) {
                    $ns_uri = Auth_OpenID::arrayGet(
                                        $this->default_namespaces,
                                        $ns_alias);
                }

                if ($ns_uri === null) {
                    $ns_uri = $openid_ns_uri;
                    $ns_key = sprintf('%s.%s', $ns_alias, $ns_key);
                } else {
                    $this->namespaces->addAlias($ns_uri, $ns_alias);
                }
            }

            $this->setArg($ns_uri, $ns_key, $value);
        }
    }

    function setOpenIDNamespace($openid_ns_uri)
    {
        global $Auth_OpenID_NULL_NAMESPACE;

        if (!in_array($openid_ns_uri, $this->allowed_openid_namespaces)) {
            // raise ValueError('Invalid null namespace: %r' % (openid_ns_uri,))
            return false;
        }

        $this->namespaces->addAlias($openid_ns_uri,
                                    $Auth_OpenID_NULL_NAMESPACE);
        $this->_openid_ns_uri = $openid_ns_uri;
    }

    function getOpenIDNamespace()
    {
        return $this->_openid_ns_uri;
    }

    function fromKVForm($kvform_string)
    {
        // Create a Message from a KVForm string
        return Auth_OpenID_Message::fromOpenIDArgs(
                     Auth_OpenID_KVForm::toArray($kvform_string));
    }

    function copy()
    {
        return $this;
    }

    function toPostArgs()
    {
        // Return all arguments with openid. in front of namespaced
        // arguments.

        global $Auth_OpenID_NULL_NAMESPACE,
            $Auth_OpenID_OPENID1_NS;

        $args = array();

        // Add namespace definitions to the output
        foreach ($this->namespaces->iteritems() as $pair) {
            list($ns_uri, $alias) = $pair;
            if ($alias == $Auth_OpenID_NULL_NAMESPACE) {
                if ($ns_uri != $Auth_OpenID_OPENID1_NS) {
                    $args['openid.ns'] = $ns_uri;
                } else {
                    // drop the default null namespace
                    // definition. This potentially changes a message
                    // since we have no way of knowing whether it was
                    // explicitly specified at the time the message
                    // was parsed. The vast majority of the time, this
                    // will be the right thing to do. Possibly this
                    // could look in the signed list.
                }
            } else {
                $ns_key = 'openid.ns.' . $alias;
                $args[$ns_key] = $ns_uri;
            }
        }

        foreach ($this->args->items() as $pair) {
            list($ns_parts, $value) = $pair;
            list($ns_uri, $ns_key) = $ns_parts;
            $key = $this->getKey($ns_uri, $ns_key);
            $args[$key] = $value;
        }

        return $args;
    }

    function toArgs()
    {
        // Return all namespaced arguments, failing if any
        // non-namespaced arguments exist.
        $post_args = $this->toPostArgs();
        $kvargs = array();
        foreach ($post_args as $k => $v) {
            if (strpos($k, 'openid.') !== 0) {
                // raise ValueError(
                //   'This message can only be encoded as a POST, because it '
                //   'contains arguments that are not prefixed with "openid."')
                return null;
            } else {
                $kvargs[substr($k, 7)] = $v;
            }
        }

        return $kvargs;
    }

    function toFormMarkup($action_url, $form_tag_attrs = null,
                          $submit_text = "Continue")
    {
        $xml =& Services_Yadis_getXMLParser();

        if ($xml === null) {
            // raise RuntimeError('This function requires ElementTree.')
            return null;
        }

        $form = "<form accept-charset=\"UTF-8\" ".
            "enctype=\"application/x-www-form-urlencoded\"";

        if (!$form_tag_attrs) {
            $form_tag_attrs = array();
        }

        $form_tag_attrs['action'] = $action_url;
        $form_tag_attrs['method'] = 'post';

        if ($form_tag_attrs) {
            foreach ($form_tag_attrs as $name => $attr) {
                $form .= sprintf(" %s=\"%s\"", $name, $attr);
            }
        }

        $form .= ">\n";

        foreach ($this->toPostArgs() as $name => $value) {
            $form .= sprintf(
                        "<input type=\"hidden\" name=\"%s\" value=\"%s\" />\n",
                        $name, $value);
        }

        $form .= sprintf("<input type=\"submit\" value=\"\" />\n",
                         $submit_text);

        $form .= "</form>\n";

        return $form;
    }

    function toURL($base_url)
    {
        // Generate a GET URL with the parameters in this message
        // attached as query parameters.
        return Auth_OpenID::appendArgs($base_url, $this->toPostArgs());
    }

    function toKVForm()
    {
        // Generate a KVForm string that contains the parameters in
        // this message. This will fail if the message contains
        // arguments outside of the 'openid.' prefix.
        return Auth_OpenID_KVForm::fromArray($this->toArgs());
    }

    function toURLEncoded()
    {
        // Generate an x-www-urlencoded string
        $args = array();

        foreach ($this->toPostArgs() as $k => $v) {
            $args[] = array($k, $v);
        }

        sort($args);
        return Auth_OpenID::httpBuildQuery($args);
    }

    function _fixNS($namespace)
    {
        global $Auth_OpenID_OPENID_NS,
            $Auth_OpenID_BARE_NS,
            $Auth_OpenID_SREG_URI;

        // Convert an input value into the internally used values of
        // this object

        if ($namespace == $OPENID_NS) {
            if ($this->_openid_ns_uri === null) {
                // raise UndefinedOpenIDNamespace('OpenID namespace not set')
                return null;
            } else {
                $namespace = $this->_openid_ns_uri;
            }
        }

        if (($namespace != $Auth_OpenID_BARE_NS) &&
            (!is_string($namespace))) {
            // raise TypeError(
            //     "Namespace must be BARE_NS, OPENID_NS or a string. got %r"
            //     % (namespace,))
            return null;
        }

        if (($namespace != $Auth_OpenID_BARE_NS) &&
            (strpos($namespace, ':') === false)) {
            // fmt = 'OpenID 2.0 namespace identifiers SHOULD be URIs. Got %r'
            // warnings.warn(fmt % (namespace,), DeprecationWarning)

            if ($namespace == 'sreg') {
                // fmt = 'Using %r instead of "sreg" as namespace'
                // warnings.warn(fmt % (SREG_URI,), DeprecationWarning,)
                return $Auth_OpenID_SREG_URI;
            }
        }

        return $namespace;
    }

    function hasKey($namespace, $ns_key)
    {
        $namespace = $this->_fixNS($namespace);
        if ($namespace !== null) {
            return $this->args->contains(array($namespace, $ns_key));
        } else {
            return false;
        }
    }

    function getKey($namespace, $ns_key)
    {
        global $Auth_OpenID_BARE_NS,
            $Auth_OpenID_NULL_NAMESPACE;

        // Get the key for a particular namespaced argument
        $namespace = $this->_fixNS($namespace);
        if ($namespace == $Auth_OpenID_BARE_NS) {
            return $ns_key;
        }

        $ns_alias = $this->namespaces->getAlias($namespace);

        // No alias is defined, so no key can exist
        if ($ns_alias === null) {
            return null;
        }

        if ($ns_alias == $Auth_OpenID_NULL_NAMESPACE) {
            $tail = $ns_key;
        } else {
            $tail = sprintf('%s.%s', $ns_alias, $ns_key);
        }

        return 'openid.' . $tail;
    }

    function getArg($namespace, $key, $default = null)
    {
        // Get a value for a namespaced key.
        $namespace = $this->_fixNS($namespace);
        if ($namespace !== null) {
            return $this->args->get(array($namespace, $key), $default);
        } else {
            return null;
        }
    }

    function getArgs($namespace)
    {
        // Get the arguments that are defined for this namespace URI

        $namespace = $this->_fixNS($namespace);
        if ($namespace !== null) {
            $stuff = array();
            foreach ($this->args->items() as $pair) {
                list($key, $value) = $pair;
                list($pair_ns, $ns_key) = $key;
                if ($pair_ns == $namespace) {
                    $stuff[$ns_key] = $value;
                }
            }

            return $stuff;
        }

        return null;
    }

    function updateArgs($namespace, $updates)
    {
        // Set multiple key/value pairs in one call

        $namespace = $this->_fixNS($namespace);

        if ($namespace !== null) {
            foreach ($updates as $k => $v) {
                $this->setArg($namespace, $k, $v);
            }
        }
    }

    function setArg($namespace, $key, $value)
    {
        // Set a single argument in this namespace
        $namespace = $this->_fixNS($namespace);

        if ($namespace !== null) {
            $this->args->set(array($namespace, $key), $value);
            $this->namespaces->add($namespace);
        }
    }

    function delArg($namespace, $key)
    {
        $namespace = $this->_fixNS($namespace);

        if ($namespace !== null) {
            $this->args->del(array($namespace, $key));
        }
    }
}

?>