<?php

/**
 * Yadis service manager to be used during yadis-driven authentication
 * attempts.
 *
 * @package Yadis
 */

/**
 * The base session class used by the Services_Yadis_Manager.  This
 * class wraps the default PHP session machinery and should be
 * subclassed if your application doesn't use PHP sessioning.
 *
 * @package Yadis
 */
class Services_Yadis_PHPSession {
    /**
     * Set a session key/value pair.
     *
     * @param string $name The name of the session key to add.
     * @param string $value The value to add to the session.
     */
    function set($name, $value)
    {
        $_SESSION[$name] = $value;
    }

    /**
     * Get a key's value from the session.
     *
     * @param string $name The name of the key to retrieve.
     * @param string $default The optional value to return if the key
     * is not found in the session.
     * @return string $result The key's value in the session or
     * $default if it isn't found.
     */
    function get($name, $default=null)
    {
        if (array_key_exists($name, $_SESSION)) {
            return $_SESSION[$name];
        } else {
            return $default;
        }
    }

    /**
     * Remove a key/value pair from the session.
     *
     * @param string $name The name of the key to remove.
     */
    function del($name)
    {
        unset($_SESSION[$name]);
    }
}

/**
 * The Yadis service manager which stores state in a session and
 * iterates over <Service> elements in a Yadis XRDS document and lets
 * a caller attempt to use each one.  This is used by the Yadis
 * library internally.
 *
 * @package Yadis
 */
class Services_Yadis_Manager {

    /**
     * Intialize a new yadis service manager.
     *
     * @access private
     */
    function Services_Yadis_Manager($starting_url, $yadis_url,
                                    $services, $session_key)
    {
        // The URL that was used to initiate the Yadis protocol
        $this->starting_url = $starting_url;

        // The URL after following redirects (the identifier)
        $this->yadis_url = $yadis_url;

        // List of service elements
        $this->services = $services;

        $this->session_key = $session_key;

        // Reference to the current service object
        $this->_current = null;

        // Stale flag for cleanup if PHP lib has trouble.
        $this->stale = false;
    }

    /**
     * @access private
     */
    function length()
    {
        // How many untried services remain?
        return count($this->services);
    }

    /**
     * Return the next service
     *
     * $this->current() will continue to return that service until the
     * next call to this method.
     */
    function nextService()
    {

        if ($this->services) {
            $this->_current = array_shift($this->services);
        } else {
            $this->_current = null;
        }

        return $this->_current;
    }

    /**
     * @access private
     */
    function current()
    {
        // Return the current service.
        // Returns None if there are no services left.
        return $this->_current;
    }

    /**
     * @access private
     */
    function forURL($url)
    {
        return in_array($url, array($this->starting_url, $this->yadis_url));
    }

    /**
     * @access private
     */
    function started()
    {
        // Has the first service been returned?
        return $this->_current !== null;
    }
}

/**
 * State management for discovery.
 *
 * High-level usage pattern is to call .getNextService(discover) in
 * order to find the next available service for this user for this
 * session. Once a request completes, call .finish() to clean up the
 * session state.
 *
 * @package Yadis
 */
class Services_Yadis_Discovery {

    /**
     * @access private
     */
    var $DEFAULT_SUFFIX = 'auth';

    /**
     * @access private
     */
    var $PREFIX = '_yadis_services_';

    /**
     * Initialize a discovery object.
     *
     * @param Services_Yadis_PHPSession $session An object which
     * implements the Services_Yadis_PHPSession API.
     * @param string $url The URL on which to attempt discovery.
     * @param string $session_key_suffix The optional session key
     * suffix override.
     */
    function Services_Yadis_Discovery(&$session, $url,
                                      $session_key_suffix = null)
    {
        /// Initialize a discovery object
        $this->session =& $session;
        $this->url = $url;
        if ($session_key_suffix === null) {
            $session_key_suffix = $this->DEFAULT_SUFFIX;
        }

        $this->session_key_suffix = $session_key_suffix;
        $this->session_key = $this->PREFIX . $this->session_key_suffix;
    }

    /**
     * Return the next authentication service for the pair of
     * user_input and session. This function handles fallback.
     */
    function getNextService($discover_cb, &$fetcher)
    {
        $manager = $this->getManager();
        if ((!$manager) ||
            $manager->stale) {
            $this->destroyManager();
            $http_response = array();

            $services = call_user_func($discover_cb, $this->url,
                                       $fetcher);

            $manager = $this->createManager($services, $this->url);
        }

        if ($manager) {
            $service = $manager->nextService();
            $this->session->set($this->session_key, serialize($manager));
        } else {
            $service = null;
        }

        return $service;
    }

    /**
     * Clean up Yadis-related services in the session and return the
     * most-recently-attempted service from the manager, if one
     * exists.
     */
    function cleanup()
    {
        $manager = $this->getManager();
        if ($manager) {
            $service = $manager->current();
            $this->destroyManager();
        } else {
            $service = null;
        }

        return $service;
    }

    /**
     * @access private
     */
    function getSessionKey()
    {
        // Get the session key for this starting URL and suffix
        return $this->PREFIX . $this->session_key_suffix;
    }

    /**
     * @access private
     */
    function getManager()
    {
        // Extract the YadisServiceManager for this object's URL and
        // suffix from the session.

        $manager_str = $this->session->get($this->getSessionKey());
        $manager = null;

        if ($manager_str !== null) {
            $manager = unserialize($manager_str);
        }

        if ($manager && $manager->forURL($this->url)) {
            return $manager;
        } else {
            return null;
        }
    }

    /**
     * @access private
     */
    function &createManager($services, $yadis_url = null)
    {
        $key = $this->getSessionKey();
        if ($this->getManager()) {
            return $this->getManager();
        }

        if (!$services) {
            return null;
        }

        $manager = new Services_Yadis_Manager($this->url, $yadis_url,
                                              $services, $key);
        $this->session->set($this->session_key, serialize($manager));
        return $manager;
    }

    /**
     * @access private
     */
    function destroyManager()
    {
        if ($this->getManager() !== null) {
            $key = $this->getSessionKey();
            $this->session->del($key);
        }
    }
}

?>