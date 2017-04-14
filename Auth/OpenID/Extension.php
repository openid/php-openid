<?php

/**
 * An interface for OpenID extensions.
 *
 * @package OpenID
 */

/**
 * Require the Message implementation.
 */
require_once 'Auth/OpenID/Message.php';

/**
 * A base class for accessing extension request and response data for
 * the OpenID 2 protocol.
 *
 * @package OpenID
 */
class Auth_OpenID_Extension {
    /**
     * ns_uri: The namespace to which to add the arguments for this
     * extension
     */
    public $ns_uri = null;
    public $ns_alias = null;

    /**
     * Get the string arguments that should be added to an OpenID
     * message for this extension.
     *
     * @param Auth_OpenID_Request|null $request
     * @return null
     */
    function getExtensionArgs($request = null)
    {
        return null;
    }

    /**
     * Add the arguments from this extension to the provided message.
     *
     * Returns the message with the extension arguments added.
     *
     * @param Auth_OpenID_Message $message
     * @param Auth_OpenID_Request $request
     * @return null
     */
    function toMessage($message, $request = null)
    {
        $implicit = $message->isOpenID1();
        $added = $message->namespaces->addAlias($this->ns_uri,
                                                $this->ns_alias,
                                                $implicit);

        if ($added === null) {
            if ($message->namespaces->getAlias($this->ns_uri) !=
                $this->ns_alias) {
                return null;
            }
        }

        if ($request !== null) {
            $message->updateArgs($this->ns_uri,
                                 $this->getExtensionArgs($request));
        } else {
            $message->updateArgs($this->ns_uri,
                                 $this->getExtensionArgs());
        }
        return $message;
    }
}

