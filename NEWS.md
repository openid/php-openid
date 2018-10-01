What's New in PHP OpenID 2.0
============================

This library implements both the OpenID 1 and OpenID 2 protocols.  The
API changes in this version of the library are minimal and mostly
backwards-compatible with current RP and Server implementations.  If
you're already using this library for OpenID 1, only a few small
changes (see Summary below) will be needed once you upgrade.

The big news here is compatibility with version 2.0 of the OpenID
protocol.  Highlights include:

 * Simple Registration support in a new module `Auth/OpenID/SReg.php`.
   (Those previously using
   `Auth_OpenID_SuccessResponse::extensionResponse()` are advised to
   look here and at the example consumer and server for detailed usage
   information.)
 * OpenID provider-driven identifier selection.
 * "Negotiators" allow you to define which association types to use.
 * Improved examples/detect.php script (bugs fixed)
 * Improved layout of example consumer (see examples/consumer)
 * An improved HTML parser implementation
 * Library is now immune to being included inside functions and
   methods
 * Fixes to avoid multibyte overloading problems

If you've written your own custom store or code that interacts
directly with it, you'll need to review the change notes for
`Auth_OpenID_Interface` in `Auth/OpenID/Interface.php`.


Upgrading from earlier versions of this library
-----------------------------------------------

One of the additions to the OpenID protocol was a specified nonce
format for one-way nonces.  As a result, the nonce table in the
SQL-driven stores has changed.  You'll need to run the Python script
`contrib/upgrade-store-1.1-to-2.0` to upgrade your store, or you'll
encounter errors about the wrong number of columns in the oid_nonces
table.  To run the script, you'll need a python module supporting your
database type: pysqlite2, psycopg, or MySQLdb.

If you cannot run the Python script, you can re-create your store by
dropping the tables in the store and calling `createTables()` on the
store object.

Consumers should now pass the consumer `return_to` URL to
`Auth_OpenID_Consumer::complete()` to defend against return_to URL
tampering.  This has REPLACED the old parameter, `$query`. `$query` is
now a second optional parameter.  It is **STRONGLY RECOMMENDED** that you
never override $query, since the OpenID library uses its own logic to
sidestep PHP's broken request-processing code.


Summary of API Changes
----------------------

 - `Auth_OpenID::fixArgs` is now no longer necessary, and
`Auth_OpenID_Consumer::complete` and `Auth_OpenID_Server::decodeRequest`
no longer take query argument arrays.  *You should no longer pass any
parameters to these methods.*

 - `Auth_OpenID_SuccessResponse::extensionResponse()` is no longer the
preferred way to extract extension response parameters from the OpenID
response.  Instead, see the `Auth/OpenID/SReg.php` module and the
example consumer and server for detailed usage information on
constructing Simple Registration requests and inspecting responses.
`extensionResponse()` is still valid, but now takes a second parameter
(bool) indicating whether extension args should be signed.

 - The `Auth_OpenID_Server`'s response `answer()` method now takes
additional parameters to support provider-driven identifier selection.
See the example server and the documentation for
`Auth_OpenID_CheckIDRequest::answer`.

- `Auth_OpenID_Consumer::complete()` now takes two args:

   - `$return_to`, a required string that is the return URL passed to
     `Auth_OpenID_AuthRequest::redirectURL()`

   - `$query`, an optional array (or null if absent) denoting the query
     parameters of the OpenID response.  If null, the response data
     will be extracted from the PHP request environment.  Library
     users **SHOULD NOT** ever pass anything for `$query` unless they're
     testing the library.
