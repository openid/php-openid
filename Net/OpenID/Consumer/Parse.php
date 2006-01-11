<?php

/**
 * This module implements a VERY limited parser that finds <link> tags
 * in the head of HTML or XHTML documents and parses out their
 * attributes according to the OpenID spec.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

/**
 * Specify some flags for use with regex matching.
 */
$_Net_OpenID_re_flags = "si";

// Stuff to remove before we start looking for tags
$_Net_OpenID_removed_re = "<!--.*?-->|" .
                          "<!\[CDATA\[.*?\]\]>|" .
                          "<script\b(?!:)[^>]*>.*?</script>";

// Starts with the tag name at a word boundary, where the tag name is
// not a namespace
$_Net_OpenID_tag_expr = "<%s\b(?!:)([^>]*?)" .
                        "(?:/>|>(.*?)" .
                        "(?:</?%s\s*>|\Z))";

function Net_OpenID_tagMatcher($tag_name, $close_tags = null)
{
    global $_Net_OpenID_tag_expr, $_Net_OpenID_re_flags;

    if ($close_tags) {
        $options = implode("|", array_merge(array($tag_name), $close_tags));
        $closer = sprintf("(?:%s)", $options);
    } else {
        $closer = $tag_name;
    }

    $expr = sprintf($_Net_OpenID_tag_expr, $tag_name, $closer);
    return sprintf("/%s/%s", $expr, $_Net_OpenID_re_flags);
}

function Net_OpenID_html_find()
{
    return Net_OpenID_tagMatcher('html');
}

function Net_OpenID_head_find()
{
    return Net_OpenID_tagMatcher('head');
}

$_Net_OpenID_link_find = sprintf("/<link\b(?!:)/%s", $_Net_OpenID_re_flags);

$_Net_OpenID_attr_find = "(\w+)=(?:[\"'](.*?)\\1|(?:[^\s<>/]|/(?!>))+)|[<>]/";
$_Net_OpenID_attr_find = sprintf("/%s/%s", $_Net_OpenID_attr_find,
                                 $_Net_OpenID_re_flags);

$_Net_OpenID_entity_replacements = array(
                                         'amp' => '&',
                                         'lt' => '<',
                                         'gt' => '>',
                                         'quot' => '"'
                                         );

function Net_OpenID_entity_replace()
{
}

?>