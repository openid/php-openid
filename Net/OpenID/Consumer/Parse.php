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

/**
 * Stuff to remove before we start looking for tags
 */
$_Net_OpenID_removed_re = "<!--.*?-->|" .
                          "<!\[CDATA\[.*?\]\]>|" .
                          "<script\b(?!:)[^>]*>.*?<\/script>";

/**
 * Starts with the tag name at a word boundary, where the tag name is
 * not a namespace
 */
$_Net_OpenID_tag_expr = "<%s\b(?!:)([^>]*?)" .
                        "(?:\/>|>(.*?)" .
                        "(?:<\/?%s\s*>|\Z))";

/**
 * Returns a regular expression that will match a given tag in an SGML
 * string.
 */
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
    return Net_OpenID_tagMatcher('head', array('body'));
}

$_Net_OpenID_attr_find = '\b(\w+)=("[^"]*"|\'[^\']*\'|[^\'"\s\/<>]+)';

$_Net_OpenID_link_find = sprintf("/<link\b(?!:)([^>]*)(?!<)>/%s",
                                 $_Net_OpenID_re_flags);

$_Net_OpenID_entity_replacements = array(
                                         'amp' => '&',
                                         'lt' => '<',
                                         'gt' => '>',
                                         'quot' => '"'
                                         );

$_Net_OpenID_attr_find = sprintf("/%s/%s",
                                 $_Net_OpenID_attr_find,
                                 $_Net_OpenID_re_flags);

$_Net_OpenID_removed_re = sprintf("/%s/%s",
                                  $_Net_OpenID_removed_re,
                                  $_Net_OpenID_re_flags);

$_Net_OpenID_ent_replace =
     sprintf("&(%s);", implode("|",
                               $_Net_OpenID_entity_replacements));

function Net_OpenID_replace_entities($str)
{
    global $_Net_OpenID_entity_replacements;
    foreach ($_Net_OpenID_entity_replacements as $old => $new) {
        $str = preg_replace(sprintf("/&%s;/", $old), $new, $str);
    }
    return $str;
}

function Net_OpenID_remove_quotes($str)
{
    $matches = array();
    $double = '/^"(.*)"$/';
    $single = "/^\'(.*)\'$/";

    if (preg_match($double, $str, $matches)) {
        return $matches[1];
    } else if (preg_match($single, $str, $matches)) {
        return $matches[1];
    } else {
        return $str;
    }
}

function Net_OpenID_parseLinkAttrs($html)
{

    global $_Net_OpenID_removed_re,
        $_Net_OpenID_link_find,
        $_Net_OpenID_attr_find;

    $stripped = preg_replace($_Net_OpenID_removed_re,
                             "",
                             $html);

    // Try to find the <HTML> tag.
    $html_re = Net_OpenID_html_find();
    $html_matches = array();
    if (!preg_match($html_re, $stripped, $html_matches)) {
        return array();
    }

    // Try to find the <HEAD> tag.
    $head_re = Net_OpenID_head_find();
    $head_matches = array();
    if (!preg_match($head_re, $html_matches[0], $head_matches)) {
        return array();
    }

    $link_data = array();
    $link_matches = array();

    if (!preg_match_all($_Net_OpenID_link_find, $head_matches[0],
                        $link_matches)) {
        return array();
    }

    foreach ($link_matches[0] as $link) {
        $attr_matches = array();
        preg_match_all($_Net_OpenID_attr_find, $link, $attr_matches);
        $link_attrs = array();
        foreach ($attr_matches[0] as $index => $full_match) {
            $name = $attr_matches[1][$index];
            $value = Net_OpenID_replace_entities(
                       Net_OpenID_remove_quotes(
                         $attr_matches[2][$index]));

            $link_attrs[$name] = $value;
        }
        $link_data[] = $link_attrs;
    }

    return $link_data;
}

?>