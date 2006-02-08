<?php

require_once "lib/session.php";

define('sites_form',
       '<div class="form">
<p>These sites have been approved for this session:</p>
<form method="post" action="%s">
<table>
<tbody>
%s
</tbody>
</table>
<input type="submit" value="Remove selected" />
</form>
</div>
');

define('sites_empty_message',
       '<p>
  No sites are remembered for this session. When you authenticate with a site,
  you can choose to add it to this list by choosing <q>Remember this
  decision</q>.
</p>
<p>%s</p>
');

define('sites_row',
       '<tr>
<td><input type="checkbox" name=%s value="%s" id=%s /></td>
<td><label for=%s>%s %s</label></td>
</tr>');

function siteListRow_render($i, $site)
{
    $esc_site = htmlspecialchars($site, ENT_QUOTES);
    if ($trusted) {
        $trust = 'Trust';
    } else {
        $trust = 'Do not trust';
    }
    $id = sprintf('"site%s"', $i);
    return sprintf(sites_row, $id, $esc_site, $id, $id, $trust, $esc_site);
}

function siteList_render($sites)
{
    $rows = '';
    $i = 0;
    foreach ($sites as $site => $trusted) {
        $rows .= siteListRow_render($i, $site);
        $i += 1;
    }
    return $rows;
}

function sites_render($sites)
{
    if ($sites) {
        $rows = siteList_render($sites);
        $form = sprintf(sites_form, buildURL('sites'), $rows);
        $body = $pre . $form;
    } else {
        $body = sprintf(sites_empty_message, link_render(buildURL(''), 'Return home'));
    }
    return page_render($body, getLoggedInUser(), 'Remembered Sites');
}

?>