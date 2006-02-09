<?php

require_once "lib/session.php";

define('sites_form',
       '<p>These decisions have been remembered for this session. All decisions
will be forgotten when the session ends.</p>
<div class="form">
<form method="post" action="%s">
<table>
<tbody>
%s
</tbody>
</table>
<input type="submit" name="remove" value="Remove Selected" />
<input type="submit" name="refresh" value="Refresh List" />
<input type="submit" name="forget" value="Forget All" />
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
<td><label for=%s><code>%s</code></label></td>
</tr>');

function siteListRow_render($i, $site)
{
    $esc_site = htmlspecialchars($site, ENT_QUOTES);
    $id = sprintf('"site%s"', $i);
    return sprintf(sites_row, $id, $esc_site, $id, $id, $esc_site);
}

function siteList_render($sites)
{
    $trusted_sites = array();
    $untrusted_sites = array();
    foreach ($sites as $site => $trusted) {
        if ($trusted) {
            $trusted_sites[] = $site;
        } else {
            $untrusted_sites[] = $site;
        }
    }
    $rows = '';
    $i = 0;
    foreach (array('Trusted Sites' => $trusted_sites,
                   'Untrusted Sites' => $untrusted_sites) as
             $name => $sites) {
        if ($sites) {
            $rows .= '<tr><th colspan="2">'. $name . '</th></tr>';
            foreach ($sites as $site) {
                $rows .= siteListRow_render($i, $site);
                $i += 1;
            }
        }
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