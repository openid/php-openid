<?php

require_once "lib/session.php";
require_once "lib/render.php";

define('trust_form_pat',
       '<div class="form">
  <p>Do you wish to confirm your identity URL (<code>%s</code>) with <code>%s</code>?</p>
  <form method="post" action="%s">
    <input type="checkbox" name="remember" value="on" id="remember"><label
        for="remember">Remember this decision</label>
    <br />
    <input type="submit" name="trust" value="Confirm" />
    <input type="submit" value="Do not confirm" />
  </form>
</div>
');

function trust_render($info)
{
    $current_user = getLoggedInUser();
    $lnk = link_render($current_user);
    $trust_root = htmlspecialchars($info->trust_root);
    $trust_url = buildURL('trust', true);
    $form = sprintf(trust_form_pat, $lnk, $trust_root, $trust_url);
    return page_render($form, $current_user, 'Trust This Site');
}

?>