<?php

$path_extra = dirname(dirname(__FILE__));
$path = ini_get('include_path');
$path = $path_extra . ':' . $path;
ini_set('include_path', $path);

class PlainText {
    function start($title)
    {
        return '';
    }

    function link($href, $text=null)
    {
        if ($text) {
            return $text . ' <' . $href . '>';
        } else {
            return $href;
        }
    }

    function contentType()
    {
        return 'text/plain';
    }

    function p($text)
    {
        return wordwrap($text) . "\n\n";
    }

    function pre($text)
    {
        $out = '';
        $lines = array_map('trim', explode("\n", $text));
        foreach ($lines as $line) {
            $out .= '    ' . $line . "\n";
        }
    }

    function ol($items)
    {
        $out = '';
        $c = 1;
        foreach ($items as $item) {
            $item = wordwrap($item, 72);
            $lines = array_map('trim', explode("\n", $item));
            $out .= $c . '. ' . $lines[0] . "\n";
            unset($lines[0]);
            foreach ($lines as $line) {
                $out .= '   ' . $line . "\n";
            }
            $out .= "\n";
            $c += 1;
        }
        return $out;
    }

    function h2($text)
    {
        return $text . "\n" . str_repeat('-', strlen($text)) . "\n\n";
    }

    function h1($text)
    {
        return $text . "\n" . str_repeat('=', strlen($text)) . "\n\n";
    }

    function end()
    {
        return '';
    }
}

class HTML {
    function start($title)
    {
        return '<html><head><title>' . $title . '</title></head><body>' . "\n";
    }

    function contentType()
    {
        return 'text/html';
    }

    function p($text)
    {
        return '<p>' . wordwrap($text) . "</p>\n";
    }

    function pre($text)
    {
        return '<pre>' . $text . "</pre>\n";
    }

    function ol($items)
    {
        $out = '<ol>';
        foreach ($items as $item) {
            $out .= '<li>' . wordwrap($item) . "</li>\n";
        }
        $out .= "</ol>\n";
        return $out;
    }

    function h($text, $n)
    {
        return "<h$n>$text</h$n>\n";
    }

    function h2($text)
    {
        return $this->h($text, 2);
    }

    function h1($text)
    {
        return $this->h($text, 1);
    }

    function link($href, $text=null)
    {
        return '<a href="' . $href . '">' . ($text ? $text : $href) . '</a>';
    }

    function end()
    {
        return "</body>\n</html>\n";
    }
}

$r = new HTML();

function detect_math($r, &$out)
{
    global $_Auth_OpenID_math_extensions;
    $out .= $r->h2('Math support');
    $ext = Auth_OpenID_detectMathLibrary($_Auth_OpenID_math_extensions);
    if (!isset($ext['extension']) || !isset($ext['class'])) {
        $out .= $r->p(
            'Your PHP installation does not include big integer math ' .
            'support. This support is required if you wish to run a ' .
            'secure OpenID server without using SSL.');
        $out .= $r->p('To use this library, you have a few options:');

        $gmp_lnk = $r->link('http://www.php.net/manual/en/ref.gmp.php', 'GMP');
        $bc_lnk = $r->link('http://www.php.net/manual/en/ref.bc.php', 'bcmath');
        $out .= $r->ol(array(
            'Install the ' . $gmp_lnk . ' PHP extension',
            'Install the ' . $bc_lnk . ' PHP extension',
            'If your site is low-security, define ' .
            'Auth_OpenID_NO_MATH_SUPPORT. The library will function, but ' .
            'the security of your OpenID server will depend on the ' .
            'security of the network links involved. If you are only ' .
            'using consumer support, you should still be able to operate ' .
            'securely when the users are communicating with a ' .
            'well-implemented server.'));
        return false;
    } else {
        switch ($ext['extension']) {
        case 'bcmath':
            $out .= $r->p('Your PHP installation has bcmath support. This is ' .
                  'adequate for small-scale use, but can be CPU-intensive. ' .
                  'You may want to look into installing the GMP extension.');
            $lnk = $r->link('http://www.php.net/manual/en/ref.gmp.php');
            $out .= $r->p('See ' . $lnk .' for more information about the GMP ' .
                  'extension.');
            break;
        case 'gmp':
            $out .= $r->p('Your PHP installation has gmp support. Good.');
            break;
        default:
            $class = $ext['class'];
            $lib = new $class();
            $one = $lib->init(1);
            $two = $lib->add($one, $one);
            $t = $lib->toString($two);
            $out .= $r->p('Uh-oh. I do not know about the ' . $ext['extension'] .
              ' extension!');
            if ($t != '2') {
                $out .= $r->p('It looks like it is broken. 1 + 1 = ' .
                  var_export($t, false));
                return false;
            } else {
                $out .= $r->p('But it seems to be able to add one and one.');
            }
        }
    }
}

header('Content-Type: ' . $r->contentType() . '; charset=us-ascii');

$status = array();

$title = 'PHP OpenID Library Check';
$out = $r->start($title) .
    $r->h1($title) .
    $r->p('This script checks your PHP installation to determine if you ' .
          'are set up to use the JanRain PHP OpenID library.');

if (!@include('Auth/OpenID/BigMath.php')) {
    $path = ini_get('include_path');
    $out .= $r->p(
        'Cannot find the OpenID library. It must be in your PHP include ' .
        'path. Your PHP include path is currently:');
    $out .= $r->pre($path);
} else {
    $status['math'] = detect_math($r, $out);
}

$out .= $r->end();
print $out;
?>