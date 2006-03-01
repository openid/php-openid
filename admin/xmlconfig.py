
"""
This is the package.xml data needed for the PHP OpenID PEAR
package.xml file.  Use the 'packagexml.py' program to generate a
package.xml file for a release of this library.
"""

leads = [
    {'name': 'Jonathan Daugherty',
     'user': 'cygnus',
     'email': 'cygnus@janrain.com',
     'active': 'yes'},
    {'name': 'Josh Hoyt',
     'user': 'jhoyt',
     'email': 'josh@janrain.com',
     'active': 'yes'}
    ]

template = 'package.xml'

package_name = 'OpenID'
package_description = 'An implementation of the OpenID single sign-on authentication protocol.'
package_summary = 'PHP OpenID'
license_name = 'LGPL'
license_uri = 'http://www.gnu.org/copyleft/lesser.txt'
contents_dirs = ['../Auth']
release_stability = 'stable'
