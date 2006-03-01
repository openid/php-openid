#!/usr/bin/python

import os
import os.path

def makeLeadXML(leads):
    lead_template = """
<lead>
  <name>%(name)s</name>
  <user>%(user)s</user>
  <email>%(email)s</email>
  <active>%(active)s</active>
</lead>
    """

    return "".join([lead_template % l for l in leads])

INDENT_STRING = "  "

def buildContentsXMLFordir(dir_or_file, roles, depth=0):
    """
    Returns a list of strings, each of which is either a <file> XML
    element for the given file or a <dir> element which contains other
    <file> elements.
    """

    try:
        entries = os.listdir(dir_or_file)
        lines = ['%s<dir name="%s">' % (INDENT_STRING * depth, os.path.basename(dir_or_file))]

        for entry in entries:
            lines += buildContentsXMLFordir(dir_or_file + os.sep + entry, roles, depth + 1)

        lines.append('%s</dir>' % (INDENT_STRING * depth))

        return lines
    except OSError:
        try:
            extension = dir_or_file.split(".")[-1]
        except:
            return []

        if extension in roles: # Ends in an extension we care about
            return ['%s<file name="%s" role="%s" />' %
                    (INDENT_STRING * depth, os.path.basename(dir_or_file), roles[extension])]
        else:
            return []

def buildContentsXML(roles, *dirs):
    lines = ['<dir name="/">']

    for directory in dirs:
        lines.append("\n".join(buildContentsXMLFordir(directory, roles, 1)))

    lines.append('</dir>')

    return "\n".join(lines)

if __name__ == "__main__":
    import sys
    import time

    try:
        import xmlconfig
    except:
        print "Could not import XML configuration module xmlconfig"
        sys.exit(1)

    try:
        template_f = open(xmlconfig.template, 'r')
    except Exception, e:
        print "Could not open template file:", str(e)
        sys.exit(1)

    # Expect sys.argv[1] to be the version number to include in the
    # package.xml file.
    try:
        version = sys.argv[1]
    except:
        print "Usage: %s <package version>" % (sys.argv[0])
        sys.exit(2)

    data = xmlconfig.__dict__.copy()

    data['contents'] = buildContentsXML({'php': 'php'}, *xmlconfig.contents_dirs)
    data['leads'] = makeLeadXML(xmlconfig.leads)
    data['date'] = time.strftime("%Y-%m-%d")
    data['version'] = version

    template_data = template_f.read()
    print template_data % data
