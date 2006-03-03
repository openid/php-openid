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

def buildContentsXMLFordir(dir_or_file, roles, depth=0, dir_role=None, all_files=False):
    """
    Returns a list of strings, each of which is either a <file> XML
    element for the given file or a <dir> element which contains other
    <file> elements.
    """

    try:
        entries = os.listdir(dir_or_file)
        dir_role_s = ''
        if dir_role:
            dir_role_s = ' role="%s"' % (dir_role)
        lines = ['%s<dir name="%s"%s>' % (INDENT_STRING * depth, os.path.basename(dir_or_file),
                                          dir_role_s)]

        for entry in entries:
            lines += buildContentsXMLFordir(dir_or_file + os.sep + entry, roles, depth + 1, dir_role, all_files)

        lines.append('%s</dir>' % (INDENT_STRING * depth))

        return lines
    except OSError:
        try:
            extension = dir_or_file.split(".")[-1]
        except:
            if not all_files:
                return []

        if extension in roles: # Ends in an extension we care about
            return ['%s<file name="%s" role="%s" />' %
                    (INDENT_STRING * depth, os.path.basename(dir_or_file), roles[extension])]
        elif all_files:
            return ['%s<file name="%s" />' %
                    (INDENT_STRING * depth, os.path.basename(dir_or_file))]
        else:
            print "FOOB for %s %s" % (all_files, dir_or_file)
            return []

def buildContentsXML(roles, *dirs):
    lines = []

    for directory in dirs:
        lines.append("\n".join(buildContentsXMLFordir(directory, roles, 1)))

    return "\n".join(lines)

def buildDocsXML(*dirs):
    lines = []

    for directory in dirs:
        lines.append("\n".join(buildContentsXMLFordir(directory, {}, 1, 'doc', all_files=True)))

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

    contents = '<dir name="/">\n' + buildContentsXML({'php': 'php'}, *xmlconfig.contents_dirs) + \
               "\n" + buildDocsXML(*xmlconfig.docs_dirs) + '\n  </dir>'

    data['contents'] = contents
    data['leads'] = makeLeadXML(xmlconfig.leads)
    data['date'] = time.strftime("%Y-%m-%d")
    data['version'] = version
    data['uri'] = "%s%s-%s.tgz" % (data['package_base_uri'], data['package_name'], version)

    template_data = template_f.read()
    print template_data % data
