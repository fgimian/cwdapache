#!/usr/bin/python3

# Generate a mod_authz_svn AuthzSVNAccessFile with memberships from a Crowd server

# Provide an existing access file and the groups section will be expanded
#  with the memberships defined in Crowd.

import json
from httplib2 import Http
from urllib.parse import quote

from sys import stderr, argv, exit

import re

# Crowd deployment base URL
base = 'http://localhost:8095/crowd'
um = base + '/rest/usermanagement/1'

# Parse command-line arguments
if len(argv) > 2:
  print('Usage: %s [access-file]' % argv[0])
  exit(5)

http = Http(cache = '.cache')

# Crowd application credentials
http.add_credentials('app', 'app')

CC_NOT_REAL_TIME = {'Cache-Control': 'max-age=300', 'Accept': 'application/json'}

def get(url):
  resp, content = http.request(url, headers = CC_NOT_REAL_TIME)
  if resp.status != 200:
    print('Failed to fetch %s: %s' % (url, resp), file = stderr)
    exit(10)
  return json.loads(content.decode('utf-8'))
 
def membersOf(groupName):
  return [user['name'] for user in get(um + '/group/user/nested?groupname=' + quote(groupName))['users']]

print('# Membership from %s' % base)

groupLine = re.compile('([^#][^=]+)\s*=\s*')

shownGroups = False

# If a file was specified, process it and expand the groups section
if len(argv) == 2:
  with open(argv[1]) as cfg:
    inGroups = False
    for l in [l.rstrip('\r\n') for l in cfg]:
      if inGroups:
        m = groupLine.match(l)
        if m:
          groupName = m.group(1)
          print('%s = %s' % (groupName, ', '.join(sorted(membersOf(groupName)))))
        else:
          print(l)
      else:
        print(l)

      if l == '[groups]':
        inGroups = True
        shownGroups = True
      elif l.startswith('['):
        inGroups = False

        print('here', l)

# If there was no groups section, create one with all memberships
if not shownGroups:
  print()
  print('[groups]')

  for groupName in sorted([group['name'] for group in get(um + '/search?entity-type=GROUP&restriction=')['groups']]):
    # And their members
    names = membersOf(groupName)
    print('%s = %s' % (groupName, ', '.join(sorted(names))))
