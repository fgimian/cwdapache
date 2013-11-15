#!/usr/bin/python3

# Generate a mod_authz_svn AuthzSVNAccessFile with memberships from a Crowd server

import json
from httplib2 import Http
from urllib.parse import quote

from sys import stderr

# Crowd deployment base URL
base = 'http://jwalton-desktop:4990/crowd'
um = base + '/rest/usermanagement/1'

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
 
print('# Membership from %s' % base)
print('[groups]')

# Get all groups
for groupName in sorted([group['name'] for group in get(um + '/search?entity-type=GROUP&restriction=')['groups']]):
  # And their members
  names = [user['name'] for user in get(um + '/group/user/nested?groupname=' + quote(groupName))['users']]

  print('%s = %s' % (groupName, ', '.join(sorted(names))))
