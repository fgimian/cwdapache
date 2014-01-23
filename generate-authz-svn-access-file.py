#!/usr/bin/python

# Generate a mod_authz_svn AuthzSVNAccessFile with memberships from a Crowd
#  server

# Provide an existing access file and the groups section will be expanded
#  with the memberships defined in Crowd.

# To update, schedule this:

# if generate-authz-svn-access-file.py --config crowd.properties --check-event-token access-file-expanded.authz; then
#    : # Do nothing; file is current
# else
#   generate-authz-svn-access-file.py --config crowd.properties access-file-template.authz >access-file-expanded.authz.tmp && mv access-file-expanded.authz.tmp access-file-expanded.authz
# fi

from __future__ import print_function

import json
from httplib2 import Http

try:
  from urllib.parse import quote
except ImportError:
  from urllib import quote

from optparse import OptionParser

from sys import stderr, argv, exit

import re

# Ad-hoc parsing of Java-like .properties files
def parseConfigFile(filename):
  cfgLine = re.compile('^([a-zA-Z._]+)\s*=\s*(.*)$')

  cfg = {}

  with open(filename) as f:
   for l in f:
     m = cfgLine.match(l)
     if m:
       cfg[m.group(1)] = m.group(2).replace('\:', ':')

  return cfg

def connectionProperties(cfg):
  if 'crowd.base.url' in cfg:
    baseUrl = cfg['crowd.base.url']
  else:
    baseUrl = re.sub('/services/?$', '', cfg['crowd.server.url'])
  name = cfg['application.name']
  password = cfg['application.password']

  return (baseUrl, name, password)


# Parse command-line arguments
parser = OptionParser(usage = 'usage: %prog [options] [access-file]')
parser.add_option("--config", dest="config",
    help = 'A crowd.properties file, with crowd.base.url, application.name and application.password.'
)
parser.add_option("--check-event-token", dest="check_event_token_filename",
    metavar='FILE',
    help = 'A processed file to check for freshness. An exit code of 0 indicates success.'
)

(options, args) = parser.parse_args()

if len(args) > 1:
  parser.print_help(file = stderr)
  exit(5)

if len(args) == 1:
  accessFile = args[0]
else:
  accessFile = None

(base, appName, appPass) = connectionProperties(parseConfigFile(options.config or 'crowd.properties'))

# Crowd deployment base URL
um = base + '/rest/usermanagement/1'

http = Http(cache = '.cache')

# Crowd application credentials
http.add_credentials(appName, appPass)

CC_FRESH = {'Cache-Control': 'max-age=0', 'Accept': 'application/json'}

def get(url):
  resp, content = http.request(url, headers = CC_FRESH)
  if resp.status != 200:
    print('Failed to fetch %s: %s' % (url, resp), file = stderr)
    exit(10)
  return json.loads(content.decode('utf-8'))
 
def getEventToken():
  url = um + '/event'
  resp, content = http.request(url, headers = CC_FRESH)
  if resp.status == 404:
    return None
  if resp.status != 200:
    print('Failed to fetch %s: %s' % (url, resp), file = stderr)
    exit(10)
  event = json.loads(content.decode('utf-8'))
  if 'incrementalSynchronisationAvailable' in event and event['incrementalSynchronisationAvailable'] and 'newEventToken' in event:
    return event['newEventToken']
  else:
    return None

newEventToken = getEventToken()

# Detect an unchanged userbase. Use a non-zero exit
#  code to indicate that things have changed.
if options.check_event_token_filename is not None:
  if newEventToken is None:
    # We can't get the current token; have to assume things have changed
    exit(5)

  tokenLine = re.compile('^#\s*eventToken:\s*(.*)$')

  oldEventToken = None

  with open(options.check_event_token_filename) as f:
   for l in f:
     m = tokenLine.match(l)
     if m:
       oldEventToken = m.group(1)
       break

  if oldEventToken == newEventToken:
    exit(0)
  else:
    exit(1)


def membersOf(groupName):
  return [user['name'] for user in get(um + '/group/user/nested?groupname=' + quote(groupName))['users']]

print('# Membership from %s' % base)
print('# eventToken: %s' % newEventToken)
print()

# Matches lines of the form:
# groupName =
# with a non-empty group name, no comment at the start,
# and no set of groups already specified
groupLine = re.compile('^\s*([^#][^=\s]*)\s*=\s*$')

shownGroups = False

# If a file was specified, process it and expand the groups section
if accessFile is not None:
  with open(accessFile) as cfg:
    inGroups = False
    for l in [l.rstrip(' \r\n') for l in cfg]:
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

# If there was no groups section, create one with all memberships
if not shownGroups:
  print()
  print('[groups]')

  for groupName in sorted([group['name'] for group in get(um + '/search?entity-type=GROUP&restriction=')['groups']]):
    # And their members
    names = membersOf(groupName)
    print('%s = %s' % (groupName, ', '.join(sorted(names))))
