#! /usr/bin/env python

import BaseHTTPServer
import cookielib
import errno
import os
import urllib2
import subprocess
import threading
import time

httpd = None
base_url = 'http://httpd.atlassian.test:8080'

def assert_exits(process):
    timeout = 5
    while process.poll() is None:
        assert timeout >  0
        timeout -= 1
        time.sleep(1)

def http_get(username, password, relative_url = '/', cookie_jar = None, forwarded_for = None):
    url = base_url + relative_url
    if username is None:
        auth_handler = None
    else:
        auth_handler = urllib2.HTTPBasicAuthHandler()
        auth_handler.add_password('test', url, username, password)
    if cookie_jar is None:
        opener = urllib2.build_opener(auth_handler)
    else:
        if auth_handler is None:
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie_jar))
        else:
            opener = urllib2.build_opener(auth_handler, urllib2.HTTPCookieProcessor(cookie_jar))
    if forwarded_for is None:
        opener.open(url)
    else:
        opener.open(urllib2.Request(url, headers = {'X-Forwarded-For': forwarded_for}))

def start_httpd(config_file = 'conf/httpd.conf'):
    global httpd
    httpd = subprocess.Popen([apache_bin_dir + '/httpd', '-X', '-d', 'httpd', '-e', 'debug', '-f', config_file], stdout = subprocess.PIPE)
    
def terminate_httpd():
    httpd.kill()
    httpd.wait()

def wait_for_httpd_startup(expect_authentication = True):
    # Test that authentication is required.  Repeat until the server starts.
    timeout = 5
    while True:
        try:
            urllib2.urlopen(base_url + '/')
            assert not expect_authentication, 'Authentication was not requested.'
            break
        except urllib2.HTTPError as exception:
            assert expect_authentication and exception.code == 401, exception.code
            break
        except urllib2.URLError as exception:
            assert timeout > 0
            timeout -= 1
            time.sleep(1)
            continue

def start_mock_crowd(request_handler):
    mock_crowd = BaseHTTPServer.HTTPServer(('', 8096), request_handler)
    threading.Thread(target = mock_crowd.serve_forever).start()
    return mock_crowd

def svn_command(user, password, command):
    command_line = ['svn', '--non-interactive', '--no-auth-cache']
    if not user is None:
        command_line += ['--username', user, '--password', password]
    command_line += command
    return subprocess.call(command_line) == 0

def svn_can_read(user = None, password = None, path=''):
    return svn_command(user, password, ['ls', base_url + path + '/'])
    
def svn_can_write(user = None, password = None, path = ''):
    if svn_command(user, password, ['mkdir', '-m', '', base_url + path + '/newdir']):
        svn_command(user, password, ['rm', '-m', '', base_url + path + '/newdir'])
        return True
    return False


apache_bin_dir = os.environ['APACHE_BIN_DIR']
print apache_bin_dir

# Install mod_authnz_crowd module.
subprocess.check_call([apache_bin_dir + '/apxs', '-S', 'LIBEXECDIR=' + os.getcwd() + '/httpd/modules', '-i', 'mod_authnz_crowd.la', 'svn/mod_authz_svn_crowd.la'])

# Start httpd with missing configuration parameter.
start_httpd('conf/httpd_missing.conf')
assert_exits(httpd)

# Start httpd with duplicated configuration parameter.
start_httpd('conf/httpd_duplicate.conf')
assert_exits(httpd)

# Start httpd with valid configuration.
start_httpd()

try:

    wait_for_httpd_startup()

    # Test that authentication succeeds with valid credentials.
    http_get('httpd_test', 'httpd_password')

    # Test that authentication succeeds with valid credentials containing XML entity.
    http_get('httpd_&gt;', 'httpd_&gt;')

    # Test that authentication succeeds with valid credentials containing <.
    http_get('httpd_<', 'httpd_<')

    # Test that authentication succeeds with valid credentials containing reserved URL characters.
    http_get('httpd_;?@=&', 'httpd_;?@=&')

    # Test that authentication succeeds with valid credentials containing CDATA terminators.
    http_get('httpd_<![CDATA[]]>', 'httpd_<![CDATA[]]>')

    # Test that authentication succeeds with valid credentials with UTF-8 encoding.
    http_get('httpd_\xc3\xa5\xc3\xa9\xc3\xae\xc3\xb8\xc3\xbc', 'httpd_\xc3\xa5\xc3\xa9\xc3\xae\xc3\xb8\xc3\xbc')

    # Test that authentication succeeds with valid credentials with ISO-8859-1 encoding.
    http_get('httpd_\xe5\xe9\xee\xf8\xfc', 'httpd_\xe5\xe9\xee\xf8\xfc')

    # Test that authentication fails with incorrect password.
    try:
        http_get('httpd_test', 'incorrect')
        assert False, 'Authentication succeeded with incorrect password.'
    except urllib2.URLError as exception:
        assert exception.code == 401, exception.code

    # Test that authentication fails with unknown username.
    try:
        http_get('httpd_iamnobody', 'incorrect')
        assert False, 'Authentication succeeded with unknown user.'
    except urllib2.URLError as exception:
        assert exception.code == 401, exception.code

    # Test that authorisation is granted with specific user requirement.
    http_get('httpd_superuser', 'httpd_superuser', relative_url = '/superuser_only/')

    # Test that authorisation is denied due to specific user requirement.
    try:
        http_get('httpd_test', 'httpd_password', relative_url = '/superuser_only/')
        assert False, 'Authorisation granted to incorrect user.'
    except urllib2.URLError as exception:
        assert exception.code == 401, exception.code

    # Test that authorisation is granted with specific group requirement.
    http_get('httpd_supergroupmember', 'httpd_supergroupmember', relative_url = '/supergroup_only/')

    # Test that authorisation is granted with specific group requirement, based on a nested group.
    http_get('httpd_nestedgroupmember', 'httpd_nestedgroupmember', relative_url = '/supergroup_only/')

    # Test that authorisation is denied due to specific group requirement.
    try:
        http_get('httpd_test', 'httpd_password', relative_url = '/supergroup_only/')
        assert False, 'Authorisation granted to non-member of group.'
    except urllib2.URLError as exception:
        assert exception.code == 401, exception.code

    # Test SSO
    cookie_jar = cookielib.CookieJar()
    http_get('httpd_test', 'httpd_password', cookie_jar = cookie_jar)
    http_get(None, None, cookie_jar = cookie_jar)

    # Test SSO via proxy
    cookie_jar = cookielib.CookieJar()
    http_get('httpd_test', 'httpd_password', cookie_jar = cookie_jar, forwarded_for = '10.0.1.1')
    http_get(None, None, cookie_jar = cookie_jar, forwarded_for = '10.0.1.1')
    try:
        http_get(None, None, cookie_jar = cookie_jar, forwarded_for = '10.0.1.2')
        assert False, 'Authentication succeeded when forwarded for different client.'
    except urllib2.URLError as exception:
        assert exception.code == 401, exception.code

    # Test behaviour when Crowd is not running.
    terminate_httpd()
    httpd = subprocess.Popen([apache_bin_dir + '/httpd', '-X', '-d', 'httpd', '-e', 'debug', '-f', 'conf/httpd_mock_crowd.conf'])
    wait_for_httpd_startup()
    try:
        http_get('httpd_test', 'httpd_password')
        assert False, 'Authentication succeeded with Crowd not running.'
    except urllib2.URLError as exception:
        assert exception.code == 500, exception.code

    # Test behaviour when response from Crowd is not valid HTTP.
    class MockCrowd_invalidHTTP(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_POST(self):
            self.wfile.write('This is not valid HTTP\r\n\r\n')
            self.wfile.close()
    mock_crowd = start_mock_crowd(MockCrowd_invalidHTTP)
    try:
        http_get('httpd_test', 'httpd_password')
        assert False, 'Authentication succeeded with non-HTTP response.'
    except urllib2.URLError as exception:
        assert exception.code == 500, exception.code
    finally:
        mock_crowd.shutdown()
        mock_crowd.socket.close()

    # Test behaviour when response from Crowd has a body that is not valid XML.
    class MockCrowd_invalidXML(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_POST(self):
            self.wfile.write('HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 18\r\n\r\nThis is not XML.\r\n')
            self.wfile.close()
    mock_crowd = start_mock_crowd(MockCrowd_invalidXML)
    try:
        http_get('httpd_test', 'httpd_password')
        assert False, 'Authentication succeeded with non-XML response.'
    except urllib2.URLError as exception:
        assert exception.code == 500, exception.code
    finally:
        mock_crowd.shutdown()
        mock_crowd.socket.close()

    # Test behaviour when response from Crowd is not received within timeout.
    class MockCrowd_timeout(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_POST(self):
            time.sleep(4)
            self.wfile.write('HTTP/1.0 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 9\r\n\r\n<user/>\r\n')
            self.wfile.close()
    mock_crowd = start_mock_crowd(MockCrowd_timeout)
    try:
        http_get('httpd_test', 'httpd_password')
        assert False, 'Authentication succeeded after timeout expired.'
    except urllib2.URLError as exception:
        assert exception.code == 500, exception.code
    finally:
        mock_crowd.shutdown()
        mock_crowd.socket.close()

finally:
    terminate_httpd()

# Start httpd with valid Subversion configuration.
start_httpd('conf/httpd_svn.conf')

try:

    wait_for_httpd_startup(expect_authentication = False)

    # Test that anonymous user can read but not write root.
    assert svn_can_read()
    assert not svn_can_write()

    # Test that permitted users can read and write root, when the correct password is supplied.
    assert svn_can_read('svn_superuser', 'svn_superuser')
    assert svn_can_write('svn_superuser', 'svn_superuser')
    assert not svn_can_write('svn_superuser', 'wrong')
    assert svn_can_read('svn_developer', 'svn_developer')
    assert svn_can_write('svn_developer', 'svn_developer')
    assert not svn_can_write('svn_developer', 'wrong')
    assert svn_can_read('svn_user', 'svn_user')
    assert not svn_can_write('svn_user', 'svn_user')
    assert not svn_can_write('svn_user', 'wrong')

    # Test a directory without anonymous access.
    assert not svn_can_read(path = '/developers_only')
    assert not svn_can_write(path = '/developers_only')
    assert svn_can_read('svn_superuser', 'svn_superuser', '/developers_only')
    assert not svn_can_read('svn_superuser', 'wrong', '/developers_only')
    assert svn_can_write('svn_superuser', 'svn_superuser', '/developers_only')
    assert not svn_can_write('svn_superuser', 'wrong', '/developers_only')
    assert svn_can_read('svn_developer', 'svn_developer', '/developers_only')
    assert not svn_can_read('svn_developer', 'wrong', '/developers_only')
    assert svn_can_write('svn_developer', 'svn_developer', '/developers_only')
    assert not svn_can_write('svn_developer', 'wrong', '/developers_only')
    assert not svn_can_read('svn_user', 'svn_user', '/developers_only')
    assert not svn_can_read('svn_user', 'wrong', '/developers_only')
    assert not svn_can_write('svn_user', 'svn_user', '/developers_only')
    assert not svn_can_write('svn_user', 'wrong', '/developers_only')

    # Test a directory with anonymous write access.
    assert svn_can_read(path = '/public_sandbox')
    assert svn_can_write(path = '/public_sandbox')
    assert svn_can_read('svn_user', 'svn_user', '/public_sandbox')
    assert svn_can_write('svn_user', 'svn_user', '/public_sandbox')

    # Test a directory with read-only access.
    assert svn_can_read(path = '/read_only')
    assert not svn_can_write(path = '/read_only')
    assert svn_can_read('svn_superuser', 'svn_superuser', '/read_only')
    assert not svn_can_write('svn_superuser', 'svn_superuser', '/read_only')
    assert not svn_can_write('svn_superuser', 'wrong', '/read_only')
    assert svn_can_read('svn_developer', 'svn_developer', '/read_only')
    assert not svn_can_write('svn_developer', 'svn_developer', '/read_only')
    assert not svn_can_write('svn_developer', 'wrong', '/read_only')
    assert svn_can_read('svn_user', 'svn_user', '/read_only')
    assert not svn_can_write('svn_user', 'svn_user', '/read_only')
    assert not svn_can_write('svn_user', 'wrong', '/read_only')

finally:
    terminate_httpd()
