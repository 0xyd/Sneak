import json
import time
import unittest
import pprint
import getpass


import pycurl
import requests
import lxml.html
from lxml import cssselect

from test_data import test_settings
from sneak.Http import Session

class TestSession(unittest.TestCase):

    def test_get(self):
        s = Session()
        r = s.get('https://httpbin.org/ip')
        pprint.pprint(r.to_json(), indent=4)
        s.proxy.terminate()
        self.assertEqual(r.status, 200)
        

    def test_get_onion(self):
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        r = s.get_onion('http://msydqstlz2kzerdg.onion')
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(r.status, 200)

        r = s.get_onion('http://money4uitwxrt2us.onion/')
        pprint.pprint(r.to_json(), indent=4)
        s.proxy.terminate()
        self.assertEqual(r.status, 200)
        

    def test_renew_identity(self):
        '''test_renew_identity
        *description*
            Test if the renew_identity function works well or not.
        '''
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        r = s.get('https://httpbin.org/ip')
        pprint.pprint(r.to_json(), indent=4)
        prev_ip = json.loads(r.body)['origin']
        self.assertEqual(r.status, 200)
        
        is_change = False
        for i in range(5):
            s.renew_identity()
            r = s.get('https://httpbin.org/ip')
            new_ip = json.loads(r.body)['origin']
            print('check new ip %s' % new_ip)
            if new_ip != prev_ip:
                is_change = True
                break
            print('Session will sleep for 20 secs.')
            time.sleep(20)
            prev_ip = new_ip
        s.proxy.terminate()
        self.assertTrue(is_change)

    # 2017115 Y.D. TODO: Add more sites as test case. 
    def test_post(self):
        '''
        *description*
            Here are two test cases:
            1. Post on https://httpbin.org/post
            2. Post a site's url on https://www.proxysite.com/ 
            3. [Cloudflare Block Onions...So we have to stop it temporarily.]
                Login to http://interactivepython.org/runestone/default/user/login 
            
        
        '''
        # TestCase 1.
        s = Session(exit_country_code='tw')
        s.cUrl.setopt(pycurl.VERBOSE, True)
        r = s.post('https://httpbin.org/post', {1:1, 2:2})
        pprint.pprint(r.to_json(), indent=4)
        s.proxy.terminate()
        self.assertEqual(r.status, 200)

        # TestCase 2.
        # r = s.post(
        #     'https://eu0.proxysite.com/includes/process.php?action=update', 
        #     data={
        #         'server-option': 'us1', 
        #         'd': 'www.google.com'
        #         })
        # pprint.pprint(r.to_json(), indent=4)
        
        # self.assertEqual(200, r.status)
        

        # TestCase 2.
        # username = input('Enter the user name')
        # password = getpass.getpass()
        
        # r = s.post(
        #     'http://interactivepython.org/runestone/default/user/login?_next=/runestone/default/index',
        #     {'username': username, 'password': password})
        # pprint.pprint(r.to_json(), indent=4)

    def test_post_onion(self):
        '''test_post_onion
        *description*
            Test if the post_onion works fine or not.
            Test Cases:
            1. Buy 1 unit of 10x1cc BD Insulin Syringes on http://pms5n4czsmblkcjl.onion/

        '''
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        r = s.post_onion(
            'http://pms5n4czsmblkcjl.onion/cart.php', 
            data={
                'id': 100,
                'add': 'action',
                'text': 2,
            })
        pprint.pprint(r.to_json(), indent=4)
        s.proxy.terminate()
        self.assertEqual(r.status, 200)

    # 20171220 Y.D.: [HOTFIX] HEAD not works well...
    def test_head(self):
        '''test_head
        *description*
            Test Case 1: Send HEAD request to Google.  (Should get 302)
            Test Case 2: Send HEAD request to twitter. (Should get 200)
        '''
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        r0   = s.head('https://www.google.com')
        req0 = requests.head('https://www.google.com')
        r1   = s.head('https://twitter.com/?lang=en')
        req1 = requests.head('https://twitter.com/?lang=en')
        s.proxy.terminate()
        self.assertEqual(r0.status, req0.status_code)
        self.assertEqual(r0.body  , req0.text)
        self.assertEqual(r1.status, req1.status_code)
        self.assertEqual(r1.body  , req1.text)
        
    def test_head_onion(self):
        '''test_head
        *description*
            Test the HEAD method is workable on hidden services or not.
            Test Case 1: 
            HEAD the [Green World](http://greenroxwc5po3ab.onion/)
            Test Case 2:
            HEAD the [Lambda](http://ze2djl7sv6m7eqzi.onion/)

        '''
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        proxies = {
            'http' : 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9500'
        }
        r0   = s.head_onion('http://greenroxwc5po3ab.onion/')
        req0 = requests.head('http://greenroxwc5po3ab.onion/', proxies=proxies)
        self.assertEqual(r0.status, req0.status_code)
        self.assertEqual(r0.body,   req0.text)

        r1   = s.head_onion('http://ze2djl7sv6m7eqzi.onion/')
        req1 = requests.head('http://ze2djl7sv6m7eqzi.onion/', proxies=proxies)
        self.assertEqual(r1.status, req1.status_code)
        self.assertEqual(r1.body,   req1.text)
        s.proxy.terminate()

    def test_cookie(self):
        '''
        *description*  
            We use pypi account as the testing sample

            Test Case 1:  
            Login and store the cookie sucessfully.  

            Test Case 2:  
            Read cookie through text.  

            Test Case 3:
            Read cookie file directly.

        '''
        def get_logstatus(html):
            html = lxml.html.fromstring(bytes(html, 'utf8'))
            html = html.get_element_by_id('document-navigation')
            links  = html.cssselect('li>a')
            status = links[1].text_content()
            return status

        log_status = ['', '']

        # 20171219 Y.D. Test Case 1
        print('username: %s' % test_settings.PYPI_USERNAME)
        print('password: %s' % test_settings.PYPI_PASSWORD)
        login = {
            'action' : 'login_form',
            'nonce'  :  test_settings.PYPI_NONCE,
            'username': test_settings.PYPI_USERNAME,
            'password': test_settings.PYPI_PASSWORD
        }
        s  = Session(cookie_path='test_data/cookies.txt', redirect=True)
        r0 = s.post('https://pypi.python.org/pypi', data=login)
        r1 = s.get('https://pypi.python.org/pypi')
        log_status[0] = get_logstatus(r0.body)
        log_status[1] = get_logstatus(r1.body)
        s.proxy.terminate()

        self.assertEqual(log_status[0], 'Logout')
        self.assertEqual(log_status[0], log_status[1])

        # 20171219 Y.D. Test Case 2
        s = Session(cookie=test_settings.PYPI_COOKIE , cookie_path='test_data/cookies.txt')
        r = s.get('https://pypi.python.org/pypi')
        log_status[0] = get_logstatus(r.body)
        r = s.get('https://pypi.python.org/pypi?%3Aaction=browse')
        log_status[1] = get_logstatus(r.body)
        s.proxy.terminate()

        print('First Login:  %s' % log_status[0])
        print('Second Login: %s' % log_status[1])
        self.assertEqual(log_status[0], 'Logout')
        self.assertEqual(log_status[0], log_status[1])

        # 20171220 Y.D. Test Case 3
        s = Session(cookie_path='test_data/cookies.txt')
        r = s.get('https://pypi.python.org/pypi')
        log_status = get_logstatus(r.body)
        self.assertEqual(log_status, 'Logout')
        s.proxy.terminate()


from sneak.Tor import Proxy, ProxyChain

class TestProxyChain(unittest.TestCase):

    def test_run(self):
        # Test Case 1: Avoid proxy collision
        p = Proxy()
        p.run()
        p.auth_controller()

        proxy_chain = ProxyChain()
        proxy_chain.run()

        p.terminate()
        proxy_chain.terminate()

    def test_write_config(self):
        proxy_chain = ProxyChain(num_proxy=10)
        proxy_chain.run()
        proxy_chain.write_config(proxychain_config='test_proxychains.config')

        # Test Case 1: Check the number of proxies in config file is 
        # the same as the number of living proxies
        start_count_proxy = False
        proxy_number = 0
        config_file = open('test_proxychains.config', 'r')
        for line in config_file.readlines():
            if '[ProxyList]' in line:
                start_count_proxy = True
            elif start_count_proxy:
                proxy_number +=1

        proxy_chain.terminate()
        self.assertEqual(proxy_number, len(proxy_chain.proxies))

from sneak.Netool import NetMap

class TestNetMap(unittest.TestCase):

    def test_scan(self):
        # Test Case 1: Usual domain
        netmap = NetMap()
        r = netmap.scan('www.google.com')
        self.assertEqual(r[0][0], '80/tcp')
        self.assertEqual(r[0][1], 'open')
        self.assertEqual(r[0][2], 'http')
        self.assertEqual(r[1][0], '443/tcp')
        self.assertEqual(r[1][1], 'open')
        self.assertEqual(r[1][2], 'https')

        # Test Case 2: Ip address
        netmap.scan('216.58.222.14')
        self.assertEqual(r[0][0], '80/tcp')
        self.assertEqual(r[0][1], 'open')
        self.assertEqual(r[0][2], 'http')
        self.assertEqual(r[1][0], '443/tcp')
        self.assertEqual(r[1][1], 'open')
        self.assertEqual(r[1][2], 'https')

        # Test Case 3: Onion site
        netmap.scan('facebookcorewwwi.onion')
        self.assertEqual(r[0][0], '80/tcp')
        self.assertEqual(r[0][1], 'open')
        self.assertEqual(r[0][2], 'http')
        self.assertEqual(r[1][0], '443/tcp')
        self.assertEqual(r[1][1], 'open')
        self.assertEqual(r[1][2], 'https')

        # Test Case 4: Stupid Ip addresses
        netmap.scan('216.58.222.14.216.58.222.14')
        netmap.scan('2165822214')
        netmap.scan('2165.8222.14')
        netmap.terminate()


def main():
    unittest.main()

if __name__ == '__main__':
    main()