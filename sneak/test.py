import json
import time
import unittest
import pprint
import getpass

import pycurl
import requests
from HTTP import Session

class TestSession(unittest.TestCase):

    def test_get(self):
        s = Session()
        r = s.get('https://httpbin.org/ip')
        pprint.pprint(r.to_json(), indent=4)
        s.proxy.terminate()
        self.assertEqual(r.status, 200)
        

    def test_get_onion(self):
        s = Session()
        r = s.get_onion('http://msydqstlz2kzerdg.onion')
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(r.status, 200)

        r = s.get_onion('http://money4uitwxrt2us.onion/')
        pprint.pprint(r.to_json(), indent=4)
        s.proxy.terminate()
        self.assertEqual(r.status, 200)
        

    def test_renew_identity(self):
        '''test_renew_identity
        :description:
            Test if the renew_identity function works well or not.
        '''
        s = Session()
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
        :description:
            Here are two test cases:
            1. Post on https://httpbin.org/post
            2. Post a site's url on https://www.proxysite.com/ 
            3. [Cloudflare Block Onions...So we have to stop it temporarily.]
                Login to http://interactivepython.org/runestone/default/user/login 
            
        
        '''
        # TestCase 1.
        s = Session(exit_country_code='tw')
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
        :description:
            Test if the post_onion works fine or not.
            Test Cases:
            1. Buy 1 unit of 10x1cc BD Insulin Syringes on http://pms5n4czsmblkcjl.onion/

        '''
        s = Session()
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

    def test_head(self):
        '''test_head
        :description:
            Test Case 1: Send HEAD request to Google.  (Should get 302)
            Test Case 2: Send HEAD request to twitter. (Should get 200)
        '''
        s = Session()
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
        :description:
            Test the HEAD method is workable on hidden services or not.
            Test Case 1: 
            HEAD the [Green World](http://greenroxwc5po3ab.onion/)
            Test Case 2:
            HEAD the [Lambda](http://ze2djl7sv6m7eqzi.onion/)

        '''
        s = Session()
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

def main():
    unittest.main()

if __name__ == '__main__':
    main()