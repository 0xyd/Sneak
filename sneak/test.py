import json
import time
import unittest
import pprint
import getpass

import pycurl
from spider import Spider

class TestSpider(unittest.TestCase):

    def test_get(self):
        s = Spider()
        r = s.get('https://httpbin.org/ip')
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(r.status, 200)
        s.terminate()

    def test_get_onion(self):
        s = Spider()
        r = s.get_onion('http://msydqstlz2kzerdg.onion')
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(r.status, 200)

        r = s.get_onion('http://money4uitwxrt2us.onion/')
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(r.status, 200)
        s.terminate()

    def test_renew_identity(self):
        s = Spider()
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
            print('Spider will sleep for 20 secs.')
            time.sleep(20)
            prev_ip = new_ip
        s.terminate()
        self.assertTrue(is_change)

    # 2017115 Y.D. TODO: Add more sites as test case. 
    def test_post(self):
        '''
        :description:
            Here are two test cases:
            1. Post on https://httpbin.org/post
            2. Login to http://interactivepython.org/runestone/default/user/login [Cloudflare Block Onions...]
            3. Post a site's url on https://www.proxysite.com/ 
        
        '''
        # TestCase 1.
        s = Spider(exit_country_code='tw')
        r = s.post('https://httpbin.org/post', {1:1, 2:2})
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(r.status, 200)

        # TestCase 2.
        # username = input('Enter the user name')
        # password = getpass.getpass()
        
        # r = s.post(
        #     'http://interactivepython.org/runestone/default/user/login?_next=/runestone/default/index',
        #     {'username': username, 'password': password})
        # pprint.pprint(r.to_json(), indent=4)

        # TestCase 3.
        r = s.post(
            'https://eu0.proxysite.com/includes/process.php?action=update', 
            data={
                'server-option': 'us1', 
                'd': 'www.google.com'
                })
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(200, r.status)
        s.terminate()

    def test_post_onion(self):
        '''test_post_onion
        :description:
            Test if the post_onion works fine or not.
            Test Cases:
            1. Buy 1 unit of 10x1cc BD Insulin Syringes on http://pms5n4czsmblkcjl.onion/

        '''
        s = Spider()
        r = s.post_onion(
            'http://pms5n4czsmblkcjl.onion/cart.php', 
            data={
                'id': 100,
                'add': 'action',
                'text': 2,
            })
        pprint.pprint(r.to_json(), indent=4)
        self.assertEqual(r.status, 200)

def main():
    unittest.main()

if __name__ == '__main__':
    main()