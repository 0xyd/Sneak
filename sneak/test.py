import json
import time
import unittest
import pprint
import getpass


import pycurl
import requests
import lxml.html
from lxml import cssselect

from sneak.Http import Session, HttpWorkerPool, default_curl
from sneak.Tor  import Proxy
from test_data  import test_settings


def get_logstatus(html):
    html = lxml.html.fromstring(bytes(html, 'utf8'))
    html = html.get_element_by_id('document-navigation')
    links  = html.cssselect('li>a')
    status = links[1].text_content()
    return status


class TestSession(unittest.TestCase):

    def test_get(self):
        s = Session()
        r = s.get('https://httpbin.org/ip')
        pprint.pprint(r.to_json(), indent=4)
        r1 = s.get('https://httpbin.orgtttt/ip')

        # 20170211 Y.D. Test if the user agent works or not
        r2 = s.get('https://httpbin.org/ip', user_agent=default_curl)
        user_agent = s.req_headers['user-agent']

        # 20170212 Y.D. Tests for Shared Proxies
        shared_proxy = s.proxy
        s2 = Session(shared_proxy=shared_proxy)
        r3 = s2.get('https://httpbin.org/ip')
        pprint.pprint(r3.to_json(), indent=4)
        s.proxy.terminate()

        p = Proxy()
        p.run()
        s3 = Session(shared_proxy=p)
        r4 = s3.get('https://httpbin.org/ip')
        p.terminate()

        self.assertEqual(r.status, 200)
        self.assertEqual(r1, None)
        self.assertEqual(r2.status, 200)
        self.assertEqual(user_agent, default_curl)
        self.assertEqual(r3.status, 200)
        self.assertEqual(r4.status, 200)

    def test_get_onion(self):
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        r0 = s.get_onion('http://msydqstlz2kzerdg.onion')
        r1 = s.get_onion('http://money4uitwxrt2us.onion')
        r2 = s.get_onion('http://money4uitwxrt2usNeverExist.onion/')
        r3 = s.get_onion('https://www.google.com/')
        proxy = s.proxy

        # 20170212 Y.D. Tests for Shared Proxies
        s2 = Session(shared_proxy=proxy)
        r4 = s2.get_onion('http://msydqstlz2kzerdg.onion')
        r5 = s2.get_onion('http://money4uitwxrt2us.onion')
        r6 = s2.get_onion('http://money4uitwxrt2usNeverExist.onion/')
        r7 = s2.get_onion('https://www.google.com/')
        s.proxy.terminate()

        proxy = Proxy()
        proxy.run()
        s3 = Session(shared_proxy=proxy)
        r8 = s3.get_onion('http://msydqstlz2kzerdg.onion')
        r9 = s3.get_onion('http://money4uitwxrt2us.onion')
        r10 = s3.get_onion('http://money4uitwxrt2usNeverExist.onion/')
        r11 = s3.get_onion('https://www.google.com/')
        proxy.terminate()

        self.assertEqual(r0.status, 200)
        self.assertEqual(r1.status, 200)
        self.assertEqual(r2, None)
        self.assertEqual(None, r3)
        self.assertEqual(r4.status, 200)
        self.assertEqual(r5.status, 200)
        self.assertEqual(r6, None)
        self.assertEqual(r7, None)
        self.assertEqual(r8.status, 200)
        self.assertEqual(r9.status, 200)
        self.assertEqual(r10, None)
        self.assertEqual(r11, None)

    def test_set_headers(self):

        headers = {
            'Accept': '*/*',
            'Accept-Language': '',
            'Accept-Encoding': ''
        }
        user_agent = 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0'

        s = Session()
        # s.cUrl.setopt(pycurl.VERBOSE, True)

        # Test Case 1. Set two different settings with different APIs.
        r0 = s.get('https://httpbin.org/anything', headers=headers, user_agent=user_agent)

        # 20170211 Y.D. Add a new test to make sure request headers setting is correct
        q0 = s.req_headers 

        s.set_headers(headers=headers, user_agent=user_agent)
        r1 = s.get('https://httpbin.org/anything')

        # 20170211 Y.D. Add a new test to make sure request headers setting is correct
        q1 = s.req_headers 

        r0_body = json.loads(r0.body)
        r1_body = json.loads(r1.body)
        pprint.pprint(r0_body['headers'], indent=4)
        pprint.pprint(r1_body['headers'], indent=4)

        # Test Case 2. Use the same setting and test again.
        r2 = s.get('https://httpbin.org/anything')
        r2_body = json.loads(r2.body)
        pprint.pprint(r2_body['headers'], indent=4)

        # Test Case 3. Change accept format 
        headers['Accept'] = \
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
        r3 = s.set_headers(headers)
        r3 = s.get('https://httpbin.org/anything')
        r3_body = json.loads(r3.body)
        pprint.pprint(r3_body['headers'], indent=4)

        # Test Case 4. 
        r4 = s.post('https://httpbin.org/post', data={1:1, 2:2}, 
            headers=headers, user_agent=user_agent)

        s.proxy.terminate()

        # 20170211 Y.D. New Test for request headers
        self.assertEqual(q0, headers)
        self.assertEqual(q1, headers)

        self.assertEqual(r0_body['headers'], r1_body['headers'])
        self.assertEqual(r1_body['headers'], r2_body['headers'])
        self.assertNotEqual(r0_body['headers'], r3_body['headers'])

        self.assertEqual(200, r4.status)

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
        
        is_change_0 = False
        for i in range(5):
            s.renew_identity()
            r = s.get('https://httpbin.org/ip')
            new_ip = json.loads(r.body)['origin']
            print('check new ip %s' % new_ip)
            if new_ip != prev_ip:
                is_change_0 = True
                break
            print('Session will sleep for 20 secs.')
            time.sleep(20)
            prev_ip = new_ip

        is_change_1 = False
        for i in range(5):
            s.renew_identity(False)
            r = s.get('https://httpbin.org/ip')
            new_ip = json.loads(r.body)['origin']
            print('check new ip %s' % new_ip)
            if new_ip != prev_ip:
                is_change_1 = True
                break
            print('Session will sleep for 20 secs.')
            time.sleep(20)
            prev_ip = new_ip
        s.proxy.terminate()

        self.assertTrue(is_change_0)
        self.assertTrue(is_change_1)

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
        # Test Case 1.
        s = Session(exit_country_code='tw')
        s.cUrl.setopt(pycurl.VERBOSE, True)
        r = s.post('https://httpbin.org/post', data={1:1, 2:2})
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
            data={ 'id': 100,'add': 'action','text': 2})
        r0 = s.post_onion(
            'http://pms5n4czsmblkcjlneverexist.onion/cart.php', 
            data={ 'id': 100,'add': 'action','text': 2})
        r1 = s.post_onion('https://httpbin.org/post', data={1:1, 2:2})
        s.proxy.terminate()

        self.assertEqual(r.status, 200)
        self.assertEqual(None, r0)
        self.assertEqual(None, r1)
        

    # 20171220 Y.D.: [HOTFIX] HEAD not works well...
    def test_head(self):
        '''test_head
        *description*
            Test Case 1: Send HEAD request to Google.  (Should get 302)
            Test Case 2: Send HEAD request to twitter. (Should get 200)
        '''
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        # r0   = s.head('https://www.google.com')
        # req0 = requests.head('https://www.google.com')
        r1   = s.head('https://twitter.com/?lang=en')
        req1 = requests.head('https://twitter.com/?lang=en')
        r2 = s.head('https://twitterneverexist.com/?lang=en')
        s.proxy.terminate()

        # self.assertEqual(r0.status, req0.status_code)
        # self.assertEqual(r0.body  , req0.text)
        self.assertEqual(r1.status, req1.status_code)
        self.assertEqual(r1.body  , req1.text)
        self.assertEqual(r2, None)
        
    def test_head_onion(self):
        '''test_head
        *description*
            Test the HEAD method is workable on hidden services or not.
            Test Case 1:  
            HEAD the [Green World](http://greenroxwc5po3ab.onion/).  

            Test Case 2:  
            HEAD the [Lambda](http://ze2djl7sv6m7eqzi.onion/)  

            Test Case 3:  
            Send HEAD to google 

        '''
        s = Session()
        s.cUrl.setopt(pycurl.VERBOSE, True)
        proxies = {
            'http' : 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9500'
        }
        r0   = s.head_onion('http://greenroxwc5po3ab.onion/')
        req0 = requests.head('http://greenroxwc5po3ab.onion/', proxies=proxies)
        r1   = s.head_onion('http://ze2djl7sv6m7eqzi.onion/')
        req1 = requests.head('http://ze2djl7sv6m7eqzi.onion/', proxies=proxies)
        r2 = s.head_onion('https://www.google.com')
        r3 = s.head_onion('http://ze2djl7sv6m7eqzineverexist.onion/')
        s.proxy.terminate()

        self.assertEqual(r0.status, req0.status_code)
        self.assertEqual(r0.body,   req0.text)
        self.assertEqual(r1.status, req1.status_code)
        self.assertEqual(r1.body,   req1.text)
        self.assertEqual(None, r2)
        self.assertEqual(None, r3)

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
        # def get_logstatus(html):
        #     html = lxml.html.fromstring(bytes(html, 'utf8'))
        #     html = html.get_element_by_id('document-navigation')
        #     links  = html.cssselect('li>a')
        #     status = links[1].text_content()
        #     return status

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
        s.proxy.terminate()
        self.assertEqual(log_status, 'Logout')


# The functions of HttpWorkerPool are multithreading
# Thus, the tests are not normal unit tests.
class TestHttpWorkerPool(unittest.TestCase):

    def test_work(self):

        sessions = []
        p = Proxy()
        p.run()

        for i in range(3):
            sessions.append(Session(shared_proxy=p))
        pool = HttpWorkerPool(workers=sessions)

        # Test Case 1: GET
        for i in range(5):
            pool.add_task('https://now.httpbin.org')
        
        for worker in pool.workers.items():
            print(worker[1]['prepared'].qsize())

        results = pool.work()
        epochs = []
        for name, res in results.items():
            for r in res:
                r = r.to_json()
                epoch = json.loads(r['body'])['now']['epoch']
                epochs.append(epoch)
        epochs.sort()
        for i in range(len(epochs)-1):
            self.assertNotEqual(epochs[i], epochs[i+1])
        
        # Check the working queue is empty
        for worker in pool.workers.items():
            self.assertTrue(worker[1]['prepared'].empty())
        
        # Test Case 2: POST
        test_post_data = [{'1':'1'}, {'2':'2'}, {'3':'3'}, {'4':'4'}, {'5':'5'}]
        for d in test_post_data:
            pool.add_task('https://httpbin.org/post', method='POST', data=d)
              
        results = pool.work()
        
        for name, res in results.items():
            for r in res:
                r = r.to_json()
                data = json.loads(r['body'])['form']
                if data in test_post_data:
                    self.assertTrue(True)
                else:
                    self.assertTrue(False)

        for worker in pool.workers.items():
            self.assertTrue(worker[1]['prepared'].empty())

        # Test Case 3: HEAD
        for i in range(5):
            pool.add_task('https://now.httpbin.org', method='HEAD')
        results = pool.work()
        
        for name, res in results.items():
            for r in res:
                r = r.to_json()
                self.assertEqual('', r['body'])

        for worker in pool.workers.items():
            self.assertTrue(worker[1]['prepared'].empty())

        # Test Case 4: Assigin Testing
        names = []
        for sess in sessions:
            names.append(sess.name)
        assigned_session = names[0]

        for i in range(5):
            pool.add_task('https://now.httpbin.org', assigned=assigned_session)
        results = pool.work()
        
        self.assertTrue(len(results[assigned_session]), 5)

        # checkout the rest of sessions which was not assigned any task.
        for name, meta in pool.workers.items():
            if name != assigned_session:
                self.assertEqual(len(results[name]), 0)

        for worker in pool.workers.items():
            self.assertTrue(worker[1]['prepared'].empty())

        # Test Case 5: 
        for i in range(5):
            pool.add_task('https://now.httpbin.org')
        results = pool.work(0.001)

        result_num = 0
        for _, r in results.items():
            result_num += len(r)
            for _r in r:
                self.assertEqual(_r.status, 200)
        self.assertEqual(result_num, 5)
        p.terminate()

    def test_work_login(self):

        p = Proxy()
        p.run()

        # Test Case: Using a worker pool to finish a Login process
        print('username: %s' % test_settings.PYPI_USERNAME)
        print('password: %s' % test_settings.PYPI_PASSWORD)
        login = {
            'action' : 'login_form',
            'nonce'  :  test_settings.PYPI_NONCE,
            'username': test_settings.PYPI_USERNAME,
            'password': test_settings.PYPI_PASSWORD
        }

        session = Session(
            shared_proxy=p, cookie_path='test_data/cookies.txt', 
            redirect=True, name='test-login')

        sessions = []
        for i in range(2):
            sessions.append(Session(shared_proxy=p))

        pool = HttpWorkerPool(workers=[session] + sessions)
        pool.add_task(
            'https://pypi.python.org/pypi', data=login, method='POST', assigned='test-login')
        pool.add_task(
            'https://pypi.python.org/pypi?%3Aaction=user_form', assigned='test-login')

        results = pool.work(30)
        p.terminate()

        for s, r in results.items():
            if len(r) == 2:
                self.assertEqual(s, 'test-login')
            for _r in r:
                log_status = get_logstatus(_r.body)
                self.assertEqual(log_status, 'Logout')
                self.assertEqual(_r.status, 200)

    def test_get_worker_by_index(self):

        sessions = []
        sessions_names = []
        p = Proxy()
        p.run()

        for i in range(3):
            sess = Session(shared_proxy=p)
            sessions_names.append(sess.name)
            sessions.append(sess)
        pool = HttpWorkerPool(workers=sessions)

        for i in range(3):
            sess = pool.get_worker_by_index(i)
            self.assertEqual(sess, sessions[i])

        p.terminate()


    def test_get_worker_by_name(self):
        sessions = []
        sessions_names = ['Petter', 'Marry', 'MotherFucker']
        p = Proxy()
        p.run()

        for name in sessions_names:
            sess = Session(shared_proxy=p, name=name)
            sessions.append(sess)

        pool = HttpWorkerPool(workers=sessions)

        for i in range(len(sessions_names)):
            sess = pool.get_worker_by_name(sessions_names[i])
            self.assertEqual(sessions[i], sess)

        p.terminate()


def main():
    unittest.main()

if __name__ == '__main__':
    main()