'''
    ## Http Module
    Http module is designed handle http operators based on Tor proxy.  

'''
import re
import zlib
import time
import hashlib
from io import BytesIO

import pycurl
import stem.process
from stem import Signal
from stem.control import Controller
from stem.util import system, term

from sneak.Tor import Proxy, display_msg

CURL_RE     = re.compile(r'lib(?P<ver>curl/\d+\.\d+.\d+)')
ONION_RE    = re.compile(r'https?://[a-zA-Z0-9\.]+.onion')
CHARSET_RE  = re.compile(r'charset=(?P<encoding>.*)')
HASHCODE_RE = re.compile(r'(?P<code>16:\w{20,})\n?')

# 20180211 Y.D.: 
default_curl = re.search(r'curl\/\d+\.\d+\.\d+', pycurl.version)
default_curl = default_curl.group()

def trans_dict_to_tuple(dict_data):
    '''
    #### trans_dict_to_tuple()
    ***description***
        Transform dictionary data into tuple format.  

    ***params***
        dict_data: < dict >  
        Arbitarary dictionary-type data.  

    '''
    return ((str(key), str(val)) for key, val in dict_data.items())

class Response():
    '''
    ### Response 
    
    ***description***
        Response object is the handler object to read and parse http response.  
        Besides, the response object contains information of connection time, lookup time and so on.
        They can be used to measure the network status is stable or not.  

    ***params***
        * status: < int >  
        The http status code. Ex: 200, 404 ...

        * headers: < dict >  
        The header string will be parsed to dictionary.  

        * charset: < string >  
        The document's encoding type.  

        * body: < string >
        The body of the html document.  

        * dns_time: < float >
        The time spend on dns lookup.  
        
        * start_transger_time: < float >  
        Time from start until just when the first byte is received.  
        See more [Detail](https://curl.haxx.se/libcurl/c/CURLINFO_STARTTRANSFER_TIME.html)  

        * total_time: < float >  
        The total spend time of the http operation.  

        * redirect_count: < int >  
        The redirect times of http operation.  

        * size_upload: < float >  
        Number of bytes uploaded.  

        * size_download: < float >  
        Number of bytes downloaded.  

        * header_size: < int >  
        The size of headers which count in bytes.  

        * requests_size: < int >  
        The size of request in bytes.  

    '''

    def __init__(self):
        self.status = None
        self.headers = None
        self.charset = None
        self.body = None
        self.dns_time = None
        self.conn_time = None
        self.start_transfer_time = None
        self.total_time = None
        self.redirect_count = None
        self.size_upload = None
        self.size_download = None
        self.header_size  = None
        self.request_size = None

    def set_headers_and_charset(self, headers):
        '''
        #### set_headers_and_charset()
        ***description***  
            Set up Response's header information and the charset.    
            
        ***params***  
            * headers: < dict >  
            The dictionary-type header data.  

        '''
        self.headers = headers
        try:
            self.charset = CHARSET_RE.search(headers['content-type'])
            self.charset = self.charset.group('encoding')
        except:
            self.charset = 'utf-8'

    def set_value(self, curl):
        '''
        #### set_value()
        ***description***  
            Get information about the connection time, dns lookup time and so on.  
            And store the data inside the response.  
        
        ***params***  
            * curl : < object curl >
            The curl object which contains the http response.  

        '''
        self.status = curl.getinfo(pycurl.HTTP_CODE)
        self.dns_time  = curl.getinfo(pycurl.NAMELOOKUP_TIME)                    
        self.conn_time = curl.getinfo(pycurl.CONNECT_TIME)            
        self.start_transfer_time = curl.getinfo(pycurl.STARTTRANSFER_TIME)       
        self.total_time = curl.getinfo(pycurl.TOTAL_TIME)                       
        self.redirect_count = curl.getinfo(pycurl.REDIRECT_COUNT)               
        self.size_upload   = curl.getinfo(pycurl.SIZE_UPLOAD)                     
        self.size_download = curl.getinfo(pycurl.SIZE_DOWNLOAD)                 
        self.header_size  = curl.getinfo(pycurl.HEADER_SIZE)                     
        self.request_size = curl.getinfo(pycurl.REQUEST_SIZE)                   

    def decode_body(self, body):
        '''
        #### decode_body()
        ***description***  
            The html body are usually transfer in compressed format to enchance the transfer efficiency.  

        ***params***  
            * body: < string >  
            The compressed http body data which is usally the html content itself.  
        '''
        body = body[self.header_size:]
        try:
            if 'content-encoding' in self.headers:
                line = 'start decompressing: %s' % self.headers['content-encoding']
                line = term.format(line,     term.Color.ORANGE)
                flag = term.format('Decode', term.Color.ORANGE)
                display_msg(line, flag)
                body = zlib.decompress(body, zlib.MAX_WBITS|16)
        except Exception as e:
            e = term.format(str(e), term.Color.RED)
            flag = term.format('Error', term.Color.RED)
            display_msg(e, flag)
        self.body = body.decode(self.charset, errors='replace')

    def to_json(self):
        '''
        #### to_json()
        ***description***  
            Return headers in dictionary format that can easily transform to json.  

        ***return***  
            self.__dict__: < dict >  
            Return response header in json format.  

        '''
        return self.__dict__

class TorSessionMixin(Proxy):

    def run_proxy(
        self, socks_port=9050, control_port=9051, 
        proxy_host='localhost', exit_country_code='us', tor_path='tor_0'):
        '''
        #### run_proxy()
        ***description***  
            Set a proxy with specific setting.

        ***params***    
            * socks_port: < int >  
            The port for SOCKS proxy.

            * control_port: < int >  
            Tor uses the control port to communicate.

            * proxy_host: < string >  
            The proxy host's ip address. 
            The default is localhost because most of people run Tor on their local machines. 
            Am I right?

            * exit_country_code: < string >  
            Decides where the exit nodes should be.

            * tor_path: < string >  
            The working directory for the tor process.

            * cookie_path: < string >  
            The path of cookie file.
        '''
        self.proxy = Proxy(
            socks_port=socks_port, control_port=control_port, 
            proxy_host=proxy_host, exit_country_code=exit_country_code, tor_path=tor_path)
        self.proxy.run()
        self.proxy.auth_controller()

    def renew_identity(self, clear_headers=True):
        '''
        #### renew_identity
        ***description***  
            Renew the identity to change tor's route.  
        '''
        self.proxy.renew_identity()
        if clear_headers:
            self._init_cUrl()
        else:
            self._init_cUrl(headers=self.req_headers)
        
class Session(TorSessionMixin):
    '''
    ### Session
    ***description***
        The session craete the connection through the tor tcp proxy.  

    ***params***  
        * socks_port: < int >  
        The port for SOCKS proxy.

        * control_port: < int >  
        Tor uses the control port to communicate.

        * proxy_host: < string >  
        The proxy host's ip address. 
        The default is localhost because most of people run Tor on their local machines. 
        Am I right?

        * exit_country_code: < string >  
        Decides where the exit nodes should be.

        * ssl_version: < string >  
        Choose a ssl_version. The default setting is tls_1_2. (TLS 1.3 is still a working draft.)
            * tls_1_2: Set curl to use TLS 1.2 
            * tls_1_1: Set curl to use TLS 1.1
            * tls_1_0: Set curl to use TLS 1.0 
            * tls_1  : Set curl to use TLS 1.x
            * ssl_1  : Set curl to use SSL 1 (Not Recommend)
            * ssl_2  : Set curl to use SSL 2 (Not Recommend)
            * ssl_3  : Set curl to use SSL 3 (Not Recommend)

        The list of SSL/TLS which are supported by curl are listed [here](https://curl.haxx.se/libcurl/c/CURLOPT_SSLVERSION.html).

        * ssl_verifypeer: < bool >  
        Verify all certicicates on the CA chian are recognizable to curl.

        * ssl_verifyhost: < bool >  
        Verify the certificate's name against host.
        If the certificate cannot verify the host's name as it known, connection will fail.
        [Reference](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)

        * tor_path: < string >  
        The working directory for the tor process.

        * cookie: < string >
        The cookie string.

        * cookie_path: < string >  
        The path of cookie file.
            
        * redirect: < bool >  
        Allow the redirect or not.        

        * headers: < dict >  
        The request headers the user want to set in the session.  
        The default value {}, which means pycurl will use curl's value as default.  
        
        * keep_alive: < bool >  
        Keep the connection alive after the transmission is succeed.  

        * name: < string >  
        The name of session for keep tracking its work.  

    '''
    def __init__(
        self, socks_port=9050, control_port=9051, proxy_host='localhost', exit_country_code='us', 
        tor_path='tor_0', cookie='', cookie_path='', keep_alive=False, redirect=False,
        headers={}, ssl_version='tls_1_2', ssl_verifypeer=True, ssl_verifyhost=True,
        shared_proxy=None, name=''):
        self.cUrl = None
        self.cookie   = cookie 
        self.redirect = redirect 
        self.keep_alive  = keep_alive
        self.req_headers = {}
        self.res_headers = {}
        self.cookie_path = cookie_path
        self.ssl_version = ssl_version
        self.ssl_verifypeer = ssl_verifypeer
        self.ssl_verifyhost = ssl_verifyhost

        # 20170212 Y.D.: Allow more than one session to share the same proxy.
        if shared_proxy:
            self.proxy = shared_proxy
        else:
            self.run_proxy(socks_port, control_port, proxy_host, exit_country_code, tor_path)

        # 20170213 Y.D.: 
        if name:
            self.name = name
        else:
            stamp = str(time.time()).encode('utf8')
            stamp = hashlib.sha256(stamp)
            self.name = stamp.hexdigest()[:16]

        self._init_cUrl(headers=headers)
        
    def set_headers(self, headers={}, keep_alive=False):
        '''
        #### Session.set_headers(headers={}, keep_alive=False)
        ***description***  
            set_headers function is used to set session's headers and user agent.  

        ***params***  
            * headers: < dict >  
            Headers that want to be set in session.  

            * keep_alive: < bool >  
            Keep the connection alive or not.  
            The default setting is False to make sure not use the same exit node all the time  
        '''
        if keep_alive:
            headers.update({'Connection': 'keep_alive'})
        
        _headers = []
        for key, hdr in headers.items():
            self.req_headers[key] = hdr
            _headers.append('{0}: {1}'.format(key, hdr))
        self.cUrl.setopt(pycurl.HTTPHEADER, _headers)


    def _init_cUrl(self, headers={}):
        '''_
        #### _init_cUrl()
        ***description***  
            Prepare the curl for http operations.
            About security settings
        _'''
        # Initialise the curl and its method to parse headers.
        # We only need to set the parse header function once.
        self.cUrl = pycurl.Curl()
        self.cUrl.setopt(pycurl.HEADER, True)
        self.cUrl.setopt(pycurl.HEADERFUNCTION, self._parse_header)

        # 20180221 Y.D.: NEW: Rewrite the logic of setting headers
        if 'User-Agent' not in headers:
            headers.update({'User-Agent': default_curl})
        self.set_headers(headers)

        # Set up the ssl settings
        if self.ssl_version == 'tls_1_2':
            self.cUrl.setopt(pycurl.SSL_OPTIONS, pycurl.SSLVERSION_TLSv1_2) 
        elif self.ssl_version == 'tls_1_1':
            self.cUrl.setopt(pycurl.SSL_OPTIONS, pycurl.SSLVERSION_TLSv1_1)
        elif self.ssl_version == 'ssl_2':
            self.cUrl.setopt(pycurl.SSL_OPTIONS, pycurl.SSLVERSION_SSLv2)
        elif self.ssl_version == 'ssl_3':
            self.cUrl.setopt(pycurl.SSL_OPTIONS, pycurl.SSLVERSION_SSLv3)

        # 20171202 Y.D.: The method to verify CA.
        if self.ssl_verifypeer:
            self.cUrl.setopt(pycurl.SSL_VERIFYPEER, 1)
        if self.ssl_verifyhost:
            # 2: Certificate must indicate that the server is the server request is send to.
            # 0: Don't care that much, just connect.
            self.cUrl.setopt(pycurl.SSL_VERIFYHOST, 2)

        if self.redirect:
            self.cUrl.setopt(pycurl.FOLLOWLOCATION, 1)
        
        # Enable cookies
        self.cUrl.setopt(pycurl.COOKIE, self.cookie)
        if self.cookie_path:
            self.cUrl.setopt(pycurl.COOKIEJAR,  self.cookie_path)
            self.cUrl.setopt(pycurl.COOKIEFILE, self.cookie_path)
        
    def _parse_header(self, header_line):
        '''_
        #### _parse_header()
        ***description***  
            The function is used to parse response's header line by line.

        ***params***    
            * header_line: < string >  
            pycurl reads response's header one line at a time.  
            
        _'''
        header_line = header_line.decode('iso-8859-1')
        if ':' not in header_line:
            return 

        # Split the header's key-value pair.
        name, value = header_line.split(':', 1)
        name  = name.strip().lower()
        value = value.strip()
        self.res_headers[name] = value
    
    def _set_proxy(method, removed_dns=False):
        '''_
        #### _set_proxy()
        ***description***
            _set_proxy is a decorator to set up the proxy server.
            Basically, the normal hostnames can be resolved by normal dns service;
            the hidden services, however, has to be resolved by socks server locally.

        ***params***  
            * method: < string >  
            The names of Http method such as GET, POST, HEAD.  

            * removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True:   The hostname has to be resolved by SOCKS server locally.
            False:  Hostname have to resolve by DNS servers. 
            
        _'''
        def decorator(fn):
            def set_proxy(self, url, **kwargs):
                self.cUrl.setopt(pycurl.PROXY, self.proxy.host)
                self.cUrl.setopt(pycurl.PROXYPORT, self.proxy.socks_port)    
                if removed_dns:
                    self.cUrl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
                else:
                    self.cUrl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5) 

                if method == 'POST':
                    for k, v in kwargs.items():
                        if k == 'data':
                            return fn(self, url, data=v)
                elif method == 'GET' or method == 'HEAD':
                    return fn(self, url)
            return set_proxy
        return decorator

    def _set_headers(method, removed_dns):
        '''_
        #### _set_headers()
        ***description***
            Set the user-agent.  

        ***params***  
            * method: < string >
            The names of Http method such as GET, POST, HEAD.  

            * removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True:   The hostname has to be resolved by SOCKS server locally.
            False:  Hostname have to resolve by DNS servers. 

        _'''
        def decorator(fn):
            def set_headers(self, url, headers={}, **kwargs):
                
                if headers != self.req_headers:
                    self.set_headers(headers)

                if method == 'GET' or method == 'HEAD':
                    return fn(self, url)
                elif method == 'POST':
                    for k, v in kwargs.items():
                        if k == 'data':
                            return fn(self, url, data=v)
            return set_headers
        return decorator

    def _is_onion(method):
        '''_
        #### _is_onion()
        ***description***  
            is_onion() is a decorator function to check if the url is onion site or not.  
            If it is not an onion site, pass None to stop function.  

        ***params***  
            * f: < function >  
            The function that will be executed only the onion url is verified.  

        _'''
        def decorator(fn):
            def is_onion(self, url, **kwargs):
                is_onion_service = False
                if ONION_RE.search(url):
                    is_onion_service = True
                if is_onion_service != True:
                    line = term.format(
                        'The URL is not an onion. Please use get() instead', 
                            term.Color.RED)
                    flag = term.format('Error', term.Color.RED)
                    display_msg(line, flag)
                    return None

                if method == 'GET' or method == 'HEAD':
                    return fn(self, url)
                elif method == 'POST':
                    for k, v in kwargs.items():
                        if k == 'data':
                            return fn(self, url, data=v)
            return is_onion
        return decorator
        
    def _get(f):  
        '''_
        #### _get()
        ***description***
            _get() is the decorator function for get() and get_onion().  
            The details of curl to perform GET are implemented here.  

        ***params***  
            * f: < function >  

            * url: < string >  
            Url you want to get.

            * removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True: The hostname has to be resolved by SOCKS server.
            False:  Hostname probably can be resolved locally.  

        _'''
        def get(self, url):
            r = Response()
            b = BytesIO()
            self.cUrl.setopt(pycurl.URL, url)
            self.cUrl.setopt(pycurl.CUSTOMREQUEST, 'GET')
            self.cUrl.setopt(pycurl.HTTPGET, 1)
            self.cUrl.setopt(pycurl.WRITEDATA, b)
            self.cUrl.setopt(pycurl.NOBODY, False)

            try:
                self.cUrl.perform()
                r.set_headers_and_charset(self.res_headers)
                r.set_value(self.cUrl)
                r.decode_body(b.getvalue())
                return r
            except Exception as e:
                e = term.format(str(e), term.Color.RED)
                flag = term.format('Error', term.Color.RED)
                display_msg(e, flag)
                return 
        return get

    @_set_headers('GET', False)
    @_set_proxy('GET', False)
    @_get
    def get(self):
        '''
        #### Session.get(url, **kwargs)
        ***description***
            A GET HTTP method for non-hidden services.  

        ***params***  
            * url: < string >  
            The host's url which you want to get.  

            * headers: < dict >
            Headers information.  

        ***return***  
            r: < Response object >  
            The response object will be return if GET can work well.  
            Otherwise, the None will be return.  
        '''
        return 

    @_is_onion('GET')
    @_set_headers('GET', True)
    @_set_proxy('GET', True)
    @_get
    def get_onion(self, onion_url):
        '''
        #### get_onion()
        ***description***
            Perfom GET method on onion service.

        ***params***  
            * onion_url: < string >
            An url of the hidden service. 
            The end of domain should be '.onion'.  

            * headers: < dict >
            Headers information.  

        ***return***  
            r: <Response object>
            The response object will be return if GET can work well.  
            Otherwise, the None will be return.  
        '''
        return 

    def _post(fn):
        '''_
        #### _post()
        ***description***
            Use pycurl to do HTTP POST method.

        ***params***  
            * url: < string >  
            Post a certain data on an url.  

            * data: < dict >  
            The data that we want to send to the host.  
        _'''
        def post(self, url, data):
            r = Response()
            b = BytesIO()
            post_data = []
            post_data.extend(trans_dict_to_tuple(data))
            self.cUrl.setopt(pycurl.CUSTOMREQUEST, 'POST')
            self.cUrl.setopt(pycurl.URL, url)
            self.cUrl.setopt(pycurl.WRITEDATA, b)
            self.cUrl.setopt(pycurl.POST, 1)
            self.cUrl.setopt(pycurl.HTTPPOST, post_data)
            self.cUrl.setopt(pycurl.NOBODY, False)

            try:
                self.cUrl.perform()
                r.set_headers_and_charset(self.res_headers)
                r.set_value(self.cUrl)
                r.decode_body(b.getvalue())
                return r
            except Exception as e:
                e = term.format(str(e), term.Color.RED)
                flag = term.format('Error', term.Color.RED)
                display_msg(e, flag)
                return 
            
        return post

    @_set_headers('POST', False)
    @_set_proxy('POST', False)
    @_post
    def post(self, url, data={}):
        '''
        #### Session.post(url, data={})
        ***description***
            POST a new data to the server through the url.

        ***params***  
            * url: < string >  
            The url to conduct HTTP POST method.

            * data: < dict >  
            The data which is used to post form. 

            * headers: < dict >  
            Headers information.  

        ***return***  
            r: <Response object>
            The response object will be return if GET can work well.  
            Otherwise, the None will be return.  

        '''
        return 

    @_is_onion('POST')
    @_set_headers('POST', True)
    @_set_proxy('POST', True)
    @_post
    def post_onion(self, onion_url, data={}):
        '''
        #### Session.post_onion(onion_url, data={})
        ***description***
            Conduct a HTTP POST in the dark world

        ***params***  
            * onion_url: < string >  
            The hidden service's url to do HTTP POST method.

            * data: < dict >  
            The data which is used to post form.  

            * headers: < dict >
            Headers information.  

        ***return***  
            r: <Response object>
            The response object will be return if GET can work well.  
            Otherwise, the None will be return. 

        '''
        return

    def _head(fn):
        '''_
        #### _head()
        ***description***
            Perform GET operation with NOBODY request.

        ***params***  
            * url: < string >  
            The url the head operation perform on.

            * removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True: The hostname has to be resolved by SOCKS server.
            False:  Hostname probably can be resolved locally.

        _'''
        def head(self, url):
            r = Response()
            b = BytesIO()
            self.cUrl.setopt(pycurl.CUSTOMREQUEST, 'HEAD')
            self.cUrl.setopt(pycurl.NOBODY, True)
            self.cUrl.setopt(pycurl.WRITEDATA, b)
            self.cUrl.setopt(pycurl.URL, url)
            try:
                self.cUrl.perform()
                r.set_headers_and_charset(self.res_headers)
                r.set_value(self.cUrl)
                r.body = ''
                # self.cUrl.reset()
                return r
            except Exception as e:
                e = term.format(str(e), term.Color.RED)
                flag = term.format('Error', term.Color.RED)
                display_msg(e, flag)
                return 
        return head

    @_set_headers('HEAD', False)
    @_set_proxy('HEAD', False)
    @_head
    def head(self, url):
        '''
        #### Session.head(url, **kwargs)
        ***description***
            Send a HTTP Head on the light url.  

        ***params***  
            * url: < string >
            The host's url which you want to head.  

            * headers: < dict >
            Headers information.  

        ***return***  
            r: <Response object>
            The response object will be return if GET can work well.  
            Otherwise, the None will be return. 

        '''

        return

    @_is_onion('HEAD')
    @_set_headers('HEAD', True)
    @_set_proxy('HEAD', True)
    @_head
    def head_onion(self, onion_url):
        '''
        #### head_onion()
        ***description***
            Send a HTTP Head on the dark url.  

        ***params***  
            * url: < string >  
            The onion site you want to HEAD on.  

        ***return***  
            r: <Response object>
            The response object will be return if GET can work well.  
            Otherwise, the None will be return. 
        '''
        return 

    def delete(self, url):
        '''
        #### delete()
        ***description***  
            Send a delete request.
        ***params***  
            * url: < string >  
            Where the delete request will be send to.
        '''
        pass

    def delete_onion(self, onion_url):
        '''
        #### delete_onion()
        ***description***  
            Send a delete request on an onion site.
        '''
        pass


from queue import Queue, Empty
from functools import partial
from threading import Thread, Event
from collections import OrderedDict as odict

class HttpWorkerPool():
    '''
    ### HttpWorkerPool
    ***description***  
        HttpWorkerPool are designed for conducting http jobs in sequence order. 
        Multiple sessions are stored to handle the assigned tasks 
        
    ***params***  
        * workers: < array <Session> >
        The array of the sessions for http tasks.

        * elapsed: < float >  
        The gap time between each thread starting.  


    '''
    def __init__(self, workers, elapsed=.5):

        self.workers = odict()
        self.threads = []
        for worker in workers:
            name = worker.name
            w = {
                name : {
                    'session' : worker,
                    'prepared': Queue(), # prepared queue to store the working task
                    'finished': Queue()  # finished queue to store the results of task
                }
            }
            self.workers.update(w)

        self.num_workers = len(workers)
        self.elapsed = elapsed
        self.lock = Event()

    def _sort_worker_queue(self):
        '''_sort_worker_queue
        ***description***  
            The function is used to sort the workers according to the prepared working queue.  
        '''
        self.workers = odict(
            sorted(self.workers.items(), key=lambda x: x[1]['prepared'].qsize()))

    def get_worker_by_index(self, index):
        '''
        #### get_worker_by_index  
        ***description***  
            Get the worker information through the index.  
        ***params***  
            * index: < int >  
            The index of the session.  
        ***return***  
            sess: < dict >  
            There are three keys: 'session', 'prepared' and 'finished'.
            'session' 's value is Session object.  
            'prepared' 's value is Queue object where the undo tasks are stored.  
            'finished' 's value is Queue object where the results of tasks are store in Queue
        '''
        worker_list = list(self.workers.items())
        worker = worker_list[index]
        name = worker[0]
        sess = worker[1]['session']
        return sess

    def get_worker_by_name(self, name):
        '''
        #### get_worker_by_name
        ***description***  
            Get the worker information through the name.  
        ***return***  
            sess: < dict >  
            There are three keys: 'session', 'prepared' and 'finished'.
            'session' 's value is Session object.  
            'prepared' 's value is Queue object where the undo tasks are stored.  
            'finished' 's value is Queue object where the results of tasks are store in Queue
        '''
        worker = self.workers[name]
        sess   = worker['session']
        return sess

    def add_task(self, url, assigned='', method='GET', headers={}, data={}, is_onion=False):
        '''   
        #### add_task()  
        ***description***  
            Add the Http task to the workers.  
        ***params***  
            * url: < string >
            The host's url which you want to head.  

            * assigned: < string >  
            The session which user want to assign the job.  

            * headers: < dict >
            Headers information.  

            * data: < dict >  
            The data which is used to post form.  
            
        '''
        # The function for wrapper to call.
        def task_get(session, result_queue, url, headers, is_onion=False):
            if is_onion:
                res = session.get_onion(url, headers=headers)
            else:
                res = session.get(url, headers=headers)
            result_queue.put(res)

        def task_post(session, result_queue, url, data, headers, is_onion=False):
            if is_onion:
                res = session.post_onion(url, data=data, headers=headers)
            else:
                res = session.post(url, data=data, headers=headers)
            result_queue.put(res)

        def task_head(session, result_queue, url, headers, is_onion=False):
            if is_onion:
                res = session.head_onion(url, headers=headers)
            else:
                res = session.head(url, headers=headers)
            result_queue.put(res)

        task = None
        last_worker = list(self.workers.items())[0][1]
        if method == 'GET' and len(assigned) == 0:
            task = partial(
                task_get, last_worker['session'], last_worker['finished'], 
                url, headers, is_onion)
            last_worker['prepared'].put(task)
        elif method == 'POST' and len(assigned) == 0:
            task = partial(
                task_post, last_worker['session'], last_worker['finished'], 
                url, data, headers, is_onion)
            last_worker['prepared'].put(task)
        elif method == 'HEAD' and len(assigned) == 0:
            task = partial(
                task_head, last_worker['session'], last_worker['finished'], 
                url, headers, is_onion)
            last_worker['prepared'].put(task)
        elif method == 'GET':
            task = partial(
                task_get, 
                self.workers[assigned]['session'], 
                self.workers[assigned]['finished'], 
                url, headers, is_onion)
            self.workers[assigned]['prepared'].put(task)
        elif method == 'POST':
            task = partial(
                task_post, 
                self.workers[assigned]['session'], 
                self.workers[assigned]['finished'], 
                url, data, headers, is_onion)
            self.workers[assigned]['prepared'].put(task)
        elif method == 'HEAD':
            task = partial(
                task_head, 
                self.workers[assigned]['session'], 
                self.workers[assigned]['finished'], 
                url, headers, is_onion)
            self.workers[assigned]['prepared'].put(task)

        self._sort_worker_queue()


    def work(self, timeout=60):
        '''
        #### work()  
        ***description***  
            The workers in the pool start their jobs.  

        ***params***  
            * timeout: < int >  
            Set up the timeout seconds. Once the time is out, renew the session.

        ***return***  
            results: < dict >  
            The results of working results are returned here.  
            The keys are the name of the sessions; the values are the list of the results.  
        '''
        self.lock.set()

        while True:
            tasks = []
            sess_names   = []
            self.threads = []
            # Caculate how many workers haven't finished all their tasks
            for worker in self.workers.items():
                if worker[1]['prepared'].empty():
                    pass
                else:
                    task = worker[1]['prepared'].get()
                    tasks.append(task)
                    sess_names.append(worker[0])

            if len(tasks) == 0:
                break
            else:
                self.threads = [ None ] * len(tasks)

                for i, thread in enumerate(self.threads):
                    thread = Thread(target=tasks[i])
                    thread.name = '{}: {}'.format(thread.name, sess_names[i])
                    thread.start()
                    self.threads[i] = thread

                for thread in self.threads:
                    thread.join(timeout)
                    time.sleep(self.elapsed)

                # Timeout then renew the identity
                is_identity_renew = False
                for i, thread in enumerate(self.threads):
                    if thread.isAlive():
                        msg  = '{0} does not work in {1} second(s)'\
                            .format(thread.name, timeout)
                        msg  = term.format(msg, term.Color.RED) 
                        flag = term.format('TimeOut', term.Color.RED)
                        display_msg(msg, flag)
                        self.lock.clear()
                        self.get_worker_by_index(i).renew_identity()
                        self.lock.set()
                        is_identity_renew = True

                    if is_identity_renew:
                        break

        # Retrieve working results of workers 
        results = {}
        for worker in self.workers.items():
            name = worker[0]
            work = worker[1]
            results[name] = []
            while True:
                if work['finished'].empty():
                    break
                else:
                    result = work['finished'].get()
                    results[name].append(result)
        return results


            



    
