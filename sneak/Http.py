'''
    ## Http Module
    Http module is designed handle http operators based on Tor proxy.  

'''
import re
import zlib
from io import BytesIO

import pycurl
import stem.process
from stem import Signal
from stem.control import Controller
from stem.util import system, term

from sneak.Tor import Proxy

CURL_RE     = re.compile(r'lib(?P<ver>curl/\d+\.\d+.\d+)')
ONION_RE    = re.compile(r'https?://[a-zA-Z0-9\.]+.onion')
CHARSET_RE  = re.compile(r'charset=(?P<encoding>.*)')
HASHCODE_RE = re.compile(r'(?P<code>16:\w{20,})\n?')


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
    ### class Response  
    ***description***
        Response object is the handler object to read and parse http response.  
        Besides, the response object contains information of connection time, lookup time and so on.
        They can be used to measure the network status is stable or not.  

    ***params***
        status: < int >  
        The http status code. Ex: 200, 404 ...

        headers: < dict >  
        The header string will be parsed to dictionary.  

        charset: < string >  
        The document's encoding type.  

        body: < string >
        The body of the html document.  

        dns_time: < float >
        The time spend on dns lookup.  
        
        start_transger_time: < float >  
        Time from start until just when the first byte is received.  
        See more [Detail](https://curl.haxx.se/libcurl/c/CURLINFO_STARTTRANSFER_TIME.html)  

        total_time: < float >  
        The total spend time of the http operation.  

        redirect_count: < int >  
        The redirect times of http operation.  

        size_upload: < float >  
        Number of bytes uploaded.  

        size_download: < float >  
        Number of bytes downloaded.  

        header_size: < int >  
        The size of headers which count in bytes.  

        requests_size: < int >  
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
            headers: < dict >  
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
            curl : < object curl >
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
            body: < string >  
            The compressed http body data which is usally the html content itself.  
        '''
        body = body[self.header_size:]
        try:
            if 'content-encoding' in self.headers:
                print('start decompressing: %s' % self.headers['content-encoding'])
                body = zlib.decompress(body, zlib.MAX_WBITS|16)
        except Exception as e:
            print(e)
            pass
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
            socks_port: < int >  
            The port for SOCKS proxy.

            control_port: < int >  
            Tor uses the control port to communicate.

            proxy_host: < string >  
            The proxy host's ip address. 
            The default is localhost because most of people run Tor on their local machines. 
            Am I right?

            exit_country_code: < string >  
            Decides where the exit nodes should be.

            tor_path: < string >  
            The working directory for the tor process.

            cookie_path: < string >  
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
            self._init_cUrl(headers=self.headers, user_agent=self.user_agent)
        
class Session(TorSessionMixin):
    '''
    ###class Session
    ***description***
        The session craete the connection through the tor tcp proxy.  

    ***params***  
        socks_port: < int >  
        The port for SOCKS proxy.

        control_port: < int >  
        Tor uses the control port to communicate.

        proxy_host: < string >  
        The proxy host's ip address. 
        The default is localhost because most of people run Tor on their local machines. 
        Am I right?

        exit_country_code: < string >  
        Decides where the exit nodes should be.

        ssl_version: < string >  
        Choose a ssl_version. The default setting is tls_1_2. (TLS 1.3 is still a working draft.)
        * tls_1_2: Set curl to use TLS 1.2 
        * tls_1_1: Set curl to use TLS 1.1
        * tls_1_0: Set curl to use TLS 1.0 
        * tls_1  : Set curl to use TLS 1.x
        * ssl_1  : Set curl to use SSL 1 (Not Recommend)
        * ssl_2  : Set curl to use SSL 2 (Not Recommend)
        * ssl_3  : Set curl to use SSL 3 (Not Recommend)

        The list of SSL/TLS which are supported by curl are listed [here](https://curl.haxx.se/libcurl/c/CURLOPT_SSLVERSION.html).

        ssl_verifypeer: < bool >  
        Verify all certicicates on the CA chian are recognizable to curl.

        ssl_verifyhost: < bool >  
        Verify the certificate's name against host.
        If the certificate cannot verify the host's name as it known, connection will fail.
        [Reference](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)

        tor_path: < string >  
        The working directory for the tor process.

        cookie: < string >
        The cookie string.

        cookie_path: < string >  
        The path of cookie file.
            
        redirect: < bool >  
        Allow the redirect or not.        

        headers: < dict >  
        The headers the user want to set in the session.  
        The default value {}, which means pycurl will use curl's value as default.  
        
        user_agent: < str >  
        The agent the user want to prentent. Without setting, the default is a *curl*.  

        keep_alive: < bool >  
        Keep the connection alive after the transmission is succeed.  


    '''
    def __init__(
        self, socks_port=9050, control_port=9051, proxy_host='localhost', exit_country_code='us', 
        tor_path='tor_0', cookie='', cookie_path='', keep_alive=False, redirect=False,
        headers={}, user_agent='', ssl_version='tls_1_2', ssl_verifypeer=True, ssl_verifyhost=True):
        self.cUrl = None
        self.cookie   = cookie 
        self.redirect = redirect 
        self.keep_alive  = keep_alive
        # 20170118 Y.D.: Set user agent
        self.user_agent  = user_agent
        # 20170118 Y.D.: Set headers
        self.headers = {}
        self.res_headers = {}
        self.cookie_path = cookie_path
        self.ssl_version = ssl_version
        self.ssl_verifypeer = ssl_verifypeer
        self.ssl_verifyhost = ssl_verifyhost

        self.run_proxy(socks_port, control_port, proxy_host, exit_country_code, tor_path)
        self._init_cUrl(headers=headers, user_agent=user_agent)

    def set_headers(self, headers={}, user_agent='', keep_alive=False):
        '''
        #### set_headers()
        ***description***  
            set_headers function is used to set session's headers and user agent.  

        ***params***  
            headers: < dict >  
            Headers that want to be set in session.  

            user_agent: < str >  
            The agent you want to pretent to be.  
        '''
        if keep_alive:
            headers.update({'Connection': 'keep_alive'})
        self.headers = headers

        headers = list('%s: %s' % (key, value) for key, value in headers.items())
        self.cUrl.setopt(pycurl.HTTPHEADER, headers)

        if len(user_agent) == 0:
            pass
        else:
            self.cUrl.setopt(pycurl.USERAGENT, user_agent) 

    def _init_cUrl(self, headers={}, user_agent=''):
        '''
        #### _init_cUrl()
        ***description***  
            Prepare the curl for http operations.
            About security settings
        '''
        # Initialise the curl and its method to parse headers.
        # We only need to set the parse header function once.
        self.cUrl = pycurl.Curl()
        self.cUrl.setopt(pycurl.HEADER, True)
        self.cUrl.setopt(pycurl.HEADERFUNCTION, self._parse_header)

        # 20180117 Y.D.: 
        self.set_headers(headers, user_agent, self.keep_alive)

        # headers = [
        #     'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        #     'Accept-Language: en-US,en;q=0.5',
        #     'Accept-Encoding: gzip, deflate'
        # ]
        # if self.keep_alive:
        #     headers.append('Connection: keep-alive')
        # self.cUrl.setopt(pycurl.HTTPHEADER, headers)

        # 20171115 Y.D.: ADD more different options.
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
        '''
        #### _parse_header()
        ***description***  
            The function is used to parse response's header line by line.

        ***params***    
            header_line: < string >  
            pycurl reads response's header one line at a time.
            
        '''
        header_line = header_line.decode('iso-8859-1')
        if ':' not in header_line:
            return 

        # Split the header's key-value pair.
        name, value = header_line.split(':', 1)
        name  = name.strip().lower()
        value = value.strip()
        self.res_headers[name] = value
    
    def _set_proxy(method, removed_dns=False):
        '''
        #### _set_proxy()
        ***description***
            _set_proxy is a decorator to set up the proxy server.
            Basically, the normal hostnames can be resolved by normal dns service;
            the hidden services, however, has to be resolved by socks server locally.

        ***params***  
            method: < string >
            The names of Http method such as GET, POST, HEAD.  

            removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True:   The hostname has to be resolved by SOCKS server locally.
            False:  Hostname have to resolve by DNS servers. 
            
        '''
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
        '''
        #### _set_headers()
        ***description***
            Set the user-agent.  

        ***params***  
            method: < string >
            The names of Http method such as GET, POST, HEAD.  

            removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True:   The hostname has to be resolved by SOCKS server locally.
            False:  Hostname have to resolve by DNS servers. 

        '''
        def decorator(fn):
            def set_headers(self, url, headers={}, user_agent='', **kwargs):
                self.set_headers(headers, user_agent)
                if method == 'GET' or method == 'HEAD':
                    return fn(self, url)
                elif method == 'POST':
                    for k, v in kwargs.items():
                        if k == 'data':
                            return fn(self, url, data=v)
            return set_headers
        return decorator

    def _is_onion(method):
        '''
        #### _is_onion()
        ***description***  
            is_onion() is a decorator function to check if the url is onion site or not.  
            If it is not an onion site, pass None to stop function.  

        ***params***  
            f: < function >  
            The function that will be executed only the onion url is verified.  

        '''
        def decorator(fn):
            def is_onion(self, url, **kwargs):
                is_onion_service = False
                if ONION_RE.search(url):
                    is_onion_service = True
                if is_onion_service != True:
                    print('The URL is not an onion. Please use get() instead')
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
        '''
        #### _get()
        ***description***
            _get() is the decorator function for get() and get_onion().  
            The details of curl to perform GET are implemented here.  

        ***params***  
            f: < function >  

            url: < string >  
            Url you want to get.

            removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True: The hostname has to be resolved by SOCKS server.
            False:  Hostname probably can be resolved locally.  

        '''
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
                print(e)
                return 
        return get

    @_set_headers('GET', False)
    @_set_proxy('GET', False)
    @_get
    def get(self):
        '''
        #### get()
        ***description***
            A GET HTTP method for non-hidden services.  

        ***params***  
            url: < string >
            The host's url which you want to get.  

            headers: < dict >
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
            onion_url: < string >
            An url of the hidden service. 
            The end of domain should be '.onion'.  

        ***return***  
            r: <Response object>
            The response object will be return if GET can work well.  
            Otherwise, the None will be return.
        '''
        return 

    def _post(fn):
        '''
        #### _post()
        ***description***
            Use pycurl to do HTTP POST method.

        ***params***  
            url: < string >  
            Post a certain data on an url.

            data: < dict >  
            The data that we want to send to the host. 
        '''
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
                print(e)
                return 
            
        return post

    @_set_headers('POST', False)
    @_set_proxy('POST', False)
    @_post
    def post(self, url, data={}):
        '''
        #### post()
        ***description***
            POST a new data to the server through the url.

        ***params***  
            url: < string >  
            The url to conduct HTTP POST method.

            data: < dict >  
            The data which is used to post form. 

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
        #### post_onion()
        ***description***
            Conduct a HTTP POST in the dark world

        ***params***  
            onion_url: < string >  
            The hidden service's url to do HTTP POST method.

            data: < dict >  
            The data which is used to post form.

        ***return***  
            r: <Response object>
            The response object will be return if GET can work well.  
            Otherwise, the None will be return. 

        '''
        return

    def _head(fn):
    # def _head(self, url, removed_dns=False):
        '''
        #### _head()
        ***description***
            Perform GET operation with NOBODY request.

        ***params***  
            url: < string >  
            The url the head operation perform on.

            removed_dns: < bool >  
            The hostname should be resolved by socks server or not.
            True: The hostname has to be resolved by SOCKS server.
            False:  Hostname probably can be resolved locally.

        '''
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
                print(e)
                return 
        return head

    @_set_headers('HEAD', False)
    @_set_proxy('HEAD', False)
    @_head
    def head(self, url):
        '''
        #### head()
        ***description***
            Send a HTTP Head on the light url.  

        ***params***  
            url: < string >
            The host's url which you want to head.   

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
            url: < string >  
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
            url: < string >  
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

    # 20171203 Y.D.: Move to tor.py
    # def terminate(self):
    #     '''terminate
    #     ***description***
    #         End the tor process.
    #     '''
    #     self.tor_process.kill()
    #     pass

    
