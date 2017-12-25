import re
# import gzip
import zlib
from io import BytesIO

import pycurl
import stem.process
from stem import Signal
from stem.control import Controller
from stem.util import system, term

from sneak.Tor import Proxy

ONION_RE   = re.compile(r'https?://[a-zA-Z0-9\.]+.onion')
CHARSET_RE = re.compile(r'charset=(?P<encoding>.*)')
HASHCODE_RE = re.compile(r'(?P<code>16:\w{20,})\n?')

def trans_dict_to_tuple(dict_data):
    return ((str(key), str(val)) for key, val in dict_data.items())

class Response():
    '''
    *description*
    
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

    def set_headers(self, headers):
        self.headers = headers
        try:
            self.charset = CHARSET_RE.search(headers['content-type'])
            self.charset = self.charset.group('encoding')
        except:
            self.charset = 'utf-8'

    def set_value(self, curl):
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
        return self.__dict__

class TorSessionMixin(Proxy):

    def run_proxy(
        self, socks_port=9050, control_port=9051, 
        proxy_host='localhost', exit_country_code='us', tor_path='tor_0'):
        '''set_proxy
        *description*  
            Set a proxy with specific setting.

        *params*  
            socks_port: <int>  
            The port for SOCKS proxy.

            control_port: <int>  
            Tor uses the control port to communicate.

            proxy_host: <string>  
            The proxy host's ip address. 
            The default is localhost because most of people run Tor on their local machines. 
            Am I right?

            exit_country_code: <string>  
            Decides where the exit nodes should be.

            tor_path: <string>  
            The working directory for the tor process.

            cookie_path: <string>  
            The path of cookie file.
        '''
        self.proxy = Proxy(
            socks_port=socks_port, control_port=control_port, 
            proxy_host=proxy_host, exit_country_code=exit_country_code, tor_path=tor_path)
        self.proxy.run()
        self.proxy.auth_controller()

    def renew_identity(self):
        '''renew_proxy
        *description*  
            Renew the identity to change tor's route.  

        '''
        self.proxy.renew_identity()
        self._init_cUrl()
        
class Session(TorSessionMixin):
    '''Session
    *description*
        The session craete the connection through the tor tcp proxy.
    
    '''
    def __init__(
        self, socks_port=9050, control_port=9051, proxy_host='localhost', exit_country_code='us', 
        tor_path='tor_0', cookie='', cookie_path='', keep_alive=False, redirect=False,
        ssl_version='tls_1_2' , ssl_verifypeer=True, ssl_verifyhost=True):
        '''__init__
        *description*
            Session is running through Tor which is based on SOCKS proxy.

        *params*
            socks_port: <int>  
            The port for SOCKS proxy.

            control_port: <int>  
            Tor uses the control port to communicate.

            proxy_host: <string>  
            The proxy host's ip address. 
            The default is localhost because most of people run Tor on their local machines. 
            Am I right?

            exit_country_code: <string>  
            Decides where the exit nodes should be.

            ssl_version: <string>  
            Choose a ssl_version. The default setting is tls_1_2. (TLS 1.3 is still a working draft.)
            tls_1_2: Set curl to use TLS 1.2 
            tls_1_1: Set curl to use TLS 1.1
            tls_1_0: Set curl to use TLS 1.0 
            tls_1  : Set curl to use TLS 1.x
            ssl_1  : Set curl to use SSL 1 (Not Recommend)
            ssl_2  : Set curl to use SSL 2 (Not Recommend)
            ssl_3  : Set curl to use SSL 3 (Not Recommend)

            The list of SSL/TLS which are supported by curl are listed [here](https://curl.haxx.se/libcurl/c/CURLOPT_SSLVERSION.html).

            ssl_verifypeer: <bool>  
            Verify all certicicates on the CA chian are recognizable to curl.

            ssl_verifyhost: <bool>  
            Verify the certificate's name against host.
            If the certificate cannot verify the host's name as it known, connection will fail.
            [Reference](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)

            tor_path: <string>  
            The working directory for the tor process.

            cookie: <string>
            The cookie string.

            cookie_path: <string>  
            The path of cookie file.
            
            redirect: <bool>  
            Allow the redirect or not.

        '''
        self.cUrl = None
        self.cookie   = cookie 
        self.redirect = redirect 
        self.keep_alive  = keep_alive
        self.res_headers = {}
        self.cookie_path = cookie_path
        self.ssl_version = ssl_version
        self.ssl_verifypeer = ssl_verifypeer
        self.ssl_verifyhost = ssl_verifyhost

        self.run_proxy(socks_port, control_port, proxy_host, exit_country_code, tor_path)
        self._init_cUrl()

    def _init_cUrl(self):
        '''_init_cUrl
        *description*  
            Prepare the curl for http operations.
            About security settings
        '''
        # Initialise the curl and its method to parse headers.
        # We only need to set the parse header function once.
        self.cUrl = pycurl.Curl()
        self.cUrl.setopt(pycurl.HEADER, True)
        self.cUrl.setopt(pycurl.HEADERFUNCTION, self._parse_header)

        # 20171228 Y.D.: Enable Keep-alive connection
        headers = [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.5',
            'Accept-Encoding: gzip, deflate'
        ]
        if self.keep_alive:
            headers.append('Connection: keep-alive')

        self.cUrl.setopt(pycurl.HTTPHEADER, headers)


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
        '''_parse_header
        *description*  
            The function is used to parse response's header line by line.

        *params*  
            header_line: <string>  
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
    
    def _set_proxy(self, removed_dns=False):
        '''_set_proxy
        *description*
            Set up the proxy server.
            Basically, the normal hostnames can be resolved locally;
            the hidden services, however, has to be resolved by socks server.

        *params*
            removed_dns: <bool>  
            removed_dns decides the hostname is to be resolved by socks server or locally.
            
        '''
        self.cUrl.setopt(pycurl.PROXY, self.proxy.host)
        if removed_dns:
            self.cUrl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
        else:
            self.cUrl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
        self.cUrl.setopt(pycurl.PROXYPORT, self.proxy.socks_port)

    def _get(self, url, removed_dns=False):
        '''_get
        *description*
            Use pycurl to do HTTP GET method.

        *params*
            url: <string>  
            Url you want to get.

            removed_dns: <bool>  
            The hostname should be resolved by socks server or not.
            True: The hostname has to be resolved by SOCKS server.
            False:  Hostname probably can be resolved locally.
        '''
        r = Response()
        b = BytesIO()

        self._set_proxy(removed_dns)
        self.cUrl.setopt(pycurl.URL, url)
        self.cUrl.setopt(pycurl.WRITEDATA, b)
        self.cUrl.perform()

        r.set_headers(self.res_headers)
        r.set_value(self.cUrl)
        r.decode_body(b.getvalue())
        
        return r

    def get(self, url):
        '''get
        *description*
            A GET HTTP method for non-hidden services.
        '''
        self.cUrl.setopt(
            pycurl.USERAGENT, 
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, \
            like Gecko) Chrome/62.0.3202.94 Safari/537.36')
        return self._get(url)

    def get_onion(self, onion_url):
        '''get_onion
        *description*
            Perfom GET method on onion service.

        *params*
            onion_url:
            An url of the hidden service. 
            The end of domain should be '.onion'.
        '''
        if ONION_RE.search(onion_url):
            # Simulate Tor's user agent
            self.cUrl.setopt(
                pycurl.USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0')
            return self._get(onion_url, True)
        else:
            print('The URL is not an onion. Please use get() instead')

    def _post(self, url, data, removed_dns=False):
        '''_post
        *description*
            Use pycurl to do HTTP POST method.

        *params*
            url: <string>  
            Post a certain data on an url.

            data: <dict>  
            The data that w

            removed_dns: <bool>  
            The hostname should be resolved by socks server or not.
            True: The hostname has to be resolved by SOCKS server.
            False:  Hostname probably can be resolved locally.            

        '''
        r = Response()
        b = BytesIO()
        post_data = []
        post_data.extend(trans_dict_to_tuple(data))
        self._set_proxy(removed_dns)
        self.cUrl.setopt(pycurl.URL, url)
        self.cUrl.setopt(pycurl.WRITEDATA, b)
        self.cUrl.setopt(pycurl.POST, 1)
        self.cUrl.setopt(pycurl.HTTPPOST, post_data)
        self.cUrl.perform()
        r.set_headers(self.res_headers)
        r.set_value(self.cUrl)
        r.decode_body(b.getvalue())
        
        return r

    def post(self, url, data={}):
        '''post
        *description*
            POST a new data to the server through the url.

        *params*
            url: <string>  
            The url to conduct HTTP POST method.

            data: <dict>  
            The data which is used to post form. 

        '''
        self.cUrl.setopt(
            pycurl.USERAGENT, 
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, \
            like Gecko) Chrome/62.0.3202.94 Safari/537.36')
        return self._post(url, data)

    def post_onion(self, onion_url, data={}):
        '''post_onion
        *description*
            Conduct a HTTP POST in the dark world

        *params*
            onion_url: <string>  
            The hidden service's url to do HTTP POST method.

            data: <dict>  
            The data which is used to post form.
        '''
        # Simulate Tor's user agent
        self.cUrl.setopt(
            pycurl.USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0')
        return self._post(onion_url, data, True)

    # def _head(self, url, removed_dns=False):
    #     '''_head
    #     *description*
    #         Perform GET operation with NOBODY request.

    #     *params*
    #         url: <string>  
    #         The url the head operation perform on.

    #         removed_dns: <bool>  
    #         The hostname should be resolved by socks server or not.
    #         True: The hostname has to be resolved by SOCKS server.
    #         False:  Hostname probably can be resolved locally.
    #     '''
    #     r = Response()
    #     b = BytesIO()
    #     self._set_proxy(removed_dns)
    #     self.cUrl.setopt(pycurl.CUSTOMREQUEST, 'HEAD')
    #     # self.cUrl.setopt(pycurl.NOBODY, True)
    #     self.cUrl.setopt(pycurl.WRITEDATA, b)
    #     self.cUrl.setopt(pycurl.URL, url)
    #     self.cUrl.perform()
    #     # self.cUrl.close()
    #     r.set_headers(self.res_headers)
    #     r.set_value(self.cUrl)
    #     r.body = ''
    #     return r

    # def head(self, url):
    #     '''head
    #     *description*
    #         Send a HTTP Head on the light url.
    #     *params*
    #         url: <string>  
    #     '''
    #     self.cUrl.setopt(
    #         pycurl.USERAGENT, 
    #         'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, \
    #         like Gecko) Chrome/62.0.3202.94 Safari/537.36')
    #     return self._head(url)

    # def head_onion(self, onion_url):
    #     '''head
    #     *description*
    #         Send a HTTP Head on the dark url.
    #     *params*
    #         url: <string>  
    #         The onion site you want to HEAD on.
    #     '''
    #     self.cUrl.setopt(
    #         pycurl.USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0')
    #     return self._head(onion_url, True)

    # def delete(self, url):
    #     '''delete
    #     *description*
    #         Send a delete request.
    #     *params*
    #         url: <string>  
    #         Where the delete request will be send to.
    #     '''
    #     pass

    # def delete_onion(self, onion_url):
    #     '''delete_onion
    #     *description*
    #         Send a delete request on an onion site.
    #     '''
    #     pass

    # 20171203 Y.D.: Move to tor.py
    # def terminate(self):
    #     '''terminate
    #     *description*
    #         End the tor process.
    #     '''
    #     self.tor_process.kill()
    #     pass

    
