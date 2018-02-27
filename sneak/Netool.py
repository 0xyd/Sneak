'''
	## Netool
	Netool is the collection of different network utilities.
'''
from stem import Signal
from stem import CircStatus
from stem import process as tor_process
from stem.util import system, term
from stem.control import Controller
from stem.descriptor.networkstatus import Descriptor

from Tor  import Proxy, display_msg
from Http import Session as HttpSession


class RouterTool():
	'''
	### RouterTool
	RouterTool is used to analysis the status of Tor's relays(roters).  

	'''
	def check_network(self, socks_port=9050, control_port=9051, proxy_host='localhost', exit_country_code='us', tor_path='tor_0'):
		'''
		#### check_network
		***description***  
			Check the status of onion relays which are known currently.

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

        ***return***  
        	router_stat: < dict >
        	The stat results of different types of relays and their statuses.  
			
			The Keys and the description of corresponding values are:  
				* Guards: The list of Guard relays.  

				* Fasts : The relays that are marked   

				* HSDirs: v2 hidden service directories which are up for at least 25 hours.  

				* Exits : 'Exit’ iff it allows exits to at least two of the ports 80, 443, and 6667 and allows exits to at least one /8 address space.  

				* Nameds: Directory  

				* Valids: A relay that runs a version of Tor that is not broken.   

				* V2Dirs: A router supports the v2 directory protocol if it has an open directory port and serving the directory protocol that clients need.  

				* Stables: The relays's MTBT(Mean Time Between Failure) is at least the median for all known routers or its weighted MTBF is 7 days at least.  

				* Unnameds: The routers whose name are failed to map their identities.  

				* Runnings: The authority managed to connect the routers to them successfully within the last 45 minutes   

				* Authorites: The authorities are called "Authoritiy" if the authority generating the network-status document believes they are.  

				* Bandwiths: The bandwith the relay supports.  

				* FingerPrints: The unique identity of the onion relay.  

		'''
		proxy = Proxy(socks_port=socks_port, control_port=control_port, 
			proxy_host=proxy_host, exit_country_code=exit_country_code, tor_path=tor_path)
		proxy.run()
		proxy.auth_controller()

		router_stat = {
			'Guards': [],
			'Fasts' : [],
			'HSDirs': [],
			'Exits' : [],
			'Nameds': [],
			'Valids': [],
			'V2Dirs': [],
			'Stables'   : [],
			'Unnameds'  : [],
			'Runnings'  : [],
			'Authorites': [],
			'Bandwiths' : [],
			'FingerPrints': []
		}

		router_index = 0

		for status in proxy.controller.get_network_statuses():

			display_msg(term.format(status.nickname,    term.Color.WHITE), term.format('Nickname',     term.Color.YELLOW))
			display_msg(term.format(status.fingerprint, term.Color.WHITE), term.format('FingerPrint',  term.Color.YELLOW))
			display_msg(term.format(status.address,     term.Color.WHITE), term.format('Address',      term.Color.YELLOW))
			display_msg(term.format(str(status.published), term.Color.WHITE), term.format('Published', term.Color.YELLOW))
			display_msg(term.format(str(status.or_port),   term.Color.WHITE), term.format('OR Port',   term.Color.YELLOW))
			display_msg(term.format(str(status.dir_port),  term.Color.WHITE), term.format('DIR Port',  term.Color.YELLOW))
			display_msg(term.format(str(status.bandwidth), term.Color.WHITE), term.format('Bandwidth', term.Color.YELLOW))
			display_msg(term.format(str(status.document),  term.Color.WHITE), term.format('Document',  term.Color.YELLOW))
			display_msg(term.format(', '.join(status.flags), term.Color.WHITE), term.format('Relay Flags', term.Color.YELLOW))
			display_msg('')

			router_stat['FingerPrints'].append(status.fingerprint)
			router_stat['Bandwidths'].append(status.bandwidth)

			if 'Fast'  in status.flags:
				router_stat['Fasts'].append(router_index)
			if 'Guard' in status.flags:
				router_stat['Guards'].append(router_index)
			if 'HSDir' in status.flags:
				router_stat['HSDirs'].append(router_index)
			if 'Exist' in status.flags:
				router_stat['Exists'].append(router_index)
			if 'Named' in status.flags:
				router_stat['Nameds'].append(router_index)
			if 'Valid' in status.flags:
				router_stat['Valids'].append(router_index)
			if 'V2Dir' in status.flags:
				router_stat['V2Dirs'].append(router_index)
			if 'Stable' in status.flags:
				router_stat['Stables'].append(router_index)
			if 'Unnamed' in status.flags:
				router_stat['Unnameds'].append(router_index)
			if 'Running' in status.flags:
				router_stat['Runnings'].append(router_index)
			if 'Authority' in status.flags:
				router_stat['Authorites'].append(router_index)

			router_index += 1

		proxy.terminate()

		return router_stat

	def select_ntop_guards(self, router_stat, n=1):
		'''
		#### select_ntop_guards
		***description***  
			Select n guards node with highest bandwidth.  

		***params***  
			router_stat: < dict >  
			The stat of router produced by check_network function.

			n: < int >, default n is 1.  
			The number of guards user want to choose. Must greater or equal to 1.

		***return***  
			guard_nodes: < list >  
			Return the guards which have top n highest bandwidth.  

		'''
		guard_and_bandwidth = [ 
			{
				'guard_fingerprint': router_stat['FingerPrints'][i], 
				'bandwidth': router_stat['Bandwidths'][i]
			} for i, bandwidth in enumerate(router_stat['Bandwidths']) 
				if i in set(router_stat['Guards']) 
		] 
		guard_and_bandwidth.sort(key=lambda x: x['bandwidth'], reverse=True)
		guard_nodes = [ g['guard_fingerprint'] for g in guard_and_bandwidth ]
		return guard_nodes[:n]



	# def scan(self):
	# 	'''
	# 	***description***
	# 		Scan the relays on the onion network.
	# 	'''
	# 	http_session = HttpSession(socks_port=socks_port, control_port=control_port, 
	# 		proxy_host=proxy_host, exit_country_code=exit_country_code, tor_path=tor_path)
	# 	pass


# 20170224 Y.D.
import re
import subprocess

from sneak.Tor import ProxyChain

# ip_re = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

# 20180227 Y.D.: Wonderful Url Validate in regular expression
ip_middle_octet = u"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5]))"
ip_last_octet   = u"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))"
hostname_regex  = re.compile(
    u"^"
    # protocol identifier
    # u"(?:(?:https?|ftp)://)"
    # user:pass authentication
    u"(?:[-a-z\u00a1-\uffff0-9._~%!$&'()*+,;=:]+"
    u"(?::[-a-z0-9._~%!$&'()*+,;=:]*)?@)?"
    u"(?:"
    u"(?P<private_ip>"
    # IP address exclusion
    # private & local networks
    u"(?:(?:10|127)" + ip_middle_octet + u"{2}" + ip_last_octet + u")|"
    u"(?:(?:169\.254|192\.168)" + ip_middle_octet + ip_last_octet + u")|"
    u"(?:172\.(?:1[6-9]|2\d|3[0-1])" + ip_middle_octet + ip_last_octet + u"))"
    u"|"
    # private & local hosts
    u"(?P<private_host>"
    u"(?:localhost))"
    u"|"
    # IP address dotted notation octets
    # excludes loopback network 0.0.0.0
    # excludes reserved space >= 224.0.0.0
    # excludes network & broadcast addresses
    # (first & last IP address of each class)
    u"(?P<public_ip>"
    u"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
    u"" + ip_middle_octet + u"{2}"
    u"" + ip_last_octet + u")"
    u"|"
    # host name
    u"(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)"
    # domain name
    u"(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*"
    # TLD identifier
    u"(?:\.(?:[a-z\u00a1-\uffff]{2,}))"
    u")"
    # port number
    u"(?::\d{2,5})?"
    # resource path
    u"(?:/[-a-z\u00a1-\uffff0-9._~%!$&'()*+,;=:@/]*)?"
    # query string
    u"(?:\?\S*)?"
    # fragment
    u"(?:#\S*)?"
    u"$",
    re.UNICODE | re.IGNORECASE
)


class NetMapMixin(ProxyChain):

	def __init__(self, num_proxy=3):
		super().__init__()

	def start_proxychain(self, 
		proxychains_config='_proxychains.config', 
		proxychains_read_timeout=15000, proxychains_connect_timeout=8000):
		self.run()
		self.write_config(
			proxychains_config, proxychains_read_timeout, proxychains_connect_timeout)

class NetMap(NetMapMixin):

	def __init__(self, num_proxy=3,
		proxychains_config='_proxychains.config', 
		proxychains_read_timeout=15000, proxychains_connect_timeout=8000):
		super().__init__()
		self.start_proxychain(
			proxychains_config, proxychains_read_timeout, proxychains_connect_timeout)
		
	def _parse_scan_result(self, scan_stdout):
		host_name = None
		service_ports   = []
		start_port_info = False

		for line in scan_stdout:
			line = line.decode('utf-8')
			if 'Nmap scan report for ' in line:
				host_name = line[22]
			elif 'PORT    STATE  SERVICE' in line:
				start_port_info = True
			elif start_port_info:
				line = (l.strip(' |\n') for l in line.split(' '))
				line = (l for l in list(line) if len(l) > 0)
				service_ports.append(list(line))
			elif start_port_info and len(line) <= 1:
				start_port_info = False

		return { 'host': host_name, 'services': service_ports }

	def scan(self, host, ports=[80, 443], timeout=30):

		ports = (str(p) for p in ports)
		ports = ','.join(list(ports))
		cmd = ['proxychains4', '-f', self.config, 'nmap', '-n', '-PS', '-sT', '-p']
		if hostname_regex.search(host):
			cmd.extend([ports, host])
		else:
			error_flag = term.format('FAILED', term.Color.RED)
			error_msg  = 'Invalid host name or address: {}'.format(host)
			error_msg  = term.format(error_msg, term.Color.RED)
			display_msg(error_msg, error_flag)
		
		scan = subprocess.Popen(cmd, stdout=subprocess.PIPE)
		return self._parse_scan_result(scan.stdout)
		
	















