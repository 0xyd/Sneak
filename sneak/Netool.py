'''
	## Netool
	Netool is the collection of different network utilities.
'''
import re
import subprocess
from collections import OrderedDict as odict

from stem import Signal
from stem import CircStatus
from stem import process as tor_process
from stem.util import system, term
from stem.control import Controller
from stem.descriptor.networkstatus import Descriptor

from Tor  import Proxy, display_msg, MESSAGE_FLAGS_AND_COLOR
from Http import Session as HttpSession


class Router():
	'''
	### Router
	Router is used to analysis the status of Tor's relays(roters).  

	'''
	def __init__(self, proxy):
		self.proxy = proxy
		self.relay_table = odict()
		self.relay_types = odict()
		self.circuits = odict()

		# 20180302 Y.D.
		self._access_network_status()
		self._access_circuits()

	def get_relay(self, fingerprint):
		if fingerprint in self.relay_table:
			return self.relay_table[fingerprint]
		else:
			error_msg = '{} does not exist'.format(fingerprint)
			display_msg(error_msg, 'ERROR')

	def get_relay_table(self):
		return self.relay_table

	def get_relays_by_type(self, rtype='Running'):
		'''
		#### Router.get_relays_by_type
		***description***  
			Get the relays of specific types.  
		***params***  
			* rtpye: < string >  
			The type of relays user want to get.  
			
		'''
		relay_type_names = set([
            'Guard', 'Fast', 'HSDir', 'Exit', 'Named', 
            'Valid', 'V2Dir', 'Stable', 'Unnamed', 'Running', 'Authority'])

		# Authority has different grammer on plural.
		if rtype == 'Authority':
			rtype = 'Authorities'
		elif rtype in relay_type_names:
			rtype = rtype + 's'
		else:
			error_msg = 'Invalid type name: {}, Please use {} instead.'.format(
				rtype, ', '.join(relay_type_names))
			display_msg(error_msg, 'ERROR')
			return []			

		relays_generator = ( 
			{ footprint: self.relay_table[footprint] } for footprint in self.relay_types[rtype] )
		return list(relays_generator)

	def get_circuits(self):
		return self.circuits

	def _access_network_status(self):
		'''_
		#### _access_network_status
		***description***  
			Check the status of onion relays which are known currently.

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

				* Authorities: The authorities are called "Authoritiy" if the authority generating the network-status document believes they are.  

				* Bandwiths: The bandwith the relay supports.  

				* FingerPrints: The unique identity of the onion relay.  

		_'''
		self.relay_types = {
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
			'Authorities': [],
		}

		for status in self.proxy.controller.get_network_statuses():

			self.relay_table.update({
				status.fingerprint: {
					'nickname'   : status.nickname,
					'address'    : status.address,
					'published'  : status.published,
					'or_port'    : status.or_port,
					'dir_port'   : status.dir_port,
					'bandwidth'  : status.bandwidth,
					'document'   : status.document,
					'flags': status.flags
			}})

			# 20180227 Y.D.: Store the fingerprint instead.
			if 'Fast'  in status.flags:
				self.relay_types['Fasts'].append(status.fingerprint)
			if 'Guard' in status.flags:
				self.relay_types['Guards'].append(status.fingerprint)
			if 'HSDir' in status.flags:
				self.relay_types['HSDirs'].append(status.fingerprint)
			if 'Exist' in status.flags:
				self.relay_types['Exists'].append(status.fingerprint)
			if 'Named' in status.flags:
				self.relay_types['Nameds'].append(status.fingerprint)
			if 'Valid' in status.flags:
				self.relay_types['Valids'].append(status.fingerprint)
			if 'V2Dir' in status.flags:
				self.relay_types['V2Dirs'].append(status.fingerprint)
			if 'Stable' in status.flags:
				self.relay_types['Stables'].append(status.fingerprint)
			if 'Unnamed' in status.flags:
				self.relay_types['Unnameds'].append(status.fingerprint)
			if 'Running' in status.flags:
				self.relay_types['Runnings'].append(status.fingerprint)
			if 'Authority' in status.flags:
				self.relay_types['Authorities'].append(status.fingerprint)

		return self.relay_types

	# 20180302 Y.D.
	def _access_circuits(self):
		'''_
		#### _access_circuits

		_'''

		for circuit in self.proxy.get_circuits():
			if circuit.status != CircStatus.BUILT:
				continue

			self.circuits[circuit.id] = {
				'purpose': circuit.purpose,
				'paths'  : [] 
			}  
			
			for path in circuit.path:
				fingerprint, nickname = path
				relay = self.relay_table[fingerprint]
				self.circuits[circuit.id]['paths'].append({fingerprint: relay})

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

	def list_relays(self, top=100):
		'''
		#### Router.list_relays(top) 
		***description***  

		***params***  

		'''
		i = 0
		color = MESSAGE_FLAGS_AND_COLOR['RELAY_INFO']
		for fingerprint, relay_meta in self.relay_table.items():
			display_msg('\n' + fingerprint, 'RELAY_INFO')
			display_msg(term.format('Nickname: ' + relay_meta['nickname'], color))
			display_msg(term.format('Address: ' + relay_meta['address'],  color),)
			display_msg(term.format('Published: ' + str(relay_meta['published']), color))
			display_msg(term.format('OR Port: ' + str(relay_meta['or_port']),  color))
			display_msg(term.format('DIR Port:' + str(relay_meta['dir_port']), color))
			display_msg(term.format('Bandwidth: ' + str(relay_meta['bandwidth']), color))
			display_msg(term.format('Document: '  + str(relay_meta['document']),  color))
			display_msg(term.format('Relay Flags: ' + ', '.join(relay_meta['flags']), color))
			display_msg('-'*20)

			i += 1
			if i == top:
				break

	def list_circuits(self):
		'''
		#### Router.list_circuits()
		***description***  


		'''
		for circuit_id, circuit_dict in self.circuits.items():
			circuit_meta = 'Circuit %s (%s)' % (circuit_id, circuit_dict['purpose'])
			circuit_meta = term.format(circuit_meta, term.Color.GREEN)
			display_msg(circuit_meta, 'INFO')
			circuit_len = len(circuit_dict['paths'])

			for i, relay in enumerate(circuit_dict['paths']):
				(relay_id, relay_val), = relay.items()
				div = '+' if i == circuit_len-1 else '|'
				div_and_fingerprint  = '%s- %s' % (div, relay_id)
				div_and_fingerprint  = term.format(div_and_fingerprint, term.Color.YELLOW)
				nickname_and_address = '(%s, %s)' % (relay_val['nickname'], relay_val['address'])
				nickname_and_address = term.format(nickname_and_address, term.Color.YELLOW)

				detail_message =  '  |---'
				detail_message += 'Bandwidth: %s ' % relay_val['bandwidth']
				detail_message += 'Flags: %s' % ','.join(relay_val['flags'])
				detail_message = term.format(detail_message, term.Color.MAGENTA)
				display_msg('%s %s\n%s' % (
					div_and_fingerprint, nickname_and_address, detail_message))

	def sniff(self, interface=None):
		'''
		#### Router.sniff() 
		***description***  
		


		***params***  

		'''
		# 20180304 Y.D.
		# Get the active interface first
		if interface is None:
			ifconfig_ps = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE)
			ifconfig = []
			for line in ifconfig_ps.stdout:
				ifconfig.append(line.decode('utf8'))
			ifconfig = ''.join(ifconfig)
			ifconfig_ps.stdout.close()
			interface = re.search(
				r"(?P<name>en[^\t\:])+:([^\n]|\n\t)*status: active", ifconfig).group('name')
		
		entry_addresses = set()
		for _, circuit in self.circuits.items():			
			addr = circuit['paths'][0]['address']
			entry_addresses.add(addr)

		procs = []
		for addr in entry_addresses:
			pc = subprocess.Popen(['tcpdump', '-i', interface, 'dst', '-vv'], stdout)



# 20170224 Y.D.
from sneak.Tor import ProxyChain

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
				host_name = line[21:].strip('\n')
			elif 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
				start_port_info = True
			elif 'Nmap done' in line:
				start_port_info = False
			elif start_port_info and len(line) > 1:
				line = (l.strip(' |\n') for l in line.split(' '))
				line = (l for l in list(line) if len(l) > 1)
				service_ports.append(list(line))

		return { 'host': host_name, 'services': service_ports }

	def scan(self, host, ports=[80, 443], timeout=30):
		'''
		#### scan
		***description***  

		***params*** 

		'''

		ports = (str(p) for p in ports)
		ports = ','.join(list(ports))
		cmd = ['proxychains4', '-f', self.config, 'nmap', '-n', '-PS', '-sT', '-p']

		# 20180227 Y.D. If there is no proxies available...
		if not self.is_proxychain_available():
			return

		if hostname_regex.search(host):
			cmd.extend([ports, host])
		else:
			error_flag = term.format('FAILED', term.Color.RED)
			error_msg  = 'Invalid host name or address: {}'.format(host)
			error_msg  = term.format(error_msg, term.Color.RED)
			display_msg(error_msg, error_flag)
			return
		
		scan = subprocess.Popen(cmd, stdout=subprocess.PIPE)
		return self._parse_scan_result(scan.stdout)
		
	















