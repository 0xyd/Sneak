import re
import os
import sys
import time
import random
import string
import hashlib
import subprocess

from stem import Signal
from stem import CircStatus
from stem import process as tor_process
from stem.util import system, term
from stem.control import Controller

HASHCODE_RE = re.compile(r'(?P<code>16:\w{20,})\n?')

# 20180226
TOR_COUNTRY_CODE = [
	'us', 'tw', 'jp', 'ru', 
	'de', 'uk', 'ch', 'se', 
	'kr', 'ir', 'is', 'ir', 
	'nl', 'be', 'fr', 'ca'
]

# 20180227 Y.D.
MESSAGE_FLAGS_AND_COLOR = {
	'FAILED' : term.Color.RED,
	'ERROR'  : term.Color.RED,
	'INFO'   : term.Color.CYAN,
	'UPDATE'  : term.Color.YELLOW,
	'WARNING' : term.Color.YELLOW,
	'FINISHED': term.Color.GREEN,
	'STARTING': term.Color.GREEN,
	'RELAY_INFO': term.Color.MAGENTA
}

def print_bootstrap_lines(line):
	if "Bootstrapped " in line:
		# line = term.format(line, term.Color.GREEN)
		display_msg(line, 'STARTING')

def seed():
	'''seed
	*description*  
		The function is used to generate seed for hash password.
		It produces a short hash with length 10.
	'''
	chars = string.ascii_letters + string.digits
	seed  = '-'.join(chars[random.randint(0, len(chars)-1)] for i in range(10))
	return seed

def display_msg(msg, flag=''):
# def display_msg(msg, flag=None):
	'''display_msg
	*description*  
		Display the processing message of the process.
	'''
	if flag:
		color = MESSAGE_FLAGS_AND_COLOR[flag]
		flag  = '[{}]'.format(flag)
		msg   = term.format(msg,  color)
		flag  = term.format(flag, color)
		msg   = '{} {}\n'.format(flag, msg)
		sys.stdout.write(msg)
	else:
		sys.stdout.write(msg+'\n')

	# if flag:
	# 	message = '[{0}] {1} \n'.format(flag, msg)
	# else:
	# 	message = '{0} \n'.format(msg)
	# sys.stdout.write(message)

class Proxy():

	def __init__(
		self, socks_port=9050, control_port=9051, 
		proxy_host='127.0.0.1', exit_country_code='us', tor_path='tor_0', name=''):
		'''__init__
		***description***   
			Initialise a Proxy server.

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
			
			name: < string >


		'''
		self.process  = None
		self.tor_path = tor_path
		self.controller = None
		self.hashcode = None
		self.host = proxy_host
		self.socks_port   = socks_port
		self.control_port = control_port
		self.exit_country_code = exit_country_code

		# 20180227 Y.D.
		if name:
			self.name = name
		else:
			timestamp = str(time.time()).encode('utf8')
			self.name = hashlib.md5(timestamp).hexdigest()[:8]

	def run(self, timeout=60):
		'''
		#### run
		***description***  
			Run tor as the proxy server.
		'''
		# seed = ''.join(self._seed_generator())
		hashcode = subprocess.check_output(['tor', '--hash-password', seed()])
		self.hashcode = HASHCODE_RE.search(hashcode.decode('utf-8')).group('code')

		# 20180227 Y.D. Add Error Handler.
		try:
			self.process  = tor_process.launch_tor_with_config(
				config={
					'SocksPort': [self.socks_port],
					'ControlPort': [self.control_port],
					'HashedControlPassword': self.hashcode,
					'CookieAuthentication': '1',
					'DataDirectory': self.tor_path,
					'ExitNodes': '{%s}' % self.exit_country_code
				},
				init_msg_handler=print_bootstrap_lines,
				timeout=timeout
			)
		except Exception as e:
			e = '{}'.format(e)
			display_msg(e, 'FAILED')

	def auth_controller(self):
		'''auth_controller
		*description*  
        	Initial a tor proxy controller  
		'''
		self.controller = Controller.from_port(port=self.control_port)
		self.controller.authenticate(password=self.hashcode)
    	
	def renew_identity(self):
		'''renew_identity
		*description*  
			According to the official document, user's identity is defined by three-hop service.
			Once renew_identity is performed, process will request tor for a new identity.
			However, the renew operation does not mean it will always provide new ip addresses.
			It is quite common to see the exit nodes used previously.
		
			[WARNING] 
			Please do not use this function too frequently 
			because it will cause a huge burden on Tor.
		'''
		self.auth_controller()
		self.controller.signal(Signal.NEWNYM)
		display_msg('Renewing the identity...',   'UPDATE')
		time.sleep(self.controller.get_newnym_wait())
		display_msg('Identity has been renewed.', 'FINISHED')

	def terminate(self):
		'''terminate
		*description*  
			End the tor process. Before the Tor relay is killed, display how many bytes our relay is read or written. 
		'''

		bytes_read    = self.controller.get_info('traffic/read')
		bytes_written = self.controller.get_info('traffic/written')
		bytes_read    = 'Our Relay has read %s bytes'    % bytes_read
		bytes_written = 'Our Relay has written %s bytes' % bytes_written

		display_msg('Tor is terminating...', 'INFO')
		display_msg(bytes_read, 'INFO')
		display_msg(bytes_written, 'INFO')
		self.process.kill()
		display_msg('Tor is terminated sucessfully!', 'INFO')

	def get_circuits(self):
		'''get_circuits
		*description*
			List all available circuits.

		'''
		return sorted((self.controller.get_circuits()))
		# for circuit in sorted(self.controller.get_circuits()):
		# 	if circuit.status != CircStatus.BUILT:
		# 		continue

		# 	circuit_meta = 'Circuit %s (%s)' % (circuit.id, circuit.purpose)
		# 	circuit_meta = term.format(circuit_meta, term.Color.GREEN)
		# 	display_msg(circuit_meta, 'INFO')

		# 	for i, entry in enumerate(circuit.path):
		# 		div = '+' if (i == len(circuit.path)-1) else '|'
		# 		fingerprint, nickname = entry
		# 		desciption = self.controller.get_network_status(fingerprint, None)
		# 		address    = desciption.address if desciption else 'unknown'
		# 		nickname_and_address = '(%s, %s)' % (nickname, address)
		# 		nickname_and_address = term.format(nickname_and_address, term.Color.WHITE)
		# 		div_and_fingerprint  = '%s - %s' % (div, fingerprint)
		# 		div_and_fingerprint  = term.format(div_and_fingerprint, term.Color.YELLOW)
		# 		display_msg('%s %s' % (div_and_fingerprint, nickname_and_address))

	# 20171225 Y.D. TODO:
	def customize_circuit(self, path, purpose='general'):
		'''
		*description*
			Build a new circuit.

		*params*
			path: < list >    
			

		'''
		self.controller.new_circuit(path=path, purpose=purpose)
		print(self.controller.get_info('circuit-status'))

# 20180226 Y.D. 
class ProxyChain():

	def __init__(self, num_proxy=3):
		
		self.prepared_proxies = []
		self.proxies = []
		socks_port   = 9050
		control_port = 9051

		tor_num = 0
		while True:
			rand_i = random.randint(0, len(TOR_COUNTRY_CODE)-1)
			code = TOR_COUNTRY_CODE[rand_i]
			tor_path = 'tor_{}'.format(tor_num)

			# To prevent port collision and lock
			p = Proxy(
				socks_port=socks_port, control_port=control_port, 
				tor_path=tor_path, exit_country_code=code)
			self.prepared_proxies.append(p)
			
			socks_port += 100
			control_port += 100
			tor_num += 1

			if tor_num == num_proxy:
				break

	def is_proxychian_available(self):
		if len(self.proxies) == 0:
			error_msg = \
				'No Proxy is able to be chained. Maybe they do not start successfully.\n'
			display_msg(error_msg, 'ERROR')
			# error_msg  = term.format(error_msg, term.Color.RED)
			# error_flag = term.format('FAILED',  term.Color.RED)
			return False
		else:
			return True
		
	def write_config(self, 
		proxychain_config='_proxycluster.config', 
		proxychain_read_timeout=15000, 
		proxychain_connect_timeout=8000):

		if not self.is_proxychian_available():
			return

		self.config = proxychain_config
		# Note: Proxychains-ng's config is here: /usr/local/etc/proxychains.conf, take it as reference.
		proxychain_config = open(proxychain_config, 'w')
		proxychain_config.write('random_chain\n')
		proxychain_config.write('proxy_dns\n')
		proxychain_config.write('remote_dns_subnet 224\n')
		proxychain_config.write('tcp_read_time_out %d \n' % proxychain_read_timeout)
		proxychain_config.write('tcp_connect_time_out %d \n' % proxychain_connect_timeout)

		# List all tor proxies
		proxychain_config.write('[ProxyList]\n')
		for proxy in self.proxies:
			proxychain_config.write('socks5 %s %d \n' % (proxy.host, proxy.socks_port))
		
		proxychain_config.close()

	def run(self):

		restart_proxies = []

		while True:
			proxy = self.prepared_proxies.pop()
			try:
				proxy.run()
				proxy.auth_controller()
				self.proxies.append(proxy)
			except Exception as e:
				error_msg = \
					'{}.\nTor Proxy {} does not run successfully. Restart Later.'.format(e, proxy.name)
				# error_msg    = term.format(error_msg, term.Color.YELLOW)
				# warning_flag = term.format('WARNING', term.Color.YELLOW)
				restart_proxies.append(proxy)
				display_msg(error_msg, 'WARNING')

			if len(self.prepared_proxies) == 0:
				break
		# for i, proxy in enumerate(self.prepared_proxies):
		# 	try:
		# 		proxy.run()
		# 		proxy.auth_controller()
		# 		self.proxies.append(proxy)
		# 	except Exception as e:
		# 		error_msg = \
		# 			'{}.\nTor Proxy {} does not run successfully. Restart Later.'.format(e, i)
		# 		error_msg = term.format(error_msg, term.Color.YELLOW)
		# 		warning_flag = term.format('WARNING', term.Color.YELLOW) 
		# 		restart_proxies.append({'number': i, 'proxy': self.prepared_proxies[i]})
		# 		display_msg(error_msg, warning_flag)

		# Restart the proxy which is failed in the first beginning
		for p in restart_proxies:
			try:
				proxy = restart_proxies.pop()
				proxy.run()
				proxy.auth_controller()
				self.proxies.append(proxy)
				# p['proxy'].run()
				# p['proxy'].auth_controller()
				# self.proxies.append(p['proxy'])
			except Exception as e:
				error_msg = \
					'{}.\nTor Proxy {} does not restart successfully. Check your network setting'\
						.format(e, p.name)
				display_msg(error_msg, 'FAILED')
				# error_msg  = term.format(error_msg, term.Color.RED)
				# error_flag = term.format('FAILED',  term.Color.RED)
				# display_msg(error_msg, error_flag)

	def terminate(self):
		for proxy in self.proxies:
			proxy.terminate()
		os.remove(self.config)
		
	






	