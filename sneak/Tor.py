import re
import sys
import time
import random
import string
import subprocess

from stem import Signal
from stem import CircStatus
from stem import process as tor_process
from stem.util import system, term
from stem.control import Controller

HASHCODE_RE = re.compile(r'(?P<code>16:\w{20,})\n?')

def print_bootstrap_lines(line):
	if "Bootstrapped " in line:
		line = term.format(line, term.Color.GREEN)
		display_msg(line)
		# print(term.format(line, term.Color.GREEN))

def seed():
	'''seed
	*description*  
		The function is used to generate seed for hash password.
		It produces a short hash with length 10.
	'''
	chars = string.ascii_letters + string.digits
	seed  = '-'.join(chars[random.randint(0, len(chars)-1)] for i in range(10))
	return seed

def display_msg(msg_context, msg_type=None):
	'''display_msg
	*description*  
		Display the processing message of the process.
	'''
	if msg_type:
		message = '[{0}] {1} \n'.format(msg_type, msg_context)
	else:
		message = '{0} \n'.format(msg_context)
	sys.stdout.write(message)

class Proxy():

	def __init__(
		self, socks_port=9050, control_port=9051, 
		proxy_host='localhost', exit_country_code='us', tor_path='tor_0'):
		'''__init__
		*description*   
			Initialise a Proxy server.

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
		'''
		self.process  = None
		self.tor_path = tor_path
		self.controller = None
		self.hashcode = None
		self.host = proxy_host
		self.socks_port   = socks_port
		self.control_port = control_port
		self.exit_country_code = exit_country_code

	def run(self):
		'''run
		*description*  
			Run tor as the proxy server.
		'''
		# seed = ''.join(self._seed_generator())
		hashcode = subprocess.check_output(['tor', '--hash-password', seed()])
		self.hashcode = HASHCODE_RE.search(hashcode.decode('utf-8')).group('code')
		self.process  = tor_process.launch_tor_with_config(
			config={
				'SocksPort': [self.socks_port],
				'ControlPort': [self.control_port],
				'HashedControlPassword': self.hashcode,
				'CookieAuthentication': '1',
				'DataDirectory': self.tor_path,
				'ExitNodes': '{%s}' % self.exit_country_code
			},
			init_msg_handler=print_bootstrap_lines
        )

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
		display_msg('Renewing the identity...',   'Update')
		time.sleep(self.controller.get_newnym_wait())
		display_msg('Identity has been renewed.', 'Finished')

	def terminate(self):
		'''terminate
		*description*  
			End the tor process. Before the Tor relay is killed, display how many bytes our relay is read or written. 
		'''

		bytes_read    = self.controller.get_info('traffic/read')
		bytes_written = self.controller.get_info('traffic/written')
		start_info    = term.format('Tor is terminating...', term.Color.CYAN)
		end_info      = term.format('Tor is terminated sucessfully!', term.Color.CYAN)
		bytes_read    = term.format('Our Relay has read %s bytes'    % bytes_read, term.Color.YELLOW)
		bytes_written = term.format('Our Relay has written %s bytes' % bytes_written, term.Color.YELLOW)
		display_msg(start_info, 'Info')
		display_msg(bytes_read, 'Info')
		display_msg(bytes_written, 'Info')
		self.process.kill()
		display_msg(end_info, 'Info')

	def list_circuits(self):
		'''list_circuits
		*description*
			List all available circuits.

		'''
		for circuit in sorted(self.controller.get_circuits()):
			if circuit.status != CircStatus.BUILT:
				continue

			circuit_meta = 'Circuit %s (%s)' % (circuit.id, circuit.purpose)
			circuit_meta = term.format(circuit_meta, term.Color.GREEN)
			display_msg(circuit_meta, 'Info')
			# print(circuit_meta)

			for i, entry in enumerate(circuit.path):
				div = '+' if (i == len(circuit.path)-1) else '|'
				fingerprint, nickname = entry
				desciption = self.controller.get_network_status(fingerprint, None)
				address    = desciption.address if desciption else 'unknown'
				nickname_and_address = '(%s, %s)' % (nickname, address)
				nickname_and_address = term.format(nickname_and_address, term.Color.WHITE)
				div_and_fingerprint  = '%s - %s' % (div, fingerprint)
				div_and_fingerprint  = term.format(div_and_fingerprint, term.Color.YELLOW)
				display_msg('%s %s' % (div_and_fingerprint, nickname_and_address))
				# print('%s %s' % (div_and_fingerprint, nickname_and_address))

	# 20171225 Y.D. TODO:
	def customize_circuit(self, path, purpose='general'):
		'''
		*description*
			Build a new circuit.

		*params*
			path: <list>  
			

		'''
		self.controller.new_circuit(path=path, purpose=purpose)
		print(self.controller.get_info('circuit-status'))





	