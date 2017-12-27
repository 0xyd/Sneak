from stem import Signal
from stem import CircStatus
from stem import process as tor_process
from stem.util import system, term
from stem.control import Controller
from stem.descriptor.networkstatus import Descriptor

from Tor  import Proxy, display
from Http import Session as HttpSession



class RouterTool():
	'''
	*descripton*
		Netool is used to check the Tor network's status
	'''
	def check_network(self, socks_port=9050, control_port=9051, proxy_host='localhost', exit_country_code='us', tor_path='tor_0'):
		'''
		*description*  
			Check the status of onion relays which are known currently.

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

        *return*  
        	router_stat: <dict>
        	The stat results of different types of relays and their statuses.  
			
			The Keys and the description of corresponding values are:  
				Guards: The list of Guard relays.  
				Fasts : The relays that are marked  
				HSDirs: v2 hidden service directories which are up for at least 25 hours.  
				Exits : 'Exit’ iff it allows exits to at least two of the ports 80, 443, and 6667 and allows exits to at least one /8 address space.  
				Nameds: Directory 
				Valids:   
				V2Dirs:   
				Stables:   
				Unnameds: The routers whose name are failed to map their identities.  
				Runnings: The authority managed to connect the routers to them successfully within the last 45 minutes   
				Authorites: The authorities are called "Authoritiy" if the authority generating the network-status document believes they are.
				Bandwiths : The bandwith the relay supports.  
				FingerPrints: The unique identity of the onion relay.  



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

			display(term.format(status.nickname,    term.Color.WHITE), term.format('Nickname',     term.Color.YELLOW))
			display(term.format(status.fingerprint, term.Color.WHITE), term.format('FingerPrint',  term.Color.YELLOW))
			display(term.format(status.address,     term.Color.WHITE), term.format('Address',      term.Color.YELLOW))
			display(term.format(str(status.published), term.Color.WHITE), term.format('Published', term.Color.YELLOW))
			display(term.format(str(status.or_port),   term.Color.WHITE), term.format('OR Port',   term.Color.YELLOW))
			display(term.format(str(status.dir_port),  term.Color.WHITE), term.format('DIR Port',  term.Color.YELLOW))
			display(term.format(str(status.bandwidth), term.Color.WHITE), term.format('Bandwidth', term.Color.YELLOW))
			display(term.format(str(status.document),  term.Color.WHITE), term.format('Document',  term.Color.YELLOW))
			display(term.format(', '.join(status.flags), term.Color.WHITE), term.format('Relay Flags', term.Color.YELLOW))
			display('')

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
		*description*  
			Select n guards node with highest bandwidth.  

		*params*  
			router_stat: <dict>  
			The stat of router produced by check_network function.

			n: <int>  
			The number of guards user want to choose. Must greater or equal to 1.
			The default value is 1.

		*return*  
			guard_nodes: <list>  
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
	# 	*description*
	# 		Scan the relays on the onion network.
	# 	'''
	# 	http_session = HttpSession(socks_port=socks_port, control_port=control_port, 
	# 		proxy_host=proxy_host, exit_country_code=exit_country_code, tor_path=tor_path)
	# 	pass


