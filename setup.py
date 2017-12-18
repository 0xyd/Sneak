from setuptools import setup

setup(name='sneak', 
	version='0.0.1', 
	description='Sneak is a URL transfer tool based on Tor technology.', 
	url='https://github.com/yudazilian/Sneak',
	author='yd',
	author_email='davisfreeman1015@gmail.com',
	license='Apache 2.0',
	packages=['sneak'],
	install_requires=[
		'stem',
		'pycurl'
	],
	zip_safe=False)