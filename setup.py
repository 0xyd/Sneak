from setuptools import setup, find_packages

setup(name='sneak', 
	# version='0.0.8', # For test
	version='0.1.0',
	description='Sneak is a URL transfer tool based on Tor technology.', 
	url='https://github.com/yudazilian/Sneak',
	author='yd',
	author_email='davisfreeman1015@gmail.com',
	license='Apache 2.0',
	packages=find_packages(),
	install_requires=[
		'stem',
		'pycurl'
	],
	keywords='curl tor http',
	zip_safe=False)