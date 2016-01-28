#!/usr/bin/env python

# Imports
from __future__ import with_statement
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import os.path

# Version
version_file = os.path.join(os.path.dirname(__file__), 'vxi11', 'version.py')
version_dict = {}
execfile(version_file, version_dict)
version = version_dict['__version__']

# Long description
long_description = """\
This Python package supports the VXI-11 Ethernet instrument control protocol
for controlling VXI11 and LXI compatible instruments.
"""

# Classifiers
classifiers = """\
Development Status :: 4 - Beta
Environment :: Console
License :: OSI Approved :: MIT License
Natural Language :: English
Operating System :: OS Independent
Intended Audience :: Science/Research
Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator
Topic :: Software Development :: Libraries :: Python Modules
Topic :: System :: Hardware :: Hardware Drivers
Topic :: System :: Networking
Programming Language :: Python :: 2
Programming Language :: Python :: 3
"""

# Setup
setup(
    name='python-vxi11',
    version=version,
    packages=['vxi11'],
    entry_points={'console_scripts': ['vxi11-cli = vxi11.cli:main']},

    description="VXI-11 driver for controlling instruments over Ethernet",
    long_description=long_description,

    author='Alex Forencich',
    author_email='alex@alexforencich.com',
    url='http://alexforencich.com/wiki/en/python-vxi11/start',
    download_url='http://github.com/python-ivi/python-vxi11/tarball/master',
    keywords='VXI LXI measurement instrument',
    license='MIT License',
    classifiers=classifiers.split())
