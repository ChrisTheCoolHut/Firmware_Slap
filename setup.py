#!/usr/bin/env python

from setuptools import setup

setup(name='Firmware_Slap',
      version='1.0',
      description='Tools to find bugs in firmware',
      author='Christopher Roberts',
      author_email='roberts.michael.christopher@gmail.com',
      url='https://github.com/ChrisTheCoolHut/Firmware_Slap',
      packages=['firmware_slap'],
      scripts=['bin/Vuln_Discover_Celery.py', 'bin/Vuln_Cluster_Celery.py',
          'bin/Discover_And_Dump.py'],
      include_package_data=True,
      install_requires=[
          "tqdm",
          "python-magic",
          "IPython",
          "sklearn",
          "matplotlib",
          "r2pipe",
          "angr",
          "psutil",
          "termcolor",
          "celery",
          "flower",
          "elasticsearch"
          ],
     )
