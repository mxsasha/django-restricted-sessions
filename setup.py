#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

import restrictedsessions

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

version = restrictedsessions.__version__

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    print("You probably want to also tag the version now:")
    print("  git tag -a %s -m 'version %s'" % (version, version))
    print("  git push --tags")
    sys.exit()

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

setup(
    name='django-restricted-sessions',
    version=version,
    description="""Restrict Django sessions to IP and/or user agent.""",
    long_description=readme + '\n\n' + history,
    author='django-restricted-sessions',
    author_email='eromijn@solidlinks.nl',
    url='https://github.com/erikr/django-restricted-sessions',
    packages=[
        'restrictedsessions',
    ],
    include_package_data=True,
    install_requires=[
        'netaddr>=0.7.10',
    ],
    license="BSD",
    zip_safe=False,
    keywords='django-restricted-sessions',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],
)
