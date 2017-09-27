#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="certsign",
    version="0.1",
    description="A tiny ACME (Let's Encrypt) Python 2 & 3 client library with minimal dependencies",
    author="Nils Fredrik Gjerull",
    author_email="n.f.gjerull@usit.uio.no",
    url="https://github.com/unioslo/certsign",
    keywords="acme letsencrypt",
    long_description=open("README.md").read(),
    packages=find_packages(exclude=["tests"]),
    setup_requires=["setuptools_git"],
    test_suite = "tests.unit_tests",
    entry_points={
        'console_scripts': [
            'certsign = certsign.cli:main',
            'certsign-server = certsign.cli:server_main',
            'certsign-tool = certsign.cli:tool_main'
        ]
    },
    classifiers=[
        "Development Status :: 4 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators"
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Topic :: Security",
    ],
)

