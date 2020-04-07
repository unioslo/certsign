#!/usr/bin/env python
import sys
from os import path
from codecs import open
from setuptools import setup, find_packages

needs_pytest = {"pytest", "test", "ptr"}.intersection(sys.argv)
setup_requires = []
if needs_pytest:
    setup_requires.append("pytest-runner")

here = path.abspath(path.dirname(__file__))
with open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="certsign",
    version="0.2",
    description="A tiny ACME (Let's Encrypt) Python 2 & 3 client library with minimal dependencies",
    author="Nils Fredrik Gjerull",
    author_email="n.f.gjerull@usit.uio.no",
    url="https://github.com/unioslo/certsign",
    keywords="acme letsencrypt",
    long_description=long_description,
    license="BSD",
    packages=find_packages(exclude=["tests"]),
    setup_requires=setup_requires,
    tests_require=[
        "pytest",
    ],
    extras_require={
        "dev": ["pytest", "wheel", "tox", "twine"],
    },
    entry_points={
        "console_scripts": [
            "certsign = certsign.cli:main",
            "certsign-server = certsign.cli:server_main",
            "certsign-tool = certsign.cli:tool_main"
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)

