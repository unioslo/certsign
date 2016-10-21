certsign
========

A tiny [ACME][acme_spec] Python 2 &amp; 3 client library with minimal dependencies. ACME is a
protocol for domain certificate verification and signing initiated by [Let's Encrypt][letsencrypt].
This package is meant to be used as a library and also comes with command line scripts.

Installation
------------

You can choose to either install it in your user's home directory or in the system directories.

This package depends on having the OpenSSL executable in the PATH.

### In you home directory
- For Python 3: `python3 setup.py install --user`
- For Python 2: `python2 setup.py install --user`

To be able to easily call the command line scripts `$HOME/.local/bin` should be in your
`$PATH`-variable if you run Linux. On Linux you can add the following to `.profile` or `.bashrc`
in your home directory, if `$HOME/.local/bin` is not already in you PATH.

```bash
# set PATH so it includes user's private .local/bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
```

The location for the scripts and the method to add it to the PATH is different for MacOS/OSX
and Windows.

### In the systems directories
- For Python 3: `sudo python3 setup.py install`
- For Python 2: `sudo python2 setup.py install`

Usage
-----

### As a library

#### Signing a Certificate Signing Request (CSR)
This is the primary usage of this library.

```python
from certsign import client
account_key = 'acme_directory_account.key'
csr_file = 'your_domain.csr'
challenges_path = '/path/served/by/your/http/server'
account_email = 'you@example.com'

signed_cert = client.sign_csr(
    account_key, csr_file, challenges_path, account_email=account_email
)
```
#### Creating a private key and a CSR

```python
from certsign import crypto

privkey_path = '/tmp/privkey.pem'
csr_path = '/tmp/example.com.csr'

privkey = crypto.create_private_key(bits=2048)
with open(privkey_path, 'w') as f:
    f.write(privkey.encode('utf-8'))

csr = crypto.create_csr(
    privkey_path,
    ['example.com', 'www.example.com'],
    openssl_conf='/etc/ssl/openssl.cnf'
)
with open(csr_path, 'w') as f:
    f.write(csr.encode('utf-8'))

```

### Command line

#### certsign
For signing a Certificate Signing Request (CSR):
```
certsign --account-key /path/to/account/key --csr /path/to/domain.csr \
  --challenge-dir /path/served/by/your/http/server \
  --account-email you@example.com
```


#### certsign-tool
Create a private key:
```
certsign-tool privkey --bits=4096 --out=/path/to/privkey.pem
```

Create a CSR:
```
certsign-tool csr --privkey=/path/to/privkey.pem \
  --out=/path/to/example.com.csr example.com www.example.com
```

View the CSR you just created:
```
certsign-tool view /path/to/example.com.csr
```


#### certsign-server
A simple server to respond to ACME challenges.
```
certsign-server --challenge-dir /path/served/by/your/http/server \
    --addr localhost \
    --port 8000 \
    --pidfile /tmp/certsign.pid &
```

To kill the server when finished:
```bash
if [ -f /tmp/certsign.pid ]; then
    pkill -F /tmp/certsign.pid
fi
```

Development
-----------

To set up a development environment for *certsign* you should create Python virtual environments.

You should create one virtual environment for Python 3 with [pyvenv] and another for Python 2
with [virtualenv]. This is necessary in order to test the library with both versions for Python.

Go the the project's root folder (where setyp.py is located) and run the following commands
in different terminals for each version of Python:
- For Python 3: `pyvenv venv-certsign-py3` and `source venv-certsign-py3/bin/activate`
  to activate the environment.
- For Python 2: `virtualenv venv-certsign-py2` and `source venv-certsign-py2/bin/activate`
  to activate the environment.

For both environments run `python setup.py develop` to install dependencies and the scripts
for this project.


[acme_spec]: https://github.com/ietf-wg-acme/acme/
[letsencrypt]: https://letsencrypt.org/
[pyvenv]: https://docs.python.org/3/library/venv.html
[virtualenv]: http://docs.python-guide.org/en/latest/dev/virtualenvs/
