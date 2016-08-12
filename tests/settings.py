import os

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')
ACCOUNT_KEY = os.path.join(FIXTURE_DIR, 'account.key')
CSR_FILE = os.path.join(FIXTURE_DIR, 'domain.csr')
PRIVKEY = os.path.join(FIXTURE_DIR, 'privkey.pem')
ACCOUNT_KEY_HEX = """d7:0f:e1:f1:52:e1:8c:70:2e:39:70:0c:f9:4d:
    7f:3e:88:ca:e3:7c:88:a1:ef:e2:67:aa:1a:f7:c5:
    59:52:0f:8c:cd:db:dc:98:9e:37:4c:cd:ae:be:cc:
    f9:3d:ba:77:9b:7f:7f:a6:af:7b:e7:e5:47:dd:41:
    35:03:5c:5b:83:7e:23:68:28:56:97:ac:4d:2b:79:
    9a:a6:0a:c0:87:b8:d5:0f:b8:a5:6b:d3:56:56:25:
    a5:57:56:b1:0c:61:e8:ef:22:cc:47:d5:6d:8b:4a:
    0b:f8:aa:90:bf:84:5a:6e:20:e8:d9:b2:20:32:31:
    44:a9:98:15:92:39:9f:ae:00:3e:61:71:c6:e5:d5:
    8e:e9:88:1d:8e:4d:58:04:f3:d1:2a:1e:fd:41:3d:
    79:68:fc:45:50:16:43:9a:21:be:77:4a:cc:57:24:
    c3:b9:18:a5:84:80:6e:e3:2e:b0:c8:fb:fd:7b:8a:
    76:1b:4d:eb:0c:08:12:40:1b:a7:13:18:fc:82:89:
    97:c2:c3:36:98:41:f6:78:b1:8a:c1:1e:09:74:5d:
    6e:05:df:e4:0a:d7:50:85:6d:a4:94:eb:ee:97:22:
    e9:ba:e1:c4:09:14:16:c3:d4:5d:b9:a6:6a:59:12:
    6e:85:0d:a5:a1:4e:35:f7:0b:46:89:25:40:c0:44:
    24:92:27:94:b6:1f:b5:3e:01:7c:cc:af:c9:cb:3e:
    7f:63:b5:dd:65:d3:66:6e:00:ad:43:08:4e:ac:57:
    5d:5e:0d:19:c1:ef:04:e3:68:7d:43:88:d3:14:4d:
    9f:56:5a:47:f5:0a:d5:ef:c8:f9:0c:f4:48:4c:4e:
    1e:b9:3f:58:75:3f:d6:f7:77:16:14:53:61:0d:ea:
    3f:2b:58:49:50:2c:e2:33:4d:ea:16:d9:1e:71:b3:
    3b:79:4e:60:b2:4f:e8:1f:5d:00:6a:ab:21:4c:99:
    d2:06:71:87:fb:08:5d:6d:63:07:e4:02:9a:e8:35:
    39:2c:b8:0f:36:3c:cf:d7:c8:d2:f3:86:eb:da:ff:
    6e:44:e0:9c:66:f8:4e:4c:f3:a5:6a:25:13:d3:04:
    ee:28:a0:f4:55:9c:55:2e:2b:32:12:cc:f7:00:1b:
    1d:49:af:53:4f:0c:98:5f:f4:e3:0a:1f:22:39:f8:
    07:69:5d:a6:c5:11:3a:c0:71:6d:d4:6d:f6:a0:5e:
    22:78:b2:13:97:6a:df:dc:56:5f:57:21:04:b8:0a:
    a2:d6:a7:3f:a8:d5:3a:aa:b4:c5:59:68:43:ab:74:
    db:0c:3c:2a:7c:63:3b:f2:91:66:86:2d:7d:f2:b2:
    aa:35:00:ae:1b:b5:1d:7a:47:7c:54:e0:b5:ad:08:
    35:ac:23"""
ACCOUNT_KEY_EXP = "010001"
DNAME = "O=Universitetet i Oslo/L=Oslo/ST=Oslo/C=NO"

OPENSSL_CONF = '/etc/ssl/openssl.cnf'
if not os.path.exists(OPENSSL_CONF):
    OPENSSL_CONF = '/etc/pki/tls/openssl.cnf'

CHALLENGE_DIR = '/srv/acme/challenges'
