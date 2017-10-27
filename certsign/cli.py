import argparse, sys, logging, os, signal, codecs

from . import client, server, crypto


def main(args=None):
    args = sys.argv[1:] if args is None else args

    parser = argparse.ArgumentParser(
        description="Use ACME to sign a certificate"
    )
    parser.add_argument(
        "--account-key", required=True, help="path to your Let's Encrypt account private key"
    )
    parser.add_argument(
        "--csr", required=True, help="path to your certificate signing request"
    )
    parser.add_argument(
        "--challenge-dir", required=True,
        help="path to the directory that serves .well-known/acme-challenge/"
    )
    parser.add_argument(
        "--account-email", default=None, help="email to be associated with the account key"
    )
    parser.add_argument(
        "--ca", default=client.DEFAULT_CA_DIRECTORY,
        help="certificate authority, default is Let's Encrypt"
    )
    parser.add_argument(
        "--quiet", action="store_const", const=logging.ERROR,
        help="suppress output except for errors"
    )

    args = parser.parse_args(args)
    sign_csr(args)


def server_main(args=None):
    args = sys.argv[1:] if args is None else args

    parser = argparse.ArgumentParser(
        description="Serves the challenge to ACME to prove you control the domain"
    )
    parser.add_argument(
        "--challenge-dir", required=True,
        help="path to the directory that serves .well-known/acme-challenge/"
    )
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--addr", default="localhost")
    parser.add_argument("--pidfile", default=None)

    args = parser.parse_args(args)
    challenge_server(args)


def tool_main(args=None):
    args = sys.argv[1:] if args is None else args

    parser = argparse.ArgumentParser(
        description="Various tools to support the certificate signing process"
    )
    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")
    subparsers.required = True

    privkey_parser = subparsers.add_parser("privkey")
    privkey_parser.add_argument("--out", required=True)
    privkey_parser.add_argument("--bits", type=int, default=4096)
    privkey_parser.set_defaults(handler=create_private_key)

    default_openssl_conf = '/etc/ssl/openssl.cnf'
    if not os.path.exists(default_openssl_conf):
        default_openssl_conf = '/etc/pki/tls/openssl.cnf'
    csr_parser = subparsers.add_parser("csr")
    csr_parser.add_argument("--privkey", required=True)
    csr_parser.add_argument("--out", required=True)
    csr_parser.add_argument(
        "--dname", default=None, help="distinguished name of your organization"
    )
    csr_parser.add_argument(
        "--conf", default=default_openssl_conf, help="the OpenSSl configuration file"
    )
    csr_parser.add_argument("domains", nargs='+')
    csr_parser.set_defaults(handler=create_csr)

    view_parser = subparsers.add_parser('view')
    view_parser.add_argument("file", help="A PEM encoded CSR or certificate")
    view_parser.set_defaults(handler=view_cert)

    args = parser.parse_args(args)
    args.handler(args)


def sign_csr(args):
    client.LOGGER.setLevel(args.quiet or client.LOGGER.level)
    signed_crt = client.sign_csr(
        args.account_key,
        args.csr,
        args.challenge_dir,
        args.account_email,
        log=client.LOGGER,
        ca_directory=args.ca,
    )
    print(signed_crt)


def challenge_server(args):
    acme_server = server.acme_challenge_server(args.challenge_dir, args.addr, args.port)
    if args.pidfile:
        if os.path.isfile(args.pidfile):
            raise FileExistsError(args.pidfile)
        with open(args.pidfile, "w") as f:
            f.write("{}\n".format(os.getpid()))
    print("Starting server on {}:{}, use <Ctrl-C> to stop".format(args.addr, args.port))
    try:
        acme_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        clean_pidfile(args.pidfile)


def create_private_key(args):
    privkey = crypto.create_private_key(args.bits)
    with codecs.open(args.out, "w", encoding="utf-8") as f:
        f.write(privkey)


def create_csr(args):
    csr = crypto.create_csr(args.privkey, args.domains, args.dname, args.conf)
    with codecs.open(args.out, "w", encoding="utf-8") as f:
        f.write(csr)


def view_cert(args):
    print(crypto.pem_file_info(args.file))


def clean_pidfile(pidfile):
    if pidfile and os.path.isfile(pidfile):
        os.unlink(pidfile)


def terminate(signo, frame):
    sys.exit(0)

# Make sure finally clauses are called on SIGTERM
signal.signal(signal.SIGTERM, terminate)
