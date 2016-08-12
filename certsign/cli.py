import argparse, sys, logging

from . import client


def main(args=None):
    args = sys.argv[1:] if args is None else args
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--account-email", default=None, help="email to be associated with the account key")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--ca", default=client.DEFAULT_CA_DIRECTORY, help="certificate authority, default is Let's Encrypt")

    args = parser.parse_args(args)
    client.LOGGER.setLevel(args.quiet or client.LOGGER.level)
    signed_crt = client.sign_csr(
        args.account_key, args.csr, args.acme_dir, args.account_email, log=client.LOGGER, ca_directory=args.ca
    )
    sys.stdout.write(signed_crt)
