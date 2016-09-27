import argparse, sys, logging, os, signal

from . import client, server


def main(args=None):
    args = sys.argv[1:] if args is None else args

    parser = argparse.ArgumentParser(
        description="Use ACME to sign a certificate"
    )
    parser.add_argument(
        "--account-key", required=False, help="path to your Let's Encrypt account private key"
    )
    parser.add_argument(
        "--csr", required=False, help="path to your certificate signing request"
    )
    parser.add_argument(
        "--challenge-dir", required=False,
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
    parser.add_argument("--port", default=8000)
    parser.add_argument("--addr", default="localhost")
    parser.add_argument("--pidfile", default=None)

    args = parser.parse_args(args)
    challenge_server(args)


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


def clean_pidfile(pidfile):
    if pidfile and os.path.isfile(pidfile):
        os.unlink(pidfile)


def terminate(signo, frame):
    sys.exit(0)

# Make sure finally clauses are called on SIGTERM
signal.signal(signal.SIGTERM, terminate)
