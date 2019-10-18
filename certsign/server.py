import posixpath, os
try:
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
    from urllib import parse as urlparse
except ImportError:
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    from BaseHTTPServer import HTTPServer
    from SocketServer import ThreadingMixIn
    import urlparse

ACME_WELL_KNOWN = "/.well-known/acme-challenge/"


def request_handler_factory(base_path):
    serve_from_path =  os.path.normpath(os.path.expanduser(base_path))

    class ACMEChallengeRequestHandler(SimpleHTTPRequestHandler):
        """Serves ACME challenges to prove you own the domain"""

        def translate_path(self, path):
            """Translate a /-separated PATH to the local filename syntax.

            Components that mean special things to the local file system
            (e.g. drive or directory names) are ignored.  (XXX They should
            probably be diagnosed.)

            """
            # abandon query parameters
            path = path.split('?',1)[0]
            path = path.split('#',1)[0]
            if path.startswith(ACME_WELL_KNOWN):
                path = path[len(ACME_WELL_KNOWN):]
            else:
                return ""
            # Don't forget explicit trailing slash when normalizing. Issue17324
            trailing_slash = path.rstrip().endswith('/')
            try:
                path = urlparse.unquote(path, errors='surrogatepass')
            except (UnicodeDecodeError, TypeError):
                path = urlparse.unquote(path)
            path = posixpath.normpath(path)
            words = path.split('/')
            words = filter(None, words)
            path = serve_from_path
            for word in words:
                if os.path.dirname(word) or word in (os.curdir, os.pardir):
                    # Ignore components that are not a simple file/directory name
                    continue
                path = os.path.join(path, word)
            if trailing_slash:
                path += '/'
            return path

    return ACMEChallengeRequestHandler


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def acme_challenge_server(challenges_path, bind_addr='localhost', bind_port=8000):
    return ThreadedHTTPServer((bind_addr, bind_port), request_handler_factory(challenges_path))

