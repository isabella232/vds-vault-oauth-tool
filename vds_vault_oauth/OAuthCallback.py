from wsgiref.simple_server import make_server, WSGIRequestHandler
from wsgiref.util import setup_testing_defaults
from urllib.parse import urlparse, parse_qs
from threading import Thread, Timer
import requests

class OAuthCallback:

    def __init__(self, oauth_container):
        self.oauth_container = oauth_container
        self.process = None
        self.httpd = None

    def application(self, environ, start_response):
        try:
            setup_testing_defaults(environ)
            status = '200 OK'
            headers = [('Content-Type', 'text/plain')]
            start_response(status, headers)
            ret = [("%s: %s\n" % (key, value)).encode("utf-8")
                for key, value in environ.items()]

            if ('error' in parse_qs(environ['QUERY_STRING'])):
                self.oauth_container.logger.log(("%s: %s\n" % ("Error", parse_qs(environ['QUERY_STRING'])['error'][0])))
                self.oauth_container.logger.log(("%s: %s\n\n" % ("Error Description", parse_qs(environ['QUERY_STRING'])['error_description'][0])))
                self.oauth_container.error = True

            if ('code' in parse_qs(environ['QUERY_STRING'])):   
                self.oauth_container.error = False 
                self.oauth_container.authorization_code = parse_qs(environ['QUERY_STRING'])['code'][0]
                self.oauth_container.logger.log(("%s: %s\n\n" % ("Authorization Code", self.oauth_container.authorization_code)))

                success = self.oauth_container.get_tokens()

                if (success == True and self.oauth_container.vault_user != None):
                    self.oauth_container.logger.log(("\n\n" + '{s:{c}^{n}}'.format(s=" Attempting to log in to Vault via OAuth2 ",n=85,c='*') + "\n\n"))
                    self.oauth_container.vault_user.get_vault_sessionid()

                if self.oauth_container.refresh_token != None:
                    self.oauth_container.logger.log(("\n\n" + '{s:{c}^{n}}'.format(s=" Refreshing Tokens ",n=85,c='*') + "\n\n"))
                    self.oauth_container.refresh_tokens()
                    self.oauth_container.logger.log(("\n\t" + '{s:{c}^{n}}'.format(s='',n=65,c='-') + "\n\n"))

            if (self.oauth_container.__class__.__name__ == 'OAuthADALContainer') and environ['PATH_INFO'].find('/favicon.ico') == -1:   
                self.oauth_container.error = False 

                self.oauth_container.logger.log(("\n\n" + '{s:{c}^{n}}'.format(s=" Authenticating with ADAL - the 'is_adfs' flag is enabled.",n=85,c='*')))
                self.oauth_container.logger.log(("\n" + '{s:{c}^{n}}'.format(s=" Issuer Endpoint: " + str(self.oauth_container.as_metadata['issuer']) + " ",n=85,c=' ') + "\n\n"))
                
                success = self.oauth_container.get_tokens()

                if (success == True and self.oauth_container.vault_user != None):
                    self.oauth_container.logger.log(("\n\n" + '{s:{c}^{n}}'.format(s=" Attempting to log in to Vault via OAuth2 ",n=85,c='*') + "\n\n"))
                    self.oauth_container.vault_user.get_vault_sessionid()

                if self.oauth_container.id_token != None or self.oauth_container.access_token != None:
                    self.oauth_container.logger.log(("\n\n" + '{s:{c}^{n}}'.format(s=" Refreshing Tokens ",n=85,c='*') + "\n\n"))
                    self.oauth_container.refresh_tokens()

        except Exception as e:
            self.oauth_container.logger.log(str(e))
        finally:
            if environ['PATH_INFO'].find('/favicon.ico') == -1:
                self.oauth_container.logger.log("\nOutput log generated at: " + self.oauth_container.logger.log_location + "\n")
                print("\nPress Enter to exit.\n\n")
            return self.oauth_container.logger.render_output

    def runLocalHostServer(self, port):
        self.oauth_container.logger.log("Starting server at: " + self.oauth_container.redirect_uri + "\n\n")
        self.httpd = make_server('', int(port), self.application, handler_class=NoLoggingWSGIRequestHandler)

        # Run server until the script is manually closed or if an OAuth connection isn't opened within 30 seconds.
        self.process = Thread(target=self.httpd.serve_forever, daemon=True)
        self.process.start()

        timer = Timer(30.0, self.end_process)
        timer.start()

    def end_process(self):
            if self.oauth_container.error == None:
                    self.oauth_container.logger.log("\n\nNo response received from OAuth2 client. Please verify the user information and client setup with your IT team and try again.\n\n")
                    self.oauth_container.logger.log("\n\nShutting down server at: " + self.oauth_container.redirect_uri + "\n\n")
                    self.oauth_container.error = False
                    
                    Thread(target=self.httpd.shutdown).start()


# Override default request handling. We don't want to log a console message when a new request is received.
class NoLoggingWSGIRequestHandler(WSGIRequestHandler):

    def log_message(self, format, *args):
        pass

