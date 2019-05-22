import requests, random, string, base64, hashlib
from vds_vault_oauth.utilities.Token import Token
from vds_vault_oauth.utilities.logging.Logger import Logger

class OAuthContainer:
    def __init__(self, as_metadata_url=None, as_metadata=None, client_id=None, port=None, logger=None):
        self.as_metadata_url = as_metadata_url
        self.scope = ""

        if as_metadata == None:
            self.as_metadata = self.get_as_metadata(as_metadata_url)
            self.set_scope()
        else:
            self.as_metadata = as_metadata
            self.set_scope()

        self.client_id = client_id
        self.redirect_uri = "http://localhost:" + str(port) 
        self.code_verifier = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=48))
        self.code_challenge_bytes = base64.urlsafe_b64encode(hashlib.sha256(self.code_verifier.encode('utf-8')).digest())
        self.code_challenge = self.code_challenge_bytes.decode("utf-8").rstrip("=")

        self.secret_type = None
        self.authorization_code = None
        self.access_token = None
        self.id_token = None
        self.refresh_token = None

        self.vault_user = None
        self.error = None
        self.logger = logger

    def get_as_metadata(self,as_metadata_url):
        request = requests.get(url = as_metadata_url)
        data = request.json()
        return data

    def set_scope(self):
        if self.as_metadata != None:
            for scope in self.as_metadata['scopes_supported']:
                if scope.find('openid') != -1 or scope.find('offline_access') != -1:
                    self.scope += scope + " "
            self.scope.strip()

    def verify_as_metadata(self):
        result = True
        if self.as_metadata != None:
            if self.scope.find("openid") == -1:
                self.logger.log(("The authorization server does not have the 'openid' scope enabled. This is required for Vault.\n\n"))
                result = False
            if self.scope.find("offline_access") == -1:
                self.logger.log(("The authorization server does not have the 'offline_access' scope enabled. This is required for Vault.\n\n"))
                result = False
            if 'introspection_endpoint' not in self.as_metadata:
                self.logger.log(("The authorization server does not have a 'introspection_endpoint'. This is required for Vault.\n\n"))
                result = False
            else:
                self.logger.log(("AS Metadata is valid - contains 'open_id' and 'offline_access' scopes and the 'introspection_endpoint'. Attempting to generate tokens. \n\n"))

        return result

    def get_authorization_code(self, code_type):
        response_type = "code"
        state = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

        url = {
            'pkce' : self.as_metadata['authorization_endpoint'] + "?client_id=" + self.client_id + "&response_type=" + response_type \
                     + "&scope=" + self.scope + "&state=" + state + "&redirect_uri=" + self.redirect_uri   \
                     + "&code_challenge=" + str(self.code_challenge) + "&code_challenge_method=S256",
            'base' : self.as_metadata['authorization_endpoint'] + "?client_id=" + self.client_id + "&response_type=" + response_type \
                     + "&scope=" + self.scope + "&state=" + state + "&redirect_uri=" + self.redirect_uri
        }[code_type]

        self.logger.log(("\n" + '{s:{c}^{n}}'.format(s=" Retrieving Authorization Code ",n=85,c='*') + "\n\n"))      
        self.logger.log(("%s: %s\n\n" % ("Authorization Endpoint", url)))
        self.secret_type = code_type

        print(url)
        return url
    
    def get_tokens(self):
        grant_type = "authorization_code"

        url = {
            'pkce' : self.as_metadata['token_endpoint'] + "?client_id=" + self.client_id + "&grant_type=" + grant_type \
                     + "&code=" + self.authorization_code + "&redirect_uri=" + self.redirect_uri + "&code_verifier=" + self.code_verifier,
            'base' : self.as_metadata['token_endpoint'] + "?client_id=" + self.client_id + "&grant_type=" + grant_type \
                     + "&code=" + self.authorization_code + "&redirect_uri=" + self.redirect_uri + "&client_secret=ZGE_AgZn-QXnkpZpR3Avv6bUkx5uJfS3fRPmhuqC"
        }[self.secret_type]

        self.logger.log(("\n" + '{s:{c}^{n}}'.format(s=" Retrieving Tokens ",n=85,c='*') + "\n\n"))           
        self.logger.log(("%s: %s\n\n" % ("Token Endpoint", url)))

        headers = {'Content-Type' : 'application/x-www-form-urlencoded'}
        request = requests.post(url = url, headers = headers)
        response_data = request.json()

        if (request.status_code == 200):
            if ('access_token' in response_data): 
                success = False
                self.access_token = Token(response_data['access_token'],"access_token", self.logger)
                self.logger.log("SUCCESS:  Access token was retrieved. Running validation...\n\n")
                self.logger.log(("%s: %s\n\n" % ("Access Token", self.access_token.token_value)))

                if (not self.access_token.decodeTokens()):
                    try:
                        self.logger.log(("\t%s: %s\n\n" % ("Error", "Non-JWT token detected. Verifying against introspection endpoint.")))
                        self.introspect_tokens()
                    except Exception:
                        self.logger.log("Introspection failure.")
                else:
                    self.access_token.verifyTokenClaims()
                    self.access_token.logTokenClaims()
            else:
                self.logger.log("FAILURE: There is no access token in the response.\n\n", "ERROR")
                    
            if ('id_token' in response_data): 
                self.id_token = Token(response_data['id_token'],"id_token", self.logger)
                self.logger.log("SUCCESS:  ID token was retrieved. Running validation...\n\n")
                self.logger.log(("%s: %s\n\n" % ("ID Token", self.id_token.token_value)))

                if (self.id_token.decodeTokens()):
                    self.id_token.verifyTokenClaims()
                    self.id_token.logTokenClaims()
            else:
                self.logger.log("FAILURE: There is no ID token in the response.\n\n", "ERROR")
            
            if ('refresh_token' in response_data): 
                self.refresh_token = Token(response_data['refresh_token'],"refresh_token", self.logger)
                self.logger.log("SUCCESS:  Refresh token was retrieved.\n\n")
                self.logger.log(("%s: %s\n\n" % ("Refresh Token", self.refresh_token.token_value)))
            else:
                self.logger.log("WARNING: There is no refresh token in the response. The 'offline_access' scope is not enabled.\n\n", "ERROR")

            if ('error' in response_data): 
                self.logger.log(("%s: %s\n" % ("Error", response_data['error'])))
                self.logger.log(("%s: %s\n\n" % ("Error Description", response_data['error_description'])))
                return False
        else:
            self.logger.log(("%s: %s\n" % ("HTTP Status Code", str(request.status_code))))
            self.logger.log(("%s: %s\n" % ("JSON Response", response_data)))
            return False

        return True

    def introspect_tokens(self):

        if ('introspection_endpoint' in self.as_metadata):
            url = self.as_metadata['introspection_endpoint'] + "?client_id=" + self.client_id + "&token=" + self.access_token.token_value

            self.logger.log(("%s: %s\n\n" % ("Introspection Endpoint", url)))

            headers = {'Content-Type' : 'application/x-www-form-urlencoded'}
            request = requests.post(url = url, headers = headers)
            response_data = request.json()

            if (request.status_code == 200):
                self.access_token.token_claims.update(response_data)
                self.access_token.verifyTokenClaims()
                self.access_token.logTokenClaims()
                
                return True
            else:
                return False
        else:
            self.logger.log(("%s: %s\n\n" % ("INFO", "AS Metadata has no introspection endpoint. Skipping token validation.")))
            return False

    def refresh_tokens(self):
        url = self.as_metadata['token_endpoint'] + "?client_id=" + self.client_id + "&refresh_token=" + self.refresh_token.token_value + "&grant_type=refresh_token" \
            + "&scope=" + self.scope

        self.logger.log(("%s: %s\n\n" % ("Refresh Token Endpoint", url)))
        self.logger.log(("\n\t" + '{s:{c}^{n}}'.format(s=" Refresh Details ",n=65,c='-') + "\n\n"))
               
        headers = {'Content-Type' : 'application/x-www-form-urlencoded'}
        request = requests.post(url = url, headers = headers)
        response_data = request.json()

        if (request.status_code == 200):
            self.logger.log("SUCCESS:  Tokens have been refreshed. Running validation...\n\n")
            for key, value in response_data.items():
                 self.logger.log(("\t%s: %s\n" % (key, value)))
            self.logger.log(("\n"))
            
            return True
        else:
            return False
