import requests, platform, webbrowser
from vds_vault_oauth.utilities.Token import Token
from vds_vault_oauth.utilities.OAuthContainer import OAuthContainer
from vds_vault_oauth import main
import dotnet, os

# Only loads if the system is on Windows
# Loads the Microsoft.IdentityModel.Clients.ActiveDirectory.dll file that is necessary for C# ADAL.
# Uses the pydotnet library (https://bitbucket.org/pydotnet/pydotnet/wiki/Home)
if platform.system() == 'Windows':
    print(main.projectPath)
    dotnet.add_assemblies(main.projectPath + "\libraries")
    dotnet.load_assembly('Microsoft.IdentityModel.Clients.ActiveDirectory')

    from System import Uri
    from Microsoft.IdentityModel.Clients.ActiveDirectory import *

class ADALService():

    def isWindows():
        if platform.system() == 'Windows':
            return True
        else:
            print("The OAuth information provided is for ADFS 4.0 (ADAL). The tool can only test against ADAL on a Windows-based machine. Please try again on a Windows machine.\n\n")
            return False


class OAuthADALContainer(OAuthContainer):
    def __init__(self, as_metadata_url=None, as_metadata=None, client_id=None, port=None, logger=None):
        super().__init__(as_metadata_url, as_metadata, client_id, port, logger)
        self.uri = Uri(self.redirect_uri)
        self.tokenCache = TokenCache()
        self.ac = AuthenticationContext(self.as_metadata['issuer'], False, self.tokenCache)
    
    def verify_as_metadata(self):
        result = True
        if self.as_metadata != None:
            result = True
            self.logger.log(("AS Metadata is valid. Attempting to generate tokens.\n\n"))

        return result

    def get_tokens(self):
        try:
            self.logger.log(("\n" + '{s:{c}^{n}}'.format(s=" Retrieving Tokens ",n=85,c='*') + "\n\n")) 
            response_data = self.ac.AcquireTokenAsync("https://login.veevavault.com",self.client_id,self.uri,PlatformParameters(PromptBehavior.Auto)).Result

            if (response_data.AccessToken != None or response_data.AccessToken != ""): 
                success = False
                self.access_token = Token(response_data.AccessToken,"access_token", self.logger)
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
                    
            if (response_data.IdToken != None or response_data.IdToken != ""):  
                self.id_token = Token(response_data.IdToken, "id_token", self.logger)
                self.logger.log("SUCCESS:  ID token was retrieved. Running validation...\n\n")
                self.logger.log(("%s: %s\n\n" % ("ID Token", self.id_token.token_value)))

                if (self.id_token.decodeTokens()):
                    self.id_token.verifyTokenClaims()
                    self.id_token.logTokenClaims()
            else:
                self.logger.log("FAILURE: There is no ID token in the response.\n\n", "ERROR")
            
        except Exception as e:
            self.logger.log(("%s: %s\n\n" % ("ADAL Error Response", str(e).split("\r\n   ")[0])), "ERROR")
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
        try:
            response_data = self.ac.AcquireTokenAsync("https://login.veevavault.com",self.client_id,self.uri,PlatformParameters(PromptBehavior.Auto)).Result

            if (response_data.AccessToken != None or response_data.AccessToken != ""): 
                success = False
                self.access_token = Token(response_data.AccessToken,"access_token", self.logger)
                self.logger.log("SUCCESS:  Tokens have been refreshed. Running validation...\n\n")
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
                    
            if (response_data.IdToken != None or response_data.IdToken != ""):  
                self.id_token = Token(response_data.IdToken, "id_token", self.logger)
                self.logger.log(("%s: %s\n\n" % ("ID Token", self.id_token.token_value)))

                if (self.id_token.decodeTokens()):
                    self.id_token.verifyTokenClaims()
                    self.id_token.logTokenClaims()

        except Exception as e:
            self.logger.log("%s: %s\n" % ("ADAL Error Response", str(e).split("\r\n   ")[0]), "ERROR")
            return False

        return True
