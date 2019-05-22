import requests, platform
from vds_vault_oauth.utilities.OAuthContainer import OAuthContainer
from vds_vault_oauth.utilities.OAuthADALContainer import OAuthADALContainer, ADALService
from vds_vault_oauth.utilities.VaultApiService import VaultConnection

# Class that retrieves AS Metadata based on a specific Veeva Vault user.
class OAuthVaultUserContainer:
    def __init__(self, username, client_id, port, logger):
        self.connection_type = None
        self.vault_session_endpoint = None
        self.client_id = client_id
        self.port = port
        self.logger = logger
        self.api_url = "https://login.veevavault.com/auth/discovery?username=" + username +  "&client_id=" + self.client_id
        self.as_metadata = None
        self.vault_connection = VaultConnection(None, None, username, None, None)
        
        self.oauth_container = None

    # AS Metadata is retrieved from a Discovery Endpoint and then parsed accordingly. 
    # https://developer.veevavault.com/api/19.1/#authentication-type-discovery
    def get_vault_metadata(self):
        request = requests.get(url = self.api_url)
        data = request.json()
        response_status = data['responseStatus'] if 'responseStatus' in data else None

        if (response_status == 'SUCCESS'):
            if (data['data']['auth_type'] == 'sso' and len(data['data']['auth_profiles']) > 0):
                self.vault_session_endpoint = data['data']['auth_profiles'][0]['vault_session_endpoint']
                self.as_metadata = data['data']['auth_profiles'][0]['as_metadata'] if 'as_metadata' in data['data']['auth_profiles'][0] else None
                
                if data['data']['auth_profiles'][0]['use_adal']:
                    print(data['data']['auth_profiles'][0]['use_adal'])

                    if (ADALService.isWindows()):
                            self.oauth_container = OAuthADALContainer(None, self.as_metadata, self.client_id, self.port, self.logger)
                            self.oauth_container.vault_user = self
                    else:
                            self.oauth_container = None
                else:
                    self.oauth_container = OAuthContainer(None, self.as_metadata, self.client_id, self.port, self.logger)
                    self.oauth_container.vault_user = self

                return self.oauth_container
            else:
                self.oauth_container.logger.log("INVALID USERNAME. Please enter a valid OAuth2 vault username.")
                return None
        elif (response_status == 'FAILURE'):
            self.oauth_container.logger.log(data)
            return None

    # With a valid Vault user, a connection will be attempted agaisnt Veeva Vault where a session ID will be generated & stored.
    def get_vault_sessionid(self):
        if (self.vault_session_endpoint != None and self.oauth_container.access_token.token_value != None):
            data = self.vault_connection.authenticate_vault_oauth(self.oauth_container.access_token.token_value,self.vault_session_endpoint)
            response_status = data['responseStatus'] if 'responseStatus' in data else None
            
            if (response_status == 'SUCCESS'):
                self.oauth_container.logger.log(("Login successful.\n\n"))
                self.oauth_container.logger.log(("%s: %s\n" % ("Vault URL", self.vault_connection.vaultUrl)))
                self.oauth_container.logger.log(("%s: %s\n" % ("Vault Username", self.vault_connection.username)))
                self.oauth_container.logger.log(("%s: %s\n" % ("Session Id", self.vault_connection.sessionId)))
            elif (response_status == 'FAILURE'):
                self.oauth_container.logger.log(("Login failure.\n\n"))
                self.oauth_container.logger.log(("%s: %s\n\n" % (data['errors'][0]['type'], data['errors'][0]['message'])))
                self.oauth_container.logger.log("Vault session could not be generated. Please review the logs and the 'OAuth 2.0 / OpenID Connect Event Logging and Troubleshooting' \n"
                    "\n(http://vaulthelp.vod309.com/wordpress/admin-user-help/authentication-vault-security/configuring-oauth-2-oidc-profiles/) section of the guide for additional troubleshooting steps.\n\n")
                return None
            else:
                self.oauth_container.logger.log(("Invalid request.\n"))
        else:
            self.oauth_container.logger.log("No valid Vault OAuth Session endpoint or access token.")
