import requests
import urllib
import webbrowser

# Class that creates a OAuth connection to a Veeva Vault instance.
class VaultConnection:
    def __init__(self,vaultUrl=None, apiVersion=None, username=None, password=None, log=None):
        self.vaultUrl = vaultUrl
        self.username = username
        self.password = password
        self.apiVersion = apiVersion
        self.sessionId = None
        self.render_output = log

    def authenticate_vault(self):
        request = requests.post(url = self.vaultUrl + self.apiVersion + "/auth", data = {'username':self.username, 'password':self.password})
        data = request.json()

        if (data['responseStatus'] == "SUCCESS"):
            self.sessionId = data['sessionId']
            print(data)
    
    def authenticate_vault_oauth(self, access_token, vault_session_endpoint):
        if (vault_session_endpoint != None):
            headers = {'Authorization' : "Bearer " + str(access_token), 'Accept':  'application/json'}
            request = requests.post(url = vault_session_endpoint, headers = headers)
            data = request.json()

            response_status = data['responseStatus'] if 'responseStatus' in data else None
            
            if (response_status == 'SUCCESS'):
                self.sessionId = data['sessionId']
                self.get_vault_url_from_oauth(data)

            return data

    def get_vault_url_from_oauth(self, response_data):
        vaultId = response_data['vaultId']
        for item in response_data['vaultIds']:
            if (item['id'] == vaultId):
                self.vaultUrl = item['url'].rstrip("/api")