import requests
import urllib
import webbrowser


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


class MetadataComponents:

    def getComponentTypes(vaultConnection: VaultConnection):
        componentMap = dict()

        headers = {'Authorization' : vaultConnection.sessionId}
        request = requests.get(url = vaultConnection.vaultUrl + vaultConnection.apiVersion + "/metadata/components", headers = headers)
        data = request.json()

        if (data['responseStatus'] == "SUCCESS"):
            for data in data['data']:
                componentMap[data['name']] = {'mdl' : {'name': None, 'create' : None, 'recreate' : None, 'alter' : None, 'drop' : None, 'rename' : None}, 'attributes' : []}
        return componentMap
    
    def getComponentTypeMetadata(vaultConnection: VaultConnection, componentType: str):
        headers = {'Authorization' : vaultConnection.sessionId}

        request = requests.get(url = vaultConnection.vaultUrl + vaultConnection.apiVersion + "/metadata/components/" + componentType, headers = headers)
        data = request.json()

        if (data['responseStatus'] == "SUCCESS"):
            return data
        else:
            print("Component Type Metadata ERROR: " + componentType)
            return data

    def getComponentTypeCollection(vaultConnection: VaultConnection, componentType: str):
        headers = {'Authorization' : vaultConnection.sessionId}

        request = requests.get(url = vaultConnection.vaultUrl + vaultConnection.apiVersion + "/configuration/" + componentType, headers = headers)
        data = request.json()

        if (data['responseStatus'] == "SUCCESS"):
            return data
        else:
            return data

    def exportMDL(vaultConnection: VaultConnection, component: str):
        headers = {'Authorization' : vaultConnection.sessionId}

        request = requests.get(url = vaultConnection.vaultUrl + "/api/mdl/components/" + component, headers = headers)

        if request.text.find("responseStatus") != -1:
            data = request.json()
            if (data['responseStatus'] == "FAILURE"):
                return data
        else:
            data = request.text
            return {'responseStatus': 'SUCCESS', 'mdl': data}

    def deployMDL(vaultConnection: VaultConnection, mdl: str):
        headers = {'Authorization' : vaultConnection.sessionId, 'Accept' : 'application/json'}

        request = requests.post(url = vaultConnection.vaultUrl + "/api/mdl/execute", headers = headers, data = mdl)
        data = request.json()

        if (data['responseStatus'] == "SUCCESS"):
            print(data)
            return data
        else:
            print(data)
            return data



