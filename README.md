# OAuth Troubleshooting Tool

This tool provides an automated way to determine if an OAuth client is configured correctly for use outside of Veeva Vault. 

Typically, this will be used for the following authorization servers:

* PingFederate
* Okta
* ADFS 4.0

For an **ADFS 4.0** client, the tool can **only** be used if the testing computer is running on **Windows**.

It will output logs that detail the access tokens, id tokens, and refresh tokens (if applicable). This includes the fully decoded contents of the tokens so that an admin can verify that the proper claims are configured for use with Veeva Vault. This includes:

* exp (expiration)
* aud (audience)
* cid (client ID)
* sub (user identifier)
* Other custom mapped claims like uid (user ID)

If the OAuth provider is configured incorrectly, the tool will return an error and not be able to retrieve tokens or it will display that the claims are invalid.

Optionally, you can also run the tool against a Vault User that is configured to use the defined OAuth client. This will perform the extra step of attempting to authenticate into Veeva Vault with the retrieved tokens.

## Setup

The Python script can be installed and run directly via the command line. 

1. The OAuth client **must** have a callback configured against **http://localhost:20500**. The port (20500) is configurable if you need to change it.
2. Install [Python 3.6.8 x64](https://www.python.org/downloads/release/python-368/) on your computer. 
   1. Python 3.6 is required.
   2. Install pip (it should be included with Python 3.6.8)
3. Install the vds-vault-oauth project using **one** of the following options.
   1. **RECOMMENDED**: `pip3.6 install -e git+https://github.com/veeva/vds-vault-oauth-tool.git@release#egg=vds_vault_oauth_tool`
      * Installation directory will be displayed in pip.
         * Windows: `c:\users\{username}\src\vds-vault-oauth-tool`
         * Mac OS : `/Users/{username}/src/vds-vault-oauth-tool`
   2. Download the project for the repository.
        1. Unzip the project and navigate to the vds-vault-vault base directory in a command line prompt:
         
            > pip install vds-vault-oauth/
         
        2. Install **dotnet**, **requests**, **python-jose** with **pip**
         
            > pip install dotnet
            
            > pip install requests
            
            > pip install python-jose


4. For **Windows** only:
   1. Navigate to `C:\users\{YOUR_USER}\AppData\local\Programs\Python\Python36\Lib\site-packages\dotnet
   2. Rename:
      * boost_python3-vc*-mt-1_64.dll → boost_python3-vc150-mt-1_64.dll
      * boost_python-vc*-mt-1_64.dll → boost_python-vc150-mt-1_64.dll

## Configuration

To configure the tool against your desired OAuth provider, add the following to the project's config.ini file or provide them as input parameters in the command line. 

The default config.ini file is located in:

* If you installed the script via option 1:
  
    Python installation directory
    Windows: `C:\users\<YOUR_USER>\AppData\local\Programs\Python\Python36\Lib\site-packages\vds_vault_oauth`
    Windows: `C:\users\{username}\src\vds-vault-oauth-tool\vds_vault_oauth`

    Mac OS : `/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/vds_vault_oauth`
    Mac OS : `/Users/{username}/src/vds-vault-oauth-tool`

* If you downloaded the script and are running the code directly:
    
    `In the project's base directory: <BASE_DIRECTORY>/vds_vault_oauth/config.ini`

### Configuration and Input Parameters. 

If using input parameters, they will override the values provided in the config.ini file.    


**Required**
```
client_id (-client_id)              : Oauth2 client ID as configured on your authorization server
username  (-username)               : Vault username that is configured against the provided OAuth provider. 
                                          Populates the AS Metadata from Vault.
   OR
as_metadata_url (-as_metadata_url)  : The Oauth AS Metadata endpoint
   OR 
as_metada_json (-as_metadata_json)  : The full Oauth AS Metadata in a JSON format
```

**Optional**
```
is_adfs (--is_adfs)                 : Takes "true" or "false" as input; default "false". Determines if the connection is to ADFS 4.0.
                                         This parameter should only be enabled on a Windows computer.
                                         This option **must** be used if your OAuth provide is **ADFS**
                                         Note: as an input parameter, this is just a flag.
                    
port (-port)                        : Default 20500; port number for the localhost callback address
c (-c)                              : The config.ini file location (if you want to define your own location)
log_directory (-log_directory)      : The directory for output logs; defaults to the project install location - <BASE_DIRECTORY>/vds_vault_oauth/logs.
```

An example config.ini configuration:

```
[oauth_connection]
client_id=xxxxxxxxxxxxxxxx
as_metadata_url=https://test.okta.com/oauth2/xxxxxxx/.well-known/oauth-authorization-server
as_metadata_json
username=
port=20500
log_directory=
is_adfs=false
```

## How to run

You can either run the tool via the installed script or directly from the code if you downloaded the project. 

Once you run the tool, a webpage will be opened in your default browser where you will be directed to login to your identity provider. A successful login will generate an authorization code that the tool will then use to generate tokens.

A log of the tool execution will then be output to the python console, the localhost:20500 webpage, and a dated 'oauth-output-{dd-Mon-yy_hh-mm-ss}.log' file.

### Installed Script:

* Run the tool against the config.ini

    > vds_vault_oauth_tool

* Run the tool against ADFS with the specified client ID and AS Metadata URL

    > vds_vault_oauth_tool --is_adfs -client_id=VaultCheckOut -as_metadata_url=https://test.testvault.com/adfs/.well-known/openid-configuration

* Run the tool against the specified Vault user and client ID

    > vds_vault_oauth_tool -client_id=VaultCheckOut -username=test.user@testveeva.com


### Run from code:

* Run the tool against the config.ini

    > python run-tool.py

* Run the tool against ADFS with the specified client ID and AS Metadata URL

    > python run-tool.py --is_adfs -client_id=VaultCheckOut -as_metadata_url=https://test.okta.com/adfs/.well-known/openid-configuration

* Run the tool against the specified Vault user and client ID

    > python run-tool.py -client_id=VaultCheckOut -username=test.user@testveeva.com
    

## License

This code serves as an example and is not meant for production use.

Copyright 2019 Veeva Systems Inc.
 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
