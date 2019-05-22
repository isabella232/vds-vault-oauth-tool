import os, webbrowser, logging, time, argparse, configparser, sys, json, platform
projectPath = os.path.abspath(os.path.dirname(__file__))

from vds_vault_oauth.utilities.logging.Logger import Logger
from vds_vault_oauth.utilities.VaultApiService import VaultConnection
from vds_vault_oauth.utilities.OAuthContainer import OAuthContainer
from vds_vault_oauth.utilities.OAuthADALContainer import OAuthADALContainer, ADALService
from vds_vault_oauth.utilities.OAuthVaultUserContainer import OAuthVaultUserContainer
from vds_vault_oauth.OAuthCallback import OAuthCallback

config = configparser.ConfigParser()
logger = None

default_username = None
default_client_id = None
default_as_metadata_url = None
default_as_metadata_json = {}
default_port = 20500
is_adfs = False


def run_server():
        global default_client_id, default_as_metadata_url
        oauth_container = None

        # Only grabs AS Metadata from Vault if there is a valid user defined as a parameter
        if (default_username != None):
                if (default_client_id != None):
                        oauth_container = OAuthVaultUserContainer(default_username, default_client_id, default_port, logger).get_vault_metadata()
                        oauth_container.logger.log("OAuth2 Client ID: " + default_client_id + "\n")
                        oauth_container.logger.log("Vault Username: " + default_username + "\n\n")
                else:
                        print("Client ID must not be null. Please enter a value as a parameter or in the config.ini file and try again.")
        
        # Else, the tool only attempts to connect to the authorization server if their is valid AS Metadata provided
        # This also won't continue if there isn't a client ID specified.
        # Without a valid client id and AS Metadata, there is nothing to test against.
        elif (default_as_metadata_url != None or len(default_as_metadata_json) > 0):
                if (default_client_id != None):
                        if (default_as_metadata_url and default_as_metadata_json) or (default_as_metadata_url and not default_as_metadata_json):
                                # Determines if the target authorization server is ADFS (ADAL enabled) or not.
                                if is_adfs:
                                        if (ADALService.isWindows()):
                                                oauth_container = OAuthADALContainer(default_as_metadata_url, None, default_client_id, default_port, logger)
                                                oauth_container.logger.log("OAuth2 Client ID: " + default_client_id + "\n")
                                                oauth_container.logger.log("AS Metadata: " + default_as_metadata_url + "\n\n")
                                        else:
                                                oauth_container = None
                                else:
                                        oauth_container = OAuthContainer(default_as_metadata_url, None, default_client_id, default_port, logger)
                                        oauth_container.logger.log("OAuth2 Client ID: " + default_client_id + "\n")
                                        oauth_container.logger.log("AS Metadata: " + default_as_metadata_url + "\n\n")

                        elif (default_as_metadata_json and not default_as_metadata_url):
                                if is_adfs:
                                        if (ADALService.isWindows()):
                                                oauth_container = OAuthADALContainer(None, default_as_metadata_json, default_client_id, default_port, logger)
                                                oauth_container.logger.log("OAuth2 Client ID: " + default_client_id + "\n")
                                                oauth_container.logger.log("AS Metadata: " + str(default_as_metadata_json) + "\n\n")
                                        else:
                                                oauth_container = None
                                else:
                                        oauth_container = OAuthContainer(None, default_as_metadata_json, default_client_id, default_port, logger)
                                        oauth_container.logger.log("OAuth2 Client ID: " + default_client_id + "\n")
                                        oauth_container.logger.log("AS Metadata: " + str(default_as_metadata_json) + "\n\n")
                        else:
                                print("AS Metadata URL or JSON must not be null. Please enter a value as a parameter or in the config.ini file and try again.")
                else:
                        print("Client ID must not be null. Please enter a value as a parameter or in the config.ini file and try again.")
        else:
                print("Please provide a 'Vault Username' or 'AS Metadata' and rerun the tool.")
        
        # Starts the necessary localhost server to receive the authorization server's callback at localhost:20500 (default port)
        # If there is no activity for 30 seconds, the server will automatically shutdown
        if oauth_container != None and oauth_container.verify_as_metadata():
                callback = OAuthCallback(oauth_container)
                callback.runLocalHostServer(default_port)
                open_browser(oauth_container)
        else:
                logger.log("OAuth2 connection could not be generated. Please review the output logs.\n\n")


def open_browser(oauth_container):
        # Opens the running user's default browser. This is required for the callback that contains the necessary authorization code.
        if (oauth_container.__class__.__name__ != 'OAuthADALContainer'):                   
                webbrowser.open(oauth_container.get_authorization_code('pkce'), new=0, autoraise=True)
                while oauth_container.error == None:
                        #Wait for callback to be retrieved.
                        time.sleep(2)
                        if (oauth_container.error == True):
                                oauth_container.logger.log("WARNING: Your OAuth2 client is not using PKCE for access. "
                                                           "While the tool can still proceed, Veeva recommends using PKCE for security purposes.\n\n")
                                webbrowser.open_new(oauth_container.get_authorization_code('base'))
                                break
                        elif (oauth_container.error == False):
                                break
        else:
                webbrowser.open(oauth_container.redirect_uri)


def path_converter(input_string):
        if platform.system() == 'Windows':
                return input_string.replace("/", "\\")
        else:
                return input_string.replace("\\", "/")

def main():
        global logger, default_client_id, default_as_metadata_url, default_as_metadata_json, default_port, default_username, is_adfs
        logFile = ""
        import sys

        # Parse in parameters from the command line
        parser = argparse.ArgumentParser(description="OAuth Troubleshooting Tool")
        parser.add_argument("-c", "--config", help="config file location")
        parser.add_argument("-username", help="vault username")
        parser.add_argument("-client_id", help="Oauth2 client Id")
        parser.add_argument("--is_adfs", action='store_true', default=False, help="Defines if the OAuth provider is ADFS")
        parser.add_argument("-as_metadata_url", help="AS Metadata URL")
        parser.add_argument("-as_metadata_json", help="AS Metadata JSON")
        parser.add_argument("-port", help="OAuth Local Callback Port")
        parser.add_argument("-log_directory", help="Output Log Directory")

        args = parser.parse_args()

        # Parse in the default config.ini if it doesn't exist as a parameter
        if (args.config == None):
                config.read(path_converter(projectPath  + "\config.ini"))
        else:
                config.read(path_converter(args.config.strip()))

        # Check for parameter values from the config.ini file
        if ('oauth_connection' in config):
                default_client_id = config['oauth_connection']['client_id'] if 'client_id' in config['oauth_connection'] and config['oauth_connection']['client_id'] != "" else default_client_id
                default_as_metadata_url = config['oauth_connection']['as_metadata_url'] if 'as_metadata_url' in config['oauth_connection'] and config['oauth_connection']['as_metadata_url'] != "" else default_as_metadata_url
                default_as_metadata_json = json.loads(config['oauth_connection']['as_metadata_json']) if 'as_metadata_json' in config['oauth_connection'] and config['oauth_connection']['as_metadata_json'] != "" else default_as_metadata_json
                default_port = int(config['oauth_connection']['port']) if 'port' in config['oauth_connection'] else default_port
                default_username = config['oauth_connection']['username'] if 'username' in config['oauth_connection'] and config['oauth_connection']['username'] != "" else default_username
                is_adfs = True if 'is_adfs' in config['oauth_connection'] and config['oauth_connection'].getboolean('is_adfs') == True else False

                if (config['oauth_connection']['log_directory'] == ""):                
                        logFile = path_converter(projectPath + "\logs")
                else:
                        logFile = path_converter(config['oauth_connection']['log_directory'].strip("\\"))

        # If there are direct command line parameters, these will override the config.ini file.
        default_username = args.username.strip() if args.username != None and args.username.strip() != "" else default_username
        default_client_id = args.client_id.strip() if args.client_id != None and args.client_id.strip() != "" else default_client_id
        is_adfs = True if args.is_adfs == True else is_adfs

        if (args.as_metadata_url and args.as_metadata_json) or (args.as_metadata_url and not args.as_metadata_json):
                default_as_metadata_url = args.as_metadata_url.strip()
                default_as_metadata_json = {}
        elif (args.as_metadata_json and not args.as_metadata_url):
                default_as_metadata_json = json.loads(args.as_metadata_json.strip().replace("'", '"'))
                default_as_metadata_url = None

        default_port = int(args.port.strip()) if args.port != None and args.port.strip() != "" else default_port
        logFile = path_converter(args.log_directory.strip()) if args.log_directory != None and args.log_directory.strip() != "" else logFile
        print("Output log directory: " + logFile + "\n")

        logger = Logger(logFile)      
               
        try:
                run_server()
        except BaseException:
                import sys
                print(sys.exc_info()[0])
                import traceback
                print(traceback.format_exc())
        finally:
                input()