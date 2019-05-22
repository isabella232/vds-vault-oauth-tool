import logging, time,os, datetime, platform
from logging.handlers import RotatingFileHandler

def path_converter(input_string):
        if platform.system() == 'Windows':
                return input_string.replace("/", "\\")
        else:
                return input_string.replace("\\", "/")

class Logger():
    def __init__(self, log_file):
        dateTag = datetime.datetime.now().strftime("%Y-%b-%d_%H-%M-%S")
        self.log_location = path_converter(log_file + "\oauth-output-%s.log" % dateTag)
        self.log_file = open(self.log_location, "w+", 1)
        self.render_output = []
        self.log("OAuth Troubleshooting Tool v0.1\n\n")
        self.log("DISCLAIMER: This is an open source tool meant to help verify OAuth client connections. It is not intended for production use.\n\n\n")
    
    def log(self, message : str, type="INFO"):
        if type == "INFO":
            print(message.replace("\n","",1))
            self.log_file.write(message)
            self.render_output.append(message.encode('utf-8'))
        if type == "ERROR":
            message += ("\n\tWARNING: You should consult with your internal IT team to resolve this issue."
                        "\n\tErrors indicate that there are problems with your OAuth client configuration outside of Veeva Vault.\n\n")
            print(message.replace("\n","",1))
            self.log_file.write(message)
            self.render_output.append(message.encode('utf-8'))
