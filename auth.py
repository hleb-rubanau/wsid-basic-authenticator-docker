from flask import Flask, jsonify, request, render_template
from wsid.basic.identification import PasswordAuthenticator, get_public_ssh_keys
from wsid.basic.simple_policy import simple_ruleset
import configparser
import os.path
import logging

app = Flask(__name__)

WHITELIST_CONFIG_PATH='/settings/identification_whitelist.conf'
SSH_CONFIG_PATH='/settings/ssh.conf'

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    root_logger=logging.getLogger()
    root_logger.handlers = gunicorn_logger.handlers
    root_logger.setLevel(gunicorn_logger.level)

class Authenticator:
    def __init__(self, debug_logger=None):
        with open(WHITELIST_CONFIG_PATH,'r') as f:
            identification_whitelist=simple_ruleset( f.readlines(), debug_logger )

        self.authenticator=PasswordAuthenticator(whitelist=identification_whitelist)


    def authenticate_by_password(self, user, password):
        return self.authenticator.authenticate(user, password)

class PublicSSHKeysManager:
    def __init__(self):
        self.ssh_config={}
        self.logger=logging.getLogger('wsid.basic.pubkeys')

        if os.path.exists(SSH_CONFIG_PATH):
            with open(SSH_CONFIG_PATH, 'r') as sshconf:
                parser = configparser.ConfigParser(allow_no_value=True)
                parser.read(SSH_CONFIG_PATH)

                for section in parser:
                    if section=='DEFAULT':
                        continue

                    self.logger.debug(f'processing section {section}')
                    username=section.split(':')[0]
                    command = ':'.join(section.split(':')[1:]) if ':' in section else '*'

                    self.logger.debug(f'username={username} command={command}')
                    if not username in self.ssh_config:
                        self.ssh_config[username]={}
                    if not command in self.ssh_config[username]:
                        self.ssh_config[username][command]=set()

                    for remote_identity in parser[section]:
                        self.logger.debug(f'Adding ssh_config[{username}][{command}] << {remote_identity}')
                        self.ssh_config[username][command].add(remote_identity)

        self.logger.debug(f"ssh_config: {self.ssh_config}")

    def get_authorized_keys(self, username):
        if not username in self.ssh_config:
            return []

        authorized_keys=[]
        for command, identities in self.ssh_config[username].items():
            for remote_identity in identities:
                for k in get_public_ssh_keys(remote_identity): 
                    if command=='*':
                        authorized_keys.append(k)
                    else:
                        authorized_keys.append(f"command=\"{command}\" {k}")
        return authorized_keys
                         

#AUTHENTICATOR=Authenticator()
AUTHENTICATOR=Authenticator(app.logger) # for debug purposes
PUBLIC_KEYS=PublicSSHKeysManager()

# default endpoint is used to process nginx authorization requests
@app.route("/", methods=["GET"])
def nginx_auth():
    # we only do validation against whitelist
    # more sophisticated analysis (authorization against particular methods etc.) is possible but it's not implemented here
    
    # we expect basic authentication to contain username(WSID identity) and password 
    if not request.authorization:
        return '{"msg":"Authenticate!"}', 401

    username=request.authorization.username
    password=request.authorization.password

    if username='https' and password.startswith('//'):
        app.logger.debug(f"Fixing username")
        username=':'.join( username, password.split(':')[0])
        password=':'.join(password.split(':')[1:])

    app.logger.debug(f"Authenticating: username={username}")
    # we are not blindly checking each and every username
    if not AUTHENTICATOR.authenticate_by_password(username, password):
        return '{}', 403

    # TODO: add configurable authorization policies based on confirmed identity and request parameters
    response=jsonify({"status": "ok", "user": username})
    response.headers['X-WSID-Identity']=username
    return response


@app.route("/.ssh/authorized_keys/<username>", methods=["GET"])
def ssh_authorized_keys(username):
    return "\n".join( PUBLIC_KEYS.get_authorized_keys(username) ) 
