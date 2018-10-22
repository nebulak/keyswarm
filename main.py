#!/usr/bin/env python3

import sys, threading, time, os
"""
from stem.control import Controller
from stem import SocketError, UnsatisfiableRequest
import stem.process
from stem.util import term
from flask import Flask
from flask import send_from_directory
"""
# crypto
import pyblake2
import pylibscrypt
import ed25519
import base58
import hashlib
import time
import json
import base64

import socks

# Stem for hidden services: source: https://stem.torproject.org/tutorials/over_the_river.html
# Serving static files with flask: source: https://www.techcoil.com/blog/serve-static-files-python-3-flask/
# Using flask with tor: source: https://gist.github.com/PaulSec/ec8f1689bfde3ce9a920

# Set tor_cmd: source: https://stackoverflow.com/a/25069013
WEB_PORT = 8080
CONTROL_PORT = 7001
SOCKS_PORT = 7000
HIDDEN_SERVICE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'hidden_service')
static_file_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'public')
TOR_CMD = "/Applications/TorBrowser.app/Tor/tor.real"

#app = Flask(__name__)


# //TODO: check password strength with zxcvbn
class KeySwarmSession(object):
    def __init__(self, email, password):
        salt = ('KeySwarm Profile Signature Key:'.join(email)).encode('utf-8')
        pw = password.encode('utf-8')
        hashed_pw = pyblake2.blake2s(pw).digest()
        seed = pylibscrypt.scrypt(hashed_pw, salt, 2**17, 8, 1, 32)
        self.private_key = ed25519.SigningKey(seed)
        #print("test: " + str(self.private_key.sign(b"hello world", encoding="base64")))
        self.public_key = self.private_key.get_verifying_key()
        self.address = base58.b58encode( self.public_key.to_bytes() + pyblake2.blake2s(self.public_key.to_bytes(), 1).digest() )
        print("Adress: ", (self.address).decode('utf-8'))




class KeySwarmCrypto(object):
    #//source: https://github.com/cathalgarvey/deadlock/blob/master/deadlock/crypto.py
    @staticmethod
    def ensure_bytes(value):
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode('utf8')
        elif isinstance(value, bytestring):
            return bytes(value)
        else:
            raise TypeError("Value is not str, bytearray or bytes: '{}', type '{}'".format(value, type(value)))

    @staticmethod
    def assert_type_and_length(varname, var, T, L = None, minL = None, maxL = None):
        'Facilitates simultaneous or one-line type/length checks.'
        if not isinstance(var, T):
            raise TypeError("Variable '{}' is supposed to be type '{}' but is '{}'".format(varname, T, type(var)))
        if isinstance(L, int):
            if not L == len(var):
                raise ValueError("Variable '{}' is supposed to be length {} but is {}".format(varname, L, len(var)))
        if isinstance(maxL, int):
            if maxL < len(var):
                raise ValueError("Variable '{}' is supposed to be smaller than {} but is length {}".format(varname, maxL, len(var)))
        if isinstance(minL, int):
            if minL > len(var):
                raise ValueError("Variable '{}' is supposed to be larger than {} but is length {}".format(varname, minL, len(var)))

    @staticmethod
    def get_verifying_key_from_address(b58_address):
        decoded_address = KeySwarmCrypto.ensure_bytes(base58.b58decode(b58_address))
        # //TODO: length check
        public_key = nacl.public.PublicKey(decoded_address[:-1])
        check_sum = decoded[-1:]
        if check_sum != pyblake2.blake2s(public_key.encode(), 1).digest():
            raise ValueError("Public Key does not match its attached checksum byte: id='{}', decoded='{}', given checksum='{}', calculated checksum={}".format(b58_address, decoded_address, check_sum, pyblake2.blake2s(public_key.encode(), 1).digest()))
        return public_key

    @staticmethod
    def get_file_sha512(file_path):
        BLOCKSIZE = 65536
        hasher = hashlib.sha512()
        with open(file_path, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        return hasher.hexdigest()



class ProfileSigner(object):
    def __init__(self, ks_session, path):
        self.ks_session = ks_session
        self.path = path
        self.metainfo_path = ""

        self.metainfo_path = os.path.join(path, 'metainfo.json')
        if not os.path.exists(self.metainfo_path):
            with open(self.metainfo_path, 'w'): pass


    def sign(self):
        # //TODO: use this function to walk dir
        # https://www.bogotobogo.com/python/python_traversing_directory_tree_recursively_os_walk.php
        path = self.path
        metaInfoContent = MetaInfoContent()
        metaInfoContent.address = self.ks_session.address.decode('utf-8')
        fname = []
        for root,d_names,f_names in os.walk(path):
            for f in f_names:
                cur_file = os.path.join(root, f)
                fname.append(cur_file)
                #//TODO: fix for json encode
                hashed_file = self.hash_file(cur_file)
                file_dict = { "path" : hashed_file.path, "hash" : hashed_file.hash}
                metaInfoContent.files.append(file_dict)

        print(json.dumps(metaInfoContent.files))

        metaInfoContent.timestamp = int(time.time())
        metaInfo = MetaInfo()
        encoded_content = json.dumps(metaInfoContent.__dict__)
        metaInfo.content = base64.b64encode(encoded_content.encode('utf-8')).decode('utf-8')
        print(metaInfo.content)
        meta_sign = self.ks_session.private_key.sign(encoded_content.encode('utf-8'), encoding='hex')
        metaInfo.signature = ("sha512:" + meta_sign.decode('utf-8'))#.decode('utf-8')
        print("sign: " + metaInfo.signature)

        with open(self.metainfo_path, 'w') as meta_file:
            meta_file.write(json.dumps(metaInfo.__dict__))

        return True

    def hash_file(self, path):
        file_info = MetaInfoFileInfo()
        file_info.path = path#.decode('utf-8')
        file_info.hash = ("sha512:" + KeySwarmCrypto.get_file_sha512(path))#.decode('utf-8')
        #print('pat: ' + file_info.path)
        #print('hash: ' + file_info.hash)
        return file_info

class MetaInfo(object):
    def __init__(self):
        self.content = ""
        self.signature = ""

    def load(self):
        # //TODO: load from file
        # //TODO: verify signature
        pass

    def save(self):
        # //TODO: save to file
        pass

class MetaInfoContent(object):
    def __init__(self):
        self.version = 0
        self.address = ""
        self.files = []
        self.timestamp = 0

class MetaInfoFileInfo(object):
    def __init__(self):
        self.path = ""
        self.hash = ""


class ProfileVerifier(object):
    def __init__(self):
        pass

    def verify(self):
        pass

    def verify_file(self):
        pass

"""
def start_web_app():
    print ('Starting web app')
    app.run(port=WEB_PORT, threaded=True)

def print_bootstrap_lines(line):
    if "Bootstrapped " in line:
        print(term.format(line, term.Color.BLUE))

@app.route('/', methods=['GET'])
def serve_dir_directory_index():
    return send_from_directory(static_file_dir, 'index.html')


@app.route('/<path:path>', methods=['GET'])
def serve_file_in_dir(path):

    if not os.path.isfile(os.path.join(static_file_dir, path)):
        path = os.path.join(path, 'index.html')

    return send_from_directory(static_file_dir, path)


def main():
    print(term.format("Starting Tor:\n", term.Attr.BOLD))

    tor_process = stem.process.launch_tor_with_config(
      config = {
        'tor_cmd': TOR_CMD,
        'SocksPort': str(SOCKS_PORT),
        'ControlPort': str(CONTROL_PORT),
        'ExitNodes': '{ru}',
      },
      init_msg_handler = print_bootstrap_lines,
    )

    # Start the flask web app in a separate thread
    t = threading.Thread(target=start_web_app)
    t.daemon = True
    t.start()

    # Connect to the Tor control port
    try:
        c = Controller.from_port(port=CONTROL_PORT)
        c.authenticate()
    except SocketError:
        print ('Cannot connect to Tor control port')
        sys.exit()

    # Create an ephemeral hidden service
    try:
        print ('Creating hidden service')
        result = c.create_hidden_service(HIDDEN_SERVICE_DIR, 80, target_port=WEB_PORT)
        print (" * Created host: %s" % result.hostname)
        onion = result.hostname
    except UnsatisfiableRequest:
        print ('Cannot create ephemeral hidden service, Tor version is too old')
        sys.exit()
    except Exception, e:
        print e
        sys.exit()

    t.join()
if __name__ == '__main__':
main()
"""

ss = KeySwarmSession("test@example.com", "123455678999")
profileSigner = ProfileSigner(ss, "/home/buchhofe/Github/keyswarm/test")
profileSigner.sign()
