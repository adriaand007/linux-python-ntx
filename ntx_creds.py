#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import base64
import getpass
import configparser
import argparse
from Crypto import Random
from Crypto.Cipher import AES

class AuthenticationAPI(object):
    __doc__ = ''' '''

    def __init__(self):
        # Initialise the options.
        self.enc_ip_addr = None
        self.enc_username = None
        self.enc_password = None
        self.dec_ip_addr = None
        self.dec_username = None
        self.dec_password = None

    def get_creds(self, path_to_Creds):
        #Only go get the encrypted passwords
        file = open(path_to_Creds, 'r').read().splitlines()
        self.enc_ip_addr = file[0]
        self.enc_username = file[1]
        self.enc_password = file[2]

    def encryption(self, ip_addr, username, password, passphrase):
        self.enc_ip_addr = self.encrypt_aes(ip_addr, passphrase)
        self.enc_username = self.encrypt_aes(username, passphrase)
        self.enc_password = self.encrypt_aes(password, passphrase)

    def decryption(self, enc_ip_addr=None, enc_username=None, enc_password=None, passphrase=None):
        # Set the decryption, unless already done
        if enc_ip_addr != None:
            self.dec_ip_addr = self.decrypt_aes(enc_ip_addr, passphrase)
        else:
            self.dec_ip_addr = self.decrypt_aes(self.enc_ip_addr, passphrase)
        if enc_username != None:
            self.dec_username = self.decrypt_aes(enc_username, passphrase)
        else:
            self.dec_username = self.decrypt_aes(self.enc_username, passphrase)
        if enc_password != None:
            self.dec_password = self.decrypt_aes(enc_password, passphrase)
        else:
            self.dec_password = self.decrypt_aes(self.enc_password, passphrase)

    def encrypt_aes(self, input, passphrase):
        IV = Random.new().read(16)
        IV_base = base64.b64encode(IV)
        aes = AES.new(passphrase[:16], AES.MODE_CFB, IV)
        aes_encryption = IV_base + base64.b64encode(aes.encrypt(input))
        return aes_encryption

    def decrypt_aes(self, input, passphrase):
        IV = base64.b64decode(input[:24])
        aes = AES.new(passphrase[0:16], AES.MODE_CFB, IV)
        return aes.decrypt(base64.b64decode(input[23:]))

def yes_or_no(question):
    reply = str(raw_input(question+' Default (Y) (y/n): ')).lower().strip()
    if len(reply) == 0:
        return True
    elif reply[0] == 'y':
        return True
    elif reply[0] == 'n':
        return False
    else:
        print "Uhhhh... please enter "
        return False

def write_uuid(suuidvalue, cfgfile):
    Config.read(cfgfile)
    readsections = Config.sections()
    sectionname = "ruuid"
    Config[sectionname] = {}
    Config[sectionname]['suuid'] = suuidvalue
    with open(options.filename, 'w') as configfile:
        Config.write(configfile)

def read_dec_cfg(cfgfile):
    authapi = AuthenticationAPI()
    print "Decoding"
    Config.read(cfgfile)
    readsections = Config.sections()
    for sectionreadname in readsections:
        if "server" in sectionreadname:
            print "Section:".ljust(12), "[" + sectionreadname + "]"
            DATA_READ = dict(Config.items(sectionreadname))
            authapi.decryption(DATA_READ['server_addr'], DATA_READ['username'], DATA_READ['value'], Config['ruuid']['suuid'])
            print "Username:".ljust(12), authapi.dec_username
            print "IP Address:".ljust(12), authapi.dec_ip_addr
            pwdlen = len(authapi.dec_password)/2
            print "Password:".ljust(12), authapi.dec_password[:pwdlen] + "#" * pwdlen

def read_cfg(cfgfile):
    Config.read(cfgfile)
    readsections = Config.sections()
    for sectionreadname in readsections:
        print "[" + sectionreadname + "]"
        DATA_READ = dict(Config.items(sectionreadname))
        for item in DATA_READ:
            print item + ":", DATA_READ[item]
        print "\n"

def write_cfg(WUSERNAME, WIPADDR, WPASSWD, WSYSNAME, cfgfile):
    authapi = AuthenticationAPI()
    Config.read(cfgfile)
    readsections = Config.sections()
    authapi.encryption(WIPADDR, WUSERNAME, WPASSWD, Config['ruuid']['suuid'])
    sectionname = "server-" + WSYSNAME
    Config[sectionname] = {}
    Config[sectionname]['server_addr'] = authapi.enc_ip_addr
    Config[sectionname]['username'] = authapi.enc_username
    Config[sectionname]['value'] = authapi.enc_password
    if options.writecfg == True:
        with open(options.filename, 'w') as configfile:
            Config.write(configfile)

def cfg_logic():
    UPASSWORD = ''
    if options.writeuuid == True:
        if len(options.filename) == 0:
            print "Please specifiy a Config File"
            sys.exit(1)
        else:
            if len(options.suuid) == 0:
                print "Please specify System UUID"
            else:
                print "Wrinting UUID to Config file"
                write_uuid(options.suuid, options.filename)
                print "Done"
                sys.exit(1)

    if options.decreadcfg == True:
        if len(options.filename) == 0:
            print "Please specifiy a Config File"
            sys.exit(1)
        elif os.path.isfile(options.filename) == False:
            print "Config file does not exist"
            print "Please use -W and -U options to create Config file"
            sys.exit(1)
        else:
            print "Reading and decoding Config file"
            read_dec_cfg(options.filename)
            print "Done"
            sys.exit(1)

    if options.readcfg == True:
        if len(options.filename) == 0:
            print "Please specifiy a Config File"
            sys.exit(1)
        elif os.path.isfile(options.filename) == False:
            print "Config file does not exist"
            print "Please use -W and -U options to create Config file"
            sys.exit(1)
        else:
            print "Reading Config file and displaying\n\n"
            read_cfg(options.filename)
            print "\n\nDone"
            sys.exit(1)

    if options.writecfg == True:
        if len(options.filename) == 0:
            print "Please specifiy a Config File"
            sys.exit(1)
        else:
            if os.path.isfile(options.filename) == False:
                print "Config file does not exist"
                print "Please use -W and -U options to create Config file"
                sys.exit(1)
            if len(options.systemname) != 0:
                WSYSNAME = options.systemname
            else:
                WSYSNAME = raw_input("What is the System name? ")
                if len(WSYSNAME) == 0:
                    print "ERROR:"
                    sys.exit(1)
            if len(options.username) != 0:
                WUSERNAME = options.username
            else:
                WUSERNAME = raw_input("What is the System Admin user name? ")
                if len(WUSERNAME) == 0:
                    print "ERROR:"
                    sys.exit(1)
            if len(options.ipaddr) != 0:
                WIPADDR = options.ipaddr
            else:
                print "No IP Address specified, Use Default"
                usedefault = yes_or_no("Use localhost")
                if usedefault == True:
                    WIPADDR = '127.0.0.1'
                else:
                    WIPADDR = raw_input("Please provide IP Address: ")
                    if len(WIPADDR) == 0:
                        print "No IP Address Specified"
                        sys.exit(1)
            if len(UPASSWORD) != 0:
                WPASSWORD = UPASSWORD
            else:
                print "No Password specified"
                UPASSWORD = getpass.getpass("Password for new system: ")
                if UPASSWORD == 0:
                    print "No passsword"
                    sys.exit(1)
                else:
                    WPASSWORD = UPASSWORD

            print "Writing Config file\n\n"
            write_cfg(WUSERNAME, WIPADDR, WPASSWORD, WSYSNAME, options.filename)
            print "\n\nDone"
            sys.exit(1)



if __name__ == '__main__':
    UPASSWORD = ''
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-f", "--file", dest="filename", default="ntx_info.conf", help="Config file to read")
    parser.add_argument("-i", "--ipaddr", dest="ipaddr", default="", help="IP Address")
    parser.add_argument("-u", "--username", dest="username", default="", help="Username")
    parser.add_argument("-s", "--systemname", dest="systemname", default="", help="System name")
    parser.add_argument("-D", "--debug", action="store_true", dest="optionsdebug", default=False, help="Print debug")
    parser.add_argument("-w", "--write", action="store_true", dest="writecfg", default=False, help="Write Authentication data to config file")
    parser.add_argument("-W", "--writeuuid", action="store_true", dest="writeuuid", default=False, help="Write UUID data to config file")
    parser.add_argument("-U", "--suuid", dest="suuid", default="", help="System UUID")
    parser.add_argument("-r", "--read", action="store_true", dest="readcfg", default=False, help="Read and Print Authentication data to config file")
    parser.add_argument("-R", "--decread", action="store_true", dest="decreadcfg", default=False)
    options = parser.parse_args()

    Config = configparser.ConfigParser()
    Config.read(options.filename)

    cfg_logic()
