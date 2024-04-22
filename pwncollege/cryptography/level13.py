import sys
import string
import random
import pathlib
import base64
import json
import textwrap
from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits, randrange
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad

def show(name, value, *, b64=True):
    print(f"{name}: {value}")

def show_b64(name, value):
    show(f"{name} (b64)", base64.b64encode(value).decode())

def show_hex_block(name, value, byte_block_size=16):
    value_to_show = ""

    for i in range(0, len(value), byte_block_size):
        value_to_show += f"{value[i:i+byte_block_size].hex()}"
        value_to_show += " "
    show(f"{name} (hex)", value_to_show)


def show_hex(name, value):
    show(name, hex(value))

def input_(name):
    try:
        return input(f"{name}: ")
    except (KeyboardInterrupt, EOFError):
        print()
        exit(0)

def input_b64(name):
    data = input_(f"{name} (b64)")
    try:
        return base64.b64decode(data)
    except base64.binascii.Error:
        print(f"Failed to decode base64 input: {data!r}", file=sys.stderr)
        exit(1)

def input_hex(name):
    data = input_(name)
    try:
        return int(data, 16)
    except Exception:
        print(f"Failed to decode hex input: {data!r}", file=sys.stderr)
        exit(1)
user_key = RSA.generate(1024)

show_hex("user key d", user_key.d)

user_certificate = {
    "name": "user",
    "key": {
        "e": user_key.e,
        "n": user_key.n,
    },
    "signer": "root",
}

user_certificate_data = json.dumps(user_certificate).encode()

user_certificate_hash = SHA256Hash(user_certificate_data).digest()

# second value: root private key from hex to decimal
# third value: n value, from root key certificate
user_certificate_signature = pow( 
    int.from_bytes(user_certificate_hash, "little"),
    9659580497366827821220085696726521126380116216976070776371039979801063339031954281605021832077510696561793023432420987601277686024442077727254179590611956384609808612323484104071360021152999509515386195304039244012261043199101718427722705953666077945076062905415491262247622166063854720832565986166962772272963374852735066504839747127696012835622345845202740771669102958826207766265730665171333291149681276835401765925062135226887018155857731177760185771357535395032900258357133337662982136428425501270707169910085225325367297449577343387616074387205778285788054817440296980629309919237619365657073554592073220021173,
    25795486300997485684220636729880651755580289571214504022615930043241948864174446865658102227201426910358789372152907290280746315790960635984396111396203809285421552351153930188803647768323212878394143189358467083708475520572887937599481000757305533495770427016776278990849068471663380267677357823907431868730970876456403539727537494027537847263818309521082490040364355244025676581363521490047031100804973706287201387832908385561010503911154731009745407707072859162299461944084328350260376598396310047618421207798837262080610930483377268267839462770181981535386318864513065503700353652087720165522267690378778437913807
).to_bytes(256, "little")

show_b64("user certificate", user_certificate_data)
show_b64("user certificate signature", user_certificate_signature)
print("user key: ", user_key.d)

secret_ciphertext=int.from_bytes(base64.b64decode(input("secret cipher: ")), byteorder='little')
ergebnis = pow(secret_ciphertext, user_key.d, user_key.n)
flag = ergebnis.to_bytes((ergebnis.bit_length() + 7) // 8, byteorder='little')
print(flag)
