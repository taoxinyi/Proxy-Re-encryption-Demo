# Proxy Re-Encryption Demo in Python

This is the demo of Proxy Re-Encryption(PRE) which demonstrates how it can be used properly combining with symmetric encryption to achieve extremely high security of user data privacy.

In this case, stream cipher `CHACHA20` and Block Cipher `AES` is used to make sure the proxy(server) cannot get user's private key and the plain data stored on it.

## Usage
```
pip3 install -r requirements.txt
python3 demo.py
```
## Demo/Sample output

```
A    ---------------------Request key pair---------------------->   CA

A    <-----------------A key pair, global param------------------   CA

B    ---------------------Request key pair---------------------->   CA

B    <-----------------B key pair, global param------------------   CA

---------------A want to restore something on the Proxy---------------

Plain msg sent from A:             b'This is a demo'

Seed from A:                       b'\x04+\xa4\xbe\xb9N\x95m(` 1H\x19\
                                   xbf\xe6\n\xe89!\xc8I\xc3q\xd8]C:P\x
                                   da\xdeo\t\xd3\x9eR>\x1d\x19\xc4\xe3
                                   _@D\xdd\\\x8b\x0c'

CHACHA20 msg sent from A:          b'\x87\xe7))\x0bN^i\xb2\x03\xa1\x93
                                   \x97\x96'

PRE encrpyted seed from A:         b'\x93\xda\x00"\x01\x02\xf0\xe8\x9e
                                   \xa6FZ\xbd\xb9KN\x87:\xd5\xdb\x99\x
                                   01\xe3\xadG\xc0\xfc|P&\xe5e\xa7\xbf
                                   }^E1\xda\x00"\x01\x02\x1044\x0c\x18
                                   \x11\xb0#\xa8\xc5=\x9e\xa2\xd8\x9c\
                                   xb4\x8c\xc6\x98p\x93\x91\xfcdW,\xcd
                                   \xce\x8b\xe3j\x1d\xda\x00"\x01\x02\
                                   xf1i\xc4\xa7\x94\xddJA\xb3\xe2B\xd6
                                   \xeeG\xa6\xf8?\x1c\x9e\x05(Q\ra\xae
                                   A\xeco\x1cV\x9f\xb4'

A    -------------(CHACHA20 msg,PRE encrypted seed)------------->PROXY

AES encrypted data on Proxy:       b'\xcd\xef\xb8\xc0h\xbclGC\x85\xbem
                                   O\xd1'

---------------The data is safely restored on the Proxy---------------

------------Of course A can download and see it at anytime------------

A    -------------------Request CHACHA 20 msg------------------->PROXY

A    <--(PRE_enc_seed, PRE_enc_aes_key), Request plain aes_key---PROXY

Plain AES key re-decrypted by A:   b'\x1a\xa4B\xd1\x94\x94\xdd\x15|,q\
                                   xe6\x8f4\x8bk2M\x9c\x0c%\n\xbc}\xe2
                                   \x04\xa2\xe5\xa5\xdf\xd6\xec\xe8\xe
                                   3T\x18\xd5\xd1\xbc\x18\xad\xc2\xcc\
                                   x1b\xda\xbc\x03\xf3'

a    -----------------------plain aes_key----------------------->Proxy

CHACHA20 msg decrypted by Proxy:   b'\x87\xe7))\x0bN^i\xb2\x03\xa1\x93
                                   \x97\x96'

A    <-----------------------CHACHA 20 msg-----------------------Proxy

Seed PRE decrypted by A:           b'\x04+\xa4\xbe\xb9N\x95m(` 1H\x19\
                                   xbf\xe6\n\xe89!\xc8I\xc3q\xd8]C:P\x
                                   da\xdeo\t\xd3\x9eR>\x1d\x19\xc4\xe3
                                   _@D\xdd\\\x8b\x0c'

Plain msg received from A:         b'This is a demo'

-----------Now A successfully received the own correct data-----------

-----------------------A want to send that to B-----------------------

A    -------------Request Re-encryption Key with B-------------->   CA

Re-encryption Key A->B:            b'\x00\xbe\xe9\xfdi\xaa\xe7\xd3\xf8
                                   \xe8&\r\xc9\x8a^\x1af\xdeY<*I\x8b\x
                                   0b\xbb.\x80\x8bR\xd6\xc4\xf3\xeb'

A    <------------------Re-encryption Key A->B-------------------   CA

A    --------------------Re-encryption A->B--------------------->Proxy

Re-encrypted seed:                 b'\x93\xda\x00"\x01\x02\x1d\xd8-t+\
                                   xce\x05x\xd3\xdc\x0fg_\xaa;\xe3\x08
                                   \xfc\xa7\x10\xbb\xba\xafbeG\xb8\x1f
                                   \xa0\xf7\xea<\xda\x00"\x01\x02\x104
                                   4\x0c\x18\x11\xb0#\xa8\xc5=\x9e\xa2
                                   \xd8\x9c\xb4\x8c\xc6\x98p\x93\x91\x
                                   fcdW,\xcd\xce\x8b\xe3j\x1d\xda\x00"
                                   \x01\x02\xf1i\xc4\xa7\x94\xddJA\xb3
                                   \xe2B\xd6\xeeG\xa6\xf8?\x1c\x9e\x05
                                   (Q\ra\xaeA\xeco\x1cV\x9f\xb4'

Re-encrypted AES key:              b'\x93\xda\x00"\x01\x03}>\xb9)5V\x1
                                   e\xa0\xc5\x8d)\x89\xd0+\xb6\xa4\xc1
                                   \x84w\x82\xadL\xe3@\xdd\x01\xcf\xd0
                                   "\xf8L\x10\xda\x00"\x01\x02\x8e\xaa
                                   \xe8\r\x8d% \xfe%<\x95\xa5~1\xd7\xe
                                   6\xc0\xe7\x03\xfe\x1a>b_\x940\xeei\
                                   xf9X\xa9E\xda\x00"\x01\x03\xdb\x9b\
                                   x93Zt\x87-h\xe23\x08+\xd2\xa7\xa5A`
                                   *\xce\x19\x13\xcb\xae\xd6\xfe\xba\x
                                   c8\xdf\x1c.O\n'

B    <---(re_enc_seed, re_enc_aes_key), Request plain aes_key----Proxy

Plain AES key re-decrypted by B:   b'\x1a\xa4B\xd1\x94\x94\xdd\x15|,q\
                                   xe6\x8f4\x8bk2M\x9c\x0c%\n\xbc}\xe2
                                   \x04\xa2\xe5\xa5\xdf\xd6\xec\xe8\xe
                                   3T\x18\xd5\xd1\xbc\x18\xad\xc2\xcc\
                                   x1b\xda\xbc\x03\xf3'

B    -----------------------plain aes_key----------------------->Proxy

CHACHA20 msg decrypted by Proxy:   b'\x87\xe7))\x0bN^i\xb2\x03\xa1\x93
                                   \x97\x96'

B    <-----------------------CHACHA 20 msg-----------------------Proxy

Seed re-decrypted by B:            b'\x04+\xa4\xbe\xb9N\x95m(` 1H\x19\
                                   xbf\xe6\n\xe89!\xc8I\xc3q\xd8]C:P\x
                                   da\xdeo\t\xd3\x9eR>\x1d\x19\xc4\xe3
                                   _@D\xdd\\\x8b\x0c'

Plain msg received from B:         b'This is a demo'

---------Now B successfully received the correct data from A----------

```
## Advantage
- The client(user) only needs to caculate stream cipher and PRE on keys, which is very fast.
- Using symmetric encryption like CHACHA20 and AES, make the actual data size the same as the plain data, therefore the data stored on proxy(server) will be the same.
- The proxy(server) knows nothing about the secrete key of any users and the actual plain data. What is actually stored is the data which has been encrypted twice (`CHACHA20` and `AES`), along with PRE encrypted`seed`(`CHACHA20` key) and `aes_key`.
- All the data during the transmission is encrypted as well.
