# CSAW 2020 Finals - hybrid2


In this crypto challenge we are provided with 3 files. `encrypted_flag.txt`, `values.txt` and `RSA.py`. This is their content respectively:

```
gAAAAABfprGds2-Sl4iF5BMjjotnTDKFPsfL8AtJOOeeruqB4w8RGk5gNUt0JM0q2xDve9x9PNHkNkk7f9rf1LekcIBjT1MHIIrvIlnhGqunRRwX59Eo42M=
```

```
n1:993026244695684152720385884540934236152899333556368140632626642931977663455763577814539451675010742634734414120506873127681575400889367126382788249627522167388706763687223391964637583980012499335053836288149762800461352926871
c1:919185245450085070842500396016408106190564102841807386352380063509870500097738484099609889796995083614948316196284397915697587992595215560226954302540303441147142319086774144200044451484633098049523092465251856761343186171446
n2:2120858645090903183026514121355650736640788936981118406136042282902569410681811232597743281933258598295558440757608733371867831987066752871107340815085437033645770613051826725100320202337307710202802730187794048230226233246437
c2:1208266765754514111395360277918056208640323550343906922007564328002144299927657437792873335826000580646064707967588174785153292261822967987055788013175865915201771920259922766547552097804855479381196953971070003030552476914575
n3:13566626315514098994196793247987944584439249998535190838667639010645726083604266690794903208593054256985816076154703189151830750410096794348919817516657177422145305767806102534164484511642213686511016911921215486685198372816147
c3:1217497400118662279329845790782375666818255286641902450369699752528387025736733412718188595857511268363598010406858933873651883505914392791968214369018429930629428806698086713411413268400019005784163187283297818419415844058298
n4:3781687268076859825619936261231343132436633759923146857815563164944282031661985906371461417791140109723961921392569564055561036370381503090194581545155223783851590130524287100727964018153092190082596699871644182610730089104887
c4:1581630010861681991426638552365806430756733284791722127829411178122452158350095552531779719660231210643815340517737141369431301977856820846393801475741850207897534313201631075802421935603144591231461900365190172816004331334424
e:5
```

```python
import random
import string
from rsa_values import checkKeys, n1, n2, n3, n4, e

def get_random_string(length):
    characters = string.ascii_letters+string.digits
    result = ''.join(random.choice(characters) for i in range(length))
    return result

def RSAEncrypt(password, n, e):
 c = (int(password.encode('utf-8').hex(),16) ** e) % n
 return c

def main():
 password = get_random_string(32)
 print(password)
 checkKeys()
 c1 = RSAEncrypt(password,n1,e)
 c2 = RSAEncrypt(password,n2,e)
 c3 = RSAEncrypt(password,n3,e)
 c4 = RSAEncrypt(password,n4,e)

 file = open("values.txt",'w')
 file.write("n1:" + str(n1) + '\n')
 file.write("c1:" + str(c1) + '\n')
 file.write("n2:" + str(n2) + '\n')
 file.write("c2:" + str(c2) + '\n')
 file.write("n3:" + str(n3) + '\n')
 file.write("c3:" + str(c3) + '\n')
 file.write("n4:" + str(n4) + '\n')
 file.write("c4:" + str(c4) + '\n')
 file.write("e:" + str(e) + '\n')
 file.close()

if __name__ == '__main__':
 main()
```

So after reading the script we understand what's going on. We have a `password` that is being encrypted using RSA. The exponent is constant and is equal to 5. There are 4 moduli and they are all different. We know this because these values are being written to `values.txt`. The last crucial piece written to that file is the resulting ciphertext of encrypting the password with a different modulo each.

I was first mislead to believe this was a low exponent attack or a Hastad's broadcast attack, but in this case the Hastad implied that we had as many ciphertexts and moduli as the value of the exponent (not the case 4 != 5). After eliminating those hypothesis I went back to the basics and tried to factor any of the modulo. So it happened the first modulo was factorizable. From that i wrote this script (clearly "inspired" from [here](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_module_attack/)).

```python
from Crypto.Util.number import inverse, long_to_bytes
from factordb.factordb import FactorDB

N = 993026244695684152720385884540934236152899333556368140632626642931977663455763577814539451675010742634734414120506873127681575400889367126382788249627522167388706763687223391964637583980012499335053836288149762800461352926871
e = 5
c = 919185245450085070842500396016408106190564102841807386352380063509870500097738484099609889796995083614948316196284397915697587992595215560226954302540303441147142319086774144200044451484633098049523092465251856761343186171446

f = FactorDB(N)
f.connect()
factors = f.get_factor_list()
print(factors)

phi = 1
for factor in factors:
    phi *= factor - 1

d = inverse(e, phi)
m = pow(c, d, N)
password = long_to_bytes(m).decode()

print(password)
```

After running i got this password: `xYDFDoqcOACPKeT5gT0wBzAfBSoGieVc`.
Now we have to do something with this password and the encrypted flag. After googling a lot for formats there was a hint in the challenge saying this was symmetric authenticated cryptography. I searched for that and found something called Fernet encryption that had tokens that looked a lot like the encrypted flag I had. I looked for a decoder online and found a python library. One of the requisites was that we had to have the password in base64 so I made sure of that.

```python
from cryptography.fernet import Fernet

key = "eFlERkRvcWNPQUNQS2VUNWdUMHdCekFmQlNvR2llVmM="
token = b"gAAAAABfprGds2-Sl4iF5BMjjotnTDKFPsfL8AtJOOeeruqB4w8RGk5gNUt0JM0q2xDve9x9PNHkNkk7f9rf1LekcIBjT1MHIIrvIlnhGqunRRwX59Eo42M="
f = Fernet(key)
print(f.decrypt(token))
```

This got us the flag and we are done! :slightly_smiling_face:
