# CSAW 2020 Qualifiers - modus_operandi


This is a crypto challenge from the CSAW 2020 CTF originally worth 150 points.

The challenge initially tells us to connect as such:

```
$ nc crypto.chal.csaw.io 5001
Hello! For each plaintext you enter, find out if the block cipher used is ECB or CBC. Enter "ECB" or "CBC" to get the flag!
```

We need to tell if the cipher being used to encode our plaintext is ECB or CBC. The big difference is that ECB, which stands for Electronic Code Book, always produces the same ciphertext for a given block.

The first thing to do is figure out the cipher block size. We can do this easily by entering only a letter and check out the size of the output.

```
$ nc crypto.chal.csaw.io 5001
(INITIAL MESSAGE)
Enter plaintext:
a
Ciphertext is:  333b2ddd618ce8a23993af9e094d7769
ECB or CBC?
```

We got `333b2ddd618ce8a23993af9e094d7769` as the ciphertext. Since this is hexadecimal representation, every character is 4 bits, thus making our block size 128 bits (4 * 32).

So to differentiate ECB from CBC we only need to send enough characters in the plaintext and then split our ciphertext every 32 characters (128 bits) and compare the first block of the ciphertext with the second. If these are equal then it's ECB, otherwise it's CBC.

I coded this into python and this is the result:

```python
#!/usr/bin/python3

from pwn import *

p = remote('crypto.chal.csaw.io', 5001)

modes_seq = []

def solve():
    global p
    global modes_seq

    counter = 1
    plaintext = ("a" * 32)
    
    # receive initial message
    p.recvlineS(keepends=False)
    while True:
        # receive plaintext prompt
        p.recvlineS(keepends=False)
        # send plaintext
        p.sendline(plaintext)
        # receive header from line with ciphertext
        p.recvuntilS("Ciphertext is:")
        # receive ciphertext
        cipher = p.recvlineS().strip()
        # receive ECB or CBC prompt
        p.recvlineS(keepends=False)
        # check if it is ECB
        is_ecb = check_equal_with_bs(cipher)
        # send cipher mode
        if is_ecb:
            p.sendline('ECB')
        else:
            p.sendline('CBC')
        print(f"cipher {counter}")
        counter *+= 1


def check_equal_with_bs(cipher):
    bs = 32
    b0 = cipher[:bs]
    b1 = cipher[bs:bs*2]

    if b0 == b1:
        return True


solve()
```

We will send 32 characters since these make up 32 bytes (256 bits), to make our 2 blocks. When we run it we get:

```
python3 solve.py
[+] Opening connection to crypto.chal.csaw.io on port 5001: Done
cipher 1
cipher 2
cipher 3
cipher 4
(...)
cipher 174
cipher 175
cipher 176
Traceback (most recent call last):
  ( EXCEPTION INFO )
EOFError
```

It gave us an EOF after a while. After trying a couple of times we would understand this behaviour is recurrent.

After fiddling a bit (a lot actually) we can get to the result by checking out the cipher modes sequence.

```python
# got this from tweaking the previous script
mode_seqs = ['ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB',
'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB',
'ECB', 'ECB', 'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC',
'CBC', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC',
'ECB', 'ECB', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB',
'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'ECB', 'CBC', 'ECB',
'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC',
'CBC', 'ECB', 'ECB', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC',
'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'ECB', 'ECB', 'ECB', 'ECB',
'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB',
'CBC', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'ECB',
'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'CBC',
'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB',
'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC',
'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC',
'ECB', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'CBC',
'ECB', 'CBC']
binary = ""

for mode in mode_seqs:
    if mode == "ECB":
        binary += "0"
    else:
        binary += "1"

print(binary)
```

Our resulting binary is:
```
0110011001101100011000010110011101111011010001010100001101000010010111110111001
0011001010100000001101100011011000111100101011111011100110101010101100011011010
110010010001111101
```

If we translate this to characters we get `flag{ECB_re@lly_sUck$}`. That's it.
