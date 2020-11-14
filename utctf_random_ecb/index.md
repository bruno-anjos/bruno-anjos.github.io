# UTCTF - Random ECB


# Introduction

First and foremost there is a very good explanation how AES ECB can be exploited through a chosen plaintext attack [here](https://zachgrace.com/posts/attacking-ecb/). The problem can be visualized in these two pictures:

{{< figure src="/tux_normal.jpg">}} {{< figure src="/tux_ecb.jpg">}}

As you can see even though the image was encrypted, Tux (the penguin) is still sort of visible in the result. This is due to the fact that AES ECB works in a standard codebook fashion, where each input has a ciphertext associated. This meaning that if you encrypt the same block over and over, the result will be exactly the same. Knowing this we can devise a chosen plaintext attack.

The attack is very easy to understand, and if i am not clear enough or confuse you please go check the link that i mentioned previously. In sum, the attack can be done by sending plaintext with **block_size-1** length, letting one of the secret bytes into our block. Then the plaintext of that block is all known except the last byte, so we just need to brute force the last byte. Easy right?

Now onto the challenge.

## Challenge

The challenge made available the server source code, so let's take a look at it.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from secret import flag

KEY = get_random_bytes(16)


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def encryption_oracle(plaintext):
    b = getrandbits(1)
    plaintext = pad((b'A' * b) + plaintext + flag, 16)
    return aes_ecb_encrypt(plaintext, KEY).hex()


if __name__ == '__main__':
    while True:
        print("Input a string to encrypt (input 'q' to quit):")
        user_input = input()
        if user_input == 'q':
            break
        output = encryption_oracle(user_input.encode())
        print("Here is your encrypted string, have a nice day :)")
        print(output)

```

So at first there are no easy shortcuts, like the key being in plaintext (it's 16 random bytes). The function **aes_ecb_encrypt** is responsible for doing the encryption itself, and it's called in **encryption_oracle**. The latter is more interesting, since it first calls the **getrandbits** function. After a google search we can confirm the function does what was expected:

```
Crypto.Random.random.getrandbits(N):
  Return a random integer, at most N bits long.
```

So pretty much it's generating a number with at most 1 bit. With 1 bit it can only be either 0 or 1. Since this number is then multiplied by **'A'**, the result will be a string with length 0 or 1, so it's either adding one byte of padding or not adding padding at all. The string that makes the plaintext is composed first by this padding, then the plaintext that we send, and finally the flag.

The way i tackled this challenge was by making a python script that was split into three main stages. First getting what was considered the correct first block. In order to do this i generated two full blocks of padding and send them. *'Why two?'* you might be asking, well if we only sent one we would not know if a random byte was added or not, so by sending two, we can be sure that if the first block is equal to the second, no random bytes were added (remember to make your padding different than theirs, in other words don't use **A** for your padding, i made that mistake :) ). After getting a result where the first block is equal to the second we can use the first block as what determines if the result has or not a random byte. In case the first block retrieved is equal to what we just saw we can conclude that no bytes were added.

Then we have a stage where we find the target, in other words, we send a padding block plus a block with length **block_size-1**, allowing a byte from the secret to fall into our block. We then get the encrypted result and store this as "the target".

Finally we have the last stage. This stage is where we brute force the byte that was encrypted in "the target". In order to to this we send the same block sent previously with **block_size-1** bytes and append **a**. If what we get back is the same, then we know that the secret started with an **a**. If it's different we try **b**, and keep going through the whole alphabet and symbols until we eventually get the same encrypted block back.

After we get our first byte we just have to remove a byte from our padding (that was **block_size-1** long) making it **block_size-2** long, which will let 2 bytes from the secret into our block that will be bruteforced. We already know the first, so we just need to bruteforce the second one. This is then repeated until we get the whole flag.

This is the final python script:

```python
import sys
import socket
from textwrap import wrap
import string

hostname = "ecb.utctf.live"
port = 9003

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
reader = sock.makefile('rw')

ignore = ["Input a string to encrypt (input 'q' to quit):",
        "Here is your encrypted string, have a nice day :)"]

print(reader.readline())
block_size = 16
final_blocks = 'B'*block_size*2
alphabet = string.ascii_letters + string.digits + " .[]{}!,:;?=-_+"

def encrypt_bytes(text):
    text += "\n"
    sock.sendall(text.encode())
    reader.readline()
    result = reader.readline()
    reader.readline()
    return wrap(result, block_size * 2)

def find_offset():
    offset = 0
    for i in range(0, block_size):
        offset_try = 'B' * (block_size-i)
        tosend = offset_try + final_blocks
        print("Trying offset " + str(i) + " with input " + tosend)
        splitted = encrypt_bytes(tosend)
        print(splitted)
    
        if splitted[1] == splitted[2]:
            print("offset = " + str(i))
            offset = i
            break
    return offset

full_block = "B" * block_size
block_number = 1

def find_target(static):
    global full_block
    global block_number

    to_encrypt = full_block + full_block + static
    splitted = encrypt_bytes(to_encrypt)
    while splitted[0] != splitted[1]:
        splitted = encrypt_bytes(to_encrypt)
    print("New target: " + splitted[3])
    return (splitted[0], splitted[3])

global_result = ""

def brute_force_byte(static, first_block, target):
    global alphabet
    global global_result
    global full_block
    global block_number

    for c in alphabet:
        static_with_chars = static + global_result + c
        to_encrypt = full_block + static_with_chars
        splitted = encrypt_bytes(to_encrypt)

        while splitted[0] != first_block:
            splitted = encrypt_bytes(to_encrypt)

        print("Trying " + c)

        if splitted[2] == target:
            print("Found " + c)
            return c

    return "ERROR"

static = ('B' * block_size) + 'B' * (block_size-1)
first_block, target = find_target(static)
while True:
    print("Sending (" + str(len(static)) + "): " + static)
    result = brute_force_byte(static, first_block, target)
    global_result += result
    static = static[1:]
    print("Global Result: " + global_result)
    _, target = find_target(static)
```

I was very proud of solving this challenge, that even though was only worth 50 points, only 100 and something teams solved out of 1000. I was also proud since i had studied this subject in college and had never put into practice. After analyzing the script there are a few things that can be simplified, but i left the script as it was when i solved the challenge.

