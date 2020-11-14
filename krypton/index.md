# Over The Wire - Krypton Walkthrough


# Introduction

[Over The Wire](http://overthewire.org/wargames/) provides multiple challenges focused on different topics of computer systems.
The one which we will solve here is Krypton. This is challenge is focused on cryptography.

You can read more about the challenge and how it works [here](http://overthewire.org/wargames/krypton/).

Levels:

- [Level 0](#level-0)
- [Level 1](#level-1)
- [Level 2](#level-2)
- [Level 3](#level-3)
- [Level 4](#level-4)
- [Level 5](#level-5)
- [Level 6](#level-6)


## Level 0

The password is a base64 encoded string. We can use the **base64** command. Let's check the manual.

```
NAME
       base64 - base64 encode/decode data and print to standard output

SYNOPSIS
       base64 [OPTION]... [FILE]

DESCRIPTION
       Base64 encode or decode FILE, or standard input, to standard output.

       With no FILE, or when FILE is -, read standard input.

       Mandatory arguments to long options are mandatory for short options too.

       -d, --decode
              decode data
```

This is exactly what we want. We wneed to use the `-d` flag to decode, and we will pipeline the string with the **echo** command.


```bash
> echo "S1JZUFRPTklTR1JFQVQ=" | base64 -d                                                         KRYPTONISGREAT%
>
```

The `%` does not make part of the string from what i understand. This password allows us to connect to `krypton.labs.overthewire.org` as `krypton1` on port `2222`. From now on the files that we need for the challenges will be in the `/krypton/` directory.

## Level 1

As we've mentioned before all the challenges from now on will be in the `/krypton/` directory so if we go there and list the files we get this.

```bash
krypton1@krypton:/krypton$ ls -la
total 32
drwxr-xr-x  8 root root 4096 Jul  1 04:21 .
drwxr-xr-x 92 root root 4096 Jul  7 14:54 ..
drwxr-xr-x  2 root root 4096 Jul  1 04:20 krypton1
drwxr-xr-x  2 root root 4096 Jul  1 04:20 krypton2
drwxr-xr-x  2 root root 4096 Jul  1 04:20 krypton3
drwxr-xr-x  2 root root 4096 Jul  1 04:20 krypton4
drwxr-xr-x  2 root root 4096 Jul  1 04:20 krypton5
drwxr-xr-x  3 root root 4096 Jul  1 04:21 krypton6
```

We are currently in [Level 1](#level-1) so let's change to the correct folder and list its content.

```
krypton1@krypton:/krypton$ cd krypton1
krypton1@krypton:/krypton/krypton1$ ls -la
total 16
drwxr-xr-x 2 root     root     4096 Jul  1 04:20 .
drwxr-xr-x 8 root     root     4096 Jul  1 04:21 ..
-rw-r----- 1 krypton1 krypton1  882 Jul  1 04:20 README
-rw-r----- 1 krypton1 krypton1   26 Jul  1 04:20 krypton2
```

We should check out the README to get more insight on this challenge.

>Welcome to Krypton!

>This game is intended to give hands on experience with cryptography and cryptanalysis.  The levels progress from classic ciphers, to modern, easy to harder. Although there are excellent public tools, like cryptool,to perform the simple analysis, we strongly encourage you to try and do these without them for now.  We will use them in later excercises.

>** Please try these levels without cryptool first **


>The first level is easy.  The password for level 2 is in the file 'krypton2'.  It is 'encrypted' using a simple rotation called ROT13. It is also in non-standard ciphertext format.  When using alpha characters for cipher text it is normal to group the letters into 5 letter clusters, regardless of word boundaries.  This helps obfuscate any patterns.

>This file has kept the plain text word boundaries and carried them to the cipher text.

>Enjoy!


ROT13 should be easy. We've messed with this previously in [Bandit](https://bruno-anjos.github.io/posts/bandit/) using the **tr** command. There is a simple example in the wiki page of ROT13 with an implementation of ROT13 using the **tr** command.

```bash
krypton1@krypton:/krypton/krypton1$ cat krypton2 | tr 'N-ZA-Mn-za-m' 'A-Za-z'
LEVEL TWO PASSWORD ROTTEN
```

We switched the letter patterns since the example is to encode and we want to **decode**. We have the password for the next level, let's go.

## Level 2

From now on i'll just change the to the challenge directory and **cat** the README.md without pasting it here explicitly.

>Krypton 2

>ROT13 is a simple substitution cipher.

>Substitution ciphers are a simple replacement algorithm.  In this example of a substitution cipher, we will explore a 'monoalphebetic' cipher. Monoalphebetic means, literally, "one alphabet" and you will see why.

>This level contains an old form of cipher called a 'Caesar Cipher'.A Caesar cipher shifts the alphabet by a set number.  For example:
>plain:  a b c d e f g h i j k ...
>cipher: G H I J K L M N O P Q ...

>In this example, the letter 'a' in plaintext is replaced by a 'G' in the ciphertext so, for example, the plaintext 'bad' becomes 'HGJ' in ciphertext.

>The password for level 3 is in the file krypton3.  It is in 5 letter group ciphertext.  It is encrypted with a Caesar Cipher.  Without any further information, this cipher text may be difficult to break.  You do not have direct access to the key, however you do have access to a program that will encrypt anything you wish to give it using the key. If you think logically, this is completely easy.

>One shot can solve it!

>Have fun.

>Additional Information:

>The `encrypt` binary will look for the keyfile in your current working directory. Therefore, it might be best to create a working direcory in /tmp and in there a link to the keyfile. As the `encrypt` binary runs setuid `krypton3`, you also need to give `krypton3` access to your working directory.

>Here is an example:
```bash
krypton2@melinda:~$ mktemp -d
/tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:~$ cd /tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ln -s /krypton/krypton2/keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ chmod 777 .
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ /krypton/krypton2/encrypt /etc/issue
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
ciphertext  keyfile.dat
```

So we have to figure out what's the rotation in this case. We should be able to do that by just encrypting the letter `a`. 

```bash
krypton2@krypton:/krypton/krypton2$ ./encrypt 

 usage: encrypt foo  - where foo is the file containing the plaintext
```

We need to create a file. Let's create a temporary directory and a file containing just the letters `aA` then.

```bash
krypton2@krypton:/krypton/krypton2$ mkdir /tmp/tempfolder
krypton2@krypton:/krypton/krypton2$ vi /tmp/tempfolder/testFile
krypton2@krypton:/krypton/krypton2$ cat /tmp/tempfolder/testFile 
aA
```

We also need to link the `keyfile.dat` to our temporary directory and then give permissions so the binary can run.

```bash
krypton2@krypton:/krypton/krypton2$ cd /tmp/tempfolder
krypton2@krypton:/tmp/tempfolder$ ln -s /krypton/krypton2/keyfile.dat
krypton2@krypton:/tmp/tempfolder$ chmod 777 .
krypton2@krypton:/tmp/tempfolder$ ls -la
total 12
drwxrwxrwx 2 krypton2 krypton2 4096 Jul  7 15:30 .
drwxrwx-wt 3 root     root     4096 Jul  7 15:32 ..
lrwxrwxrwx 1 krypton2 krypton2   29 Jul  7 15:30 keyfile.dat -> /krypton/krypton2/keyfile.dat
-rw-rw-r-- 1 krypton2 krypton2    2 Jul  7 15:27 testFile
```

Now we just need to run the binary on the file we've just created.

```bash
krypton2@krypton:/tmp/tempfolder$ /krypton/krypton2/encrypt testFile 
krypton2@krypton:/tmp/tempfolder$ ls -la
total 16
drwxrwxrwx 2 krypton2 krypton2 4096 Jul  7 15:33 .
drwxrwx-wt 3 root     root     4096 Jul  7 15:33 ..
-rw-rw-r-- 1 krypton3 krypton2    1 Jul  7 15:33 ciphertext
lrwxrwxrwx 1 krypton2 krypton2   29 Jul  7 15:30 keyfile.dat -> /krypton/krypton2/keyfile.dat
-rw-rw-r-- 1 krypton2 krypton2    2 Jul  7 15:27 testFile
```

Let's check the resulting `ciphertext`.

```bash
krypton2@krypton:/tmp/tempfolder$ cat ciphertext 
MM
```

So that tells us that it's rotating from `aA` to `MM`. So to decode we just have to do the other way around. Let's modify our previous **tr** command with the rotation we want.

We had `tr 'N-ZA-Mn-za-m' 'A-Za-z'` now what we want is to rotate from `M` to `A`. You should end up with `tr 'M-ZA-L' 'A-Z'`.

Let's try it on our file to see if we get our `AA` back. As we've seen before the encryption rotates any letter to uppercase no matter what case it was originally.

```bash
krypton2@krypton:/tmp/tempfolder$ cat ciphertext | tr 'M-ZA-L' 'A-Z'
AA
```

We got `AA` so this should be able to decrypt our initial `krypton3` file.

```bash
krypton2@krypton:/tmp/tempfolder$ cd /krypton/krypton2/
krypton2@krypton:/krypton/krypton2$ cat krypton3 | tr 'M-ZA-L' 'A-Z'
CAESARISEASY
```

We got it. Next one.

## Level 3

As always first check the `README.md`,

>Well done.  You've moved past an easy substitution cipher.
>
>Hopefully you just encrypted the alphabet a plaintext 
>to fully expose the key in one swoop.
>
>The main weakness of a simple substitution cipher is 
>repeated use of a simple key.  In the previous exercise
>you were able to introduce arbitrary plaintext to expose
>the key.  In this example, the cipher mechanism is not 
>available to you, the attacker.
>
>However, you have been lucky.  You have intercepted more
>than one message.  The password to the next level is found
>in the file 'krypton4'.  You have also found 3 other files.
>(found1, found2, found3)
>
>You know the following important details:
>
> - The message plaintexts are in English (*** very important)
> - They were produced from the same key (*** even better!)
>
>
>Enjoy.

In this case we don't have access to the encryption method. I know for a fact that these types of ciphers are weak to attacks based on frequency analysis, this meaning that for example in the english language the most common letter is `e` so in the text that we have, the letter that appears the most times, SHOULD be the result of rotating `e`. And from that point we can calculate the key. Let's find a website that does frequency analysis of text. I found this one https://www.dcode.fr/frequency-analysis.

After pasting all of the `found*` files content we get this output on the website:

{{< figure src="/freq_analysis.png">}}

So now we know that the most common letter in the text is `S` so we could assume that to decode we need to perform this rotation `tr 'S-ZA-R' 'E-ZA-D'`.

Let's try it then,

```bash
krypton3@krypton:/krypton/krypton3$ cat krypton4 | tr 'S-ZA-R' 'E-ZA-D'
WEHHI NSEVP EHEUE HJNYZ KCGGW NZIOG MZYVE
```

Hmmm... Doesn't seem like it's correct.

After reading the `README.md` again i understand what i did wrong... I was assuming that this was a rotation cipher again. It's not it's substitution. So what we actually have to do is replace the most common letter in the analysis by the most common letter in the english alphabet, and so on.

We can use a quick python script. I got this english frequency, "EARIOTNSLCUDPMHGBFYWKVXZJQ", from [here](https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language).


```python
real_freq = "EARIOTNSLCUDPMHGBFYWKVXZJQ"
cipher_freq = "SQJUBNCGDZVWMYTXKELAFIOHRP"
cipher_text = "KSVVW BGSJD SVSIS VXBMN YQUUK BNWCU ANMJS"
real_text = ""

for letter in cipher_text:
    if letter not in real_freq:
        real_text += letter
    else:
        real_text += real_freq[cipher_freq.find(letter)]

print real_text
```

This should do it.

Spoiler alert that doesn't do it. In fact the frequency analysis goes deeper than this since some letters have a wrong correspondence, so you would have to do analysis of bigrams and trigrams. I started making a more advanced script but then i found a good website that does it.

https://www.guballa.de/substitution-solver

{{< figure src="/freq_analysis_2.png">}}

As you can see the text makes sense even though it's broken into 5 characters. This should do it as our correct decryption key. We just need to change a few things in our script.

**NOTE:** I worked on my own computer instead of in the normal ssh connection.

```python
real_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
cipher_alphabet = "QAZWSXEDCRFVTGBYHNUJMIKOLP"
cipher_text = "KSVVW BGSJD SVSIS VXBMN YQUUK BNWCU ANMJS"
real_text = ""

for letter in cipher_text:
    if letter not in real_alphabet:
        real_text += letter
    else:
        real_text += real_alphabet[cipher_alphabet.find(letter)]

print real_text
```

```bash
> python ~/Desktop/krypton3/simple_crack.py
WELLD ONETH ELEVE LFOUR PASSW ORDIS BRUTE
>   
```

We got the password! This would be much harder if we hadn't find that online tool. Next one!

## Level 4

So now we have a vigenere cipher. This kind of cipher is the result of adding the plaintext with a key, so now a character doesn't have a direct correspondence since it depends which character of the key was added. If you search online you will eventually understand that we can just apply the same logic as before but you have to use modulus.

We can use [this](https://www.dcode.fr/vigenere-cipher), to decode and do the analysis for us.

As we can see here, there are multiple possible keys, but the one that makes sense and transforms our cipher text into readable text is the first one.

{{< figure src="/vigenere_analysis.png">}}

In this case our key is `FREKEY`

So when we decrypt our encrypted text we get the following

{{< figure src="/vigenere_analysis_2.png">}}

Without the spaces of course.


## Level 5

Once again we can use the website previously mentioned.

{{< figure src="/krypton5.png">}}

They suggest `KEYZTBGTH` as the key. This seems random, but if we look closer there's `KEY` and then ends in `GTH` it seems like `KEYLENGTH` we should try to decrypt using `KEYLENGTH` as the key.

{{< figure src="/krypton5_2.png">}}

Ok we got the word `RANDOM` it can't be coincidence. After trying to connect, you can see that the password is right.


