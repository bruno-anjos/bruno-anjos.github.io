# Over The Wire - Bandit Walkthrough


# Introduction

[Over The Wire](http://overthewire.org/wargames/) provides multiple challenges focused on different topics of computer systems.
The one which we will solve here is Bandit. This is focused on SSH communication, bash commands and some basic UNIX concepts.

To connect to any of these levels you need 2 things: a username, and a password. Each level has a username in the format **bandit\<level_number\>** (without the '<' '>') so for level 0 the username would be **bandit0**. Then each level also has a password. Usually you find the password for the next level on the current one, this meaning that in level 0 you will find the password for level 1, which you will login with **bandit1** and the password you found.

You can read more about the challenge and how it works [here](http://overthewire.org/wargames/bandit/).

Levels:

- [Introduction](#introduction)
  - [Level 0](#level-0)
  - [Level 1](#level-1)
  - [Level 2](#level-2)
  - [Level 3](#level-3)
  - [Level 4](#level-4)
  - [Level 5](#level-5)
  - [Level 6](#level-6)
  - [Level 7](#level-7)
  - [Level 8](#level-8)
  - [Level 9](#level-9)
  - [Level 10](#level-10)
  - [Level 11](#level-11)
  - [Level 12](#level-12)
  - [Level 13](#level-13)
  - [Level 14](#level-14)
  - [Level 15](#level-15)
  - [Level 16](#level-16)
  - [Level 17](#level-17)
  - [Level 18](#level-18)
  - [Level 19](#level-19)
  - [Level 20](#level-20)
  - [Level 21](#level-21)
  - [Level 22](#level-22)
  - [Level 23](#level-23)
  - [Level 24](#level-24)
  - [Level 25](#level-25)
  - [Level 26](#level-26)
  - [Level 27](#level-27)
  - [Level 28](#level-28)
  - [Level 29](#level-29)
  - [Level 30](#level-30)
  - [Level 31](#level-31)
  - [Level 32](#level-32)
  - [Level 33](#level-33)
  - [Level 34](#level-34)

## Level 0


So we need to login as **bandit0** using the password **bandit0** at **bandit.labs.overthewire.org** using SSH. It's also said that the connection should be done to port **2220**.

We can use the **man** command followed by **ssh** to get information on how to use ssh. The **man** command is super useful, but sometimes can present you with more information then you need. A nice alternative is the **tldr** command which you can install through your package manager (have in mind that you won't be able to use it once you login through ssh since you can't install anything in the bandit machine). It also takes the command that you want to see more information as an argument but it shows you some examples frequently used. So by doing `tldr ssh` we get one of the lines saying

> - Connect to a remote server using a specific port:                    
  ssh username@remote_host -p 2222

which we can change with the arguments we have, resulting in `ssh bandit0@bandit.labs.overthewire.org -p 2220`. Now we know how to make a basic ssh connection with a username and a port. After we execute the command a password is asked. We insert **bandit0** and finally we have an open ssh connection, which we can see by the prompt `bandit0@bandit:~$`.

Ok now we can go to the next level.

## Level 1


We will use the connection established in [Level 0](#level-0) to solve this level. They say that the password for the next level is stored in the file called **readme**. To print the content of the file we can use the `cat` command which takes the file you want to see.

```bash
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

So now that we have the password we can go to the next level.

## Level 2


In this level the password is in a file called `-`. The problem here is that the character `-` is used as a special character to represent stdin ([more information on this here](https://unix.stackexchange.com/questions/16357/usage-of-dash-in-place-of-a-filename)), so in this case we should be able to see its content if we specify the filename in a path format like

```bash
bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

The `.` means the current directory, so what we are representing is the current directory, which inside has a file named `-`.

## Level 3


So now the file that we want to see is called `spaces in this filename`. The challenge here is that if we do like before and use the command **cat** followed by the name we get this

```bash
bandit2@bandit:~$ cat spaces in this filename 
cat: spaces: No such file or directory
cat: in: No such file or directory
cat: this: No such file or directory
cat: filename: No such file or directory
```

Wait what???

So the problem here is that as we've seen before commands take arguments so what we are doing is calling the **cat** command with 4 arguments: **spaces**, **in**, **this** and **filename**. This is not what we want at all. What we want is to print the file named `spaces in this filename`. So the way to do it is to give it to the command as a whole string by surrounding it with `"`.

```bash
bandit2@bandit:~$ cat "spaces in this filename" 
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

Onto the next level.

## Level 4


Now the file that contains the password is a hidden file and is in the `inhere` directory. To change directory we use the **cd** command.

```bash
bandit3@bandit:~$ cd inhere
```

Now we know that we are in the `inhere` directory because the bash prompt says it `bandit3@bandit:~/inhere$`.

If we list the files in the current directory, which we can do by executing the command `ls` we get a blank listing.

```bash
bandit3@bandit:~/inhere$ ls
bandit3@bandit:~/inhere$ 
```

Ok it makes sense. The challenge said that the file was hidden. You can search a bit about hidden files in UNIX systems and you will eventually find out that by convention the hidden files start with a `.`. To list hidden files you can do `man ls` and see that there is a flag that you can pass to list **all** entries, not ignoring those starting with `.` (to quit **man** simply hit **q**).

```bash
bandit3@bandit:~/inhere$ ls -a
.  ..  .hidden
```

Ok as we can see there is a file named `.hidden` that should be the one (the other two `.`, `..` are the current directory and the parent directory respectively).

```bash
bandit3@bandit:~/inhere$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

So by using **cat** with the filename we can then get the password for the next level.

## Level 5


So now the password is stored in the only human-readable file in the `inhere` directory. As we've seen before to change directory we can use the **cd** command. Then we can list the files in the current directory by using ls (i use the **-l** flag just to display it as a vertical listing).

```bash
bandit4@bandit:~/inhere$ ls -l
total 40
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file00
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file01
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file02
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file03
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file04
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file05
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file06
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file07
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file08
-rw-r----- 1 bandit5 bandit4 33 Oct 16  2018 -file09
```

Ok so we have 10 files. The listing doesn't tells us much about them. On the other hand one of suggested commands **file** can tell us interesting things about each file, maybe know which one is human-readable we hope. So what we can do is calling **file** on all the files in this directory. There are two ways to do this: the bruteforce way and the smart way. The bruteforce way is to run `file -fileXX` (replacing XX for the file number) for each file in the directory. The smart way is to use the symbol `*` that matches with every file name, this meaning that using `*` or every filename separated by spaces is the same.

```bash
bandit4@bandit:~/inhere$ file *
file: Cannot open `ile00' (No such file or directory).
file: Cannot open `ile01' (No such file or directory).
file: Cannot open `ile02' (No such file or directory).
file: Cannot open `ile03' (No such file or directory).
file: Cannot open `ile04' (No such file or directory).
file: Cannot open `ile05' (No such file or directory).
file: Cannot open `ile06' (No such file or directory).
file: Cannot open `ile07' (No such file or directory).
file: Cannot open `ile08' (No such file or directory).
file: Cannot open `ile09' (No such file or directory).
```

"Wait... You said this was the smart way and it didn't work, that doesn't seem very smart to me." I know, i know just give me a chance. So the problem here is that the files begin by a `-`, and we've encountered this problem before. Let's do as we did before by putting the filenames in a path like format, so `./*`.

```bash
bandit4@bandit:~/inhere$ file ./*
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
```

Ohhh so now it worked, okay. This tells us that the only file that has an `ASCII text` type is `-file07`. This is the one.

So we use **cat** no surprise there and we get

```bash
bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```

Done. Next level.

## Level 6


So now the password is in a file stored in the `inhere` directory and has three properties:

- human-readable
- 1033 bytes in size
- not executable

So lets **cd** onto `inhere` and the list its content.

```bash
bandit5@bandit:~/inhere$ ls -l
total 80
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere00
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere01
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere02
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere03
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere04
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere05
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere06
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere07
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere08
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere09
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere10
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere11
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere12
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere13
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere14
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere15
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere16
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere17
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere18
drwxr-x--- 2 root bandit5 4096 Oct 16  2018 maybehere19
```

Ok so here bruteforce might not be worth it since each of those entries is a directory and has multiple files. We can use one of the suggested commands named **find** which, guess what, finds stuff.

So to learn a bit about find you can use **man** and just so you know you can search words in **man** by hitting **/** and then typing the word you want to lookup. We can lookup `size` and `readable` in there which will give us 2 flags to use: `-size` and `-readable`. `-size` works with the number of units you want followed by the character that represents the unit. So in our case we want 1033 bytes, so the result will be `-size 1033c`. The readable flag needs no argument. The final command is:

```bash
bandit5@bandit:~/inhere$ find -size 1033c -readable
./maybehere07/.file2
```

**find** searches by default in your current directory. The result is only one file so we don't need to care about it being executable or not.

```bash
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

Onto the next level.

## Level 7


In this level the password is stored **somewhere in the server** with a few properties:

- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

**find** should do the job here as well, it's just a matter of finding the flags associated with the functionalities. We already know how to use the `-size` so that's going to be `-size 33c`. After digging a bit in the **man**, we can see that `-user` and `-group` do what we want.

```bash
bandit6@bandit:~$ find -user bandit7 -group bandit6 -size 33c
bandit6@bandit:~$
```

Wait... No file matched what we wanted. The trick here is that it says **somewhere in the server** so to search everywhere and not just the current directory we have to give the `/` directory (which is the root) as an argument to **find**.

```bash
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c
find: ‘/run/lvm’: Permission denied
(...more...)
find: ‘/var/cache/apt/archives/partial’: Permission denied
/var/lib/dpkg/info/bandit7.password
find: ‘/var/lib/apt/lists/partial’: Permission denied
(...more...)
find: ‘/boot/lost+found’: Permission denied
```

Well as you can see there are a lot of errors but the file is there. If you want to clean it up you can redirect the error output to `/dev/null` so the errors don't show up.

```bash
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c 2> /dev/null
/var/lib/dpkg/info/bandit7.password
```

Ok so we found the file. We just need to use **cat** and we should get the password.

```bash
bandit6@bandit:~$ cat $(find / -user bandit7 -group bandit6 -size 33c 2> /dev/null)
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

Quick note, what i did in the previous command was telling bash that **cat** took the result of another command (**find**) as an argument, we do this by surrounding it with `$()`. This tells bash that what's inside is not only text, it's actually a command. So then the resulting output of the **find** command `/var/lib/dpkg/info/bandit7.password` will be an argument to **cat**.

## Level 8


New challenge. The password is stored in the file `data.txt` next to the word `millionth`. Ok so let's see the content of the file.

```bash
bandit7@bandit:~$ cat data.txt
humiliation's   47r0YuNylaQ3k6HqGF5NsPPiGuolDCjn
malarkey's      0huyJeRwvtJaoyRmJjQFsRnQcYG4gDir
(...A LOT MORE...)
chemical        7D5J0CAJMWr2Ryb9uB0kSRuqz7BQPv6X
shaded  v5MBdtwMnmZ9YlheYVOxBJiOSxp9BeAA
```

We won't be able to find this just by seeing the file's content, we will need some sort of finder, but for a file's content. So once again we will see the suggested commands, and one that fits our needs is **grep**. Now a way we can do this is by using the file's content as the content to look in. On the **man grep** page it says that you can pass the file as an argument, the other way is that if you don't specify a file **grep** will use the standard input. So the first way of doing this is:

```bash
bandit7@bandit:~$ grep millionth data.txt 
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

Easy. Another way that teaches you a few other concepts is doing it like this:

```bash
bandit7@bandit:~$ cat data.txt | grep millionth
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

What we are doing here is called pipelining commands. What it does is using the output of the first command as the input of the second one, so **grep** will use the standard input (which will be the output produced by **cat**) to search the term `millionth`.

Onto the next level.

## Level 9


Now the password is still stored in `data.txt` but now they say is the only line that is unique.
We will **cat** the file just to see its content

```bash
bandit8@bandit:~$ cat data.txt 
KerqNiDbY0zV2VxnOCmWX5XWxumldlAe
MsxcvOe3PGrt78wpZG2bBNF5wfXpZhET
(...more...)
YzZX7E35vOa6IQ9SRUGdlEpyaiyjvWXE
DXI6y5CNPU06rVpkoZgnZJBWfkdW131j
```

So once again we won't be able to get the unique line without using a few tools.
There is a suggested command named `uniq`, sounds like what we need by checking the **man** page.
So the way to use the command is by passing the flag `-u` that tells `uniq` to only print unique lines.

```bash
bandit8@bandit:~$ uniq -u data.txt                    
KerqNiDbY0zV2VxnOCmWX5XWxumldlAe
MsxcvOe3PGrt78wpZG2bBNF5wfXpZhET
(...more...)
YzZX7E35vOa6IQ9SRUGdlEpyaiyjvWXE
DXI6y5CNPU06rVpkoZgnZJBWfkdW131j
```

Wait... It gave us the same. Let's check the **man** page again.

```bash
NAME
       uniq - report or omit repeated lines

SYNOPSIS
       uniq [OPTION]... [INPUT [OUTPUT]]

DESCRIPTION
       Filter adjacent matching lines from INPUT (or standard input), writing to OUTPUT (or standard output).
```

Ok then. So it only filters **adjacent matching lines**. So what we could do is sort the lines so that all the repeated lines be adjacent to one another. Guess what, one of the suggested commands is **sort**, that should do it. We look a bit into the **man** page to see how it works and is nothing special, **sort** followed by the file name. Now **sort** writes to the standard output so what we can do is pipelining, check [Level 8](#level-8) for more information on this.

```bash
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

Ok there we go. We have the password, let's go to the next level.

## Level 10


Now the password is stored in the file `data.txt` and is one of the few human-readable strings, beginning with several `=` characters. Now we already know what a few of the suggested commands do, so we know they're not quite what we want. Let's check out **strings**.

```bash
NAME
       strings - print the strings of printable characters in files.
```

Ok. We can try combining **strings** with **grep** in order to get only the strings that have a `=`.

```bash
bandit9@bandit:~$ strings data.txt | grep =
2========== the
========== password
>t=     yP
rV~dHm=
========== isa
=FQ?P\U
=       F[
pb=x
J;m=
=)$=
========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
iv8!=
```

Ok we can assume the password is the penultimate line, minus the `=`s of course.

## Level 11


Now the password is still stored in `data.txt` but encoded with base64. There is a suggested command named `base64` that might be useful.

```bash
NAME
       base64 - base64 encode/decode data and print to standard output
```

Ok, it can decode base64 so that should do it. To decode we use the `-d` flag.

```bash
bandit10@bandit:~$ base64 -d data.txt 
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

*DJ Khaled Voice:* Another one

## Level 12


The password is stored in the file `data.txt`, but all lowercase and uppercase letters have been rotated 13 positions. This is called ROT13 (you can google it to get some more information on this). It's a ceasar's cipher with the **n** equal to 13 (you can google this as well). So by checking out the suggested commands there are a few that we already know that are not suitable for this. One of the new ones is **tr**. Let's check the **man** page.

```bash
NAME
       tr - translate or delete characters
```

Ok. So it translates characters. I guess that's what we kind of want. We want to translate 'a' to 13 positions ahead. So a quick google of `tr ROT13` would land us on the [Wikipedia page](https://en.wikipedia.org/wiki/ROT13). In the page there is an implementation of ROT13 using **tr**. We can kind of reverse engineer it and get what we want. This is the way to encode `tr 'A-Za-z' 'N-ZA-Mn-za-m'`, so to decode it should be the other way around right? `tr 'N-ZA-Mn-za-m' 'A-Za-z'`

Well let's try it. **tr** uses the standard input, so we will pipeline it using **cat**.

```bash
bandit11@bandit:~$ cat data.txt | tr 'N-ZA-Mn-za-m' 'A-Za-z'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```

Perfect. Next level.

## Level 13


Let's see the challenge description,

>The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv (read the manpages!)

Ok understood. Let's follow the useful tips.

```bash
bandit12@bandit:~$ mkdir /tmp/dirforfiles
```

Now we have a directory to work with our files. Let's copy our file in there first

```bash
bandit12@bandit:~$ cp data.txt /tmp/dirforfiles
```

Done. Let's change our current directory to the one we created.

```bash
bandit12@bandit:~$ cd /tmp/dirforfiles
bandit12@bandit:/tmp/dirforfiles$ 
```

So they said that the file was a hexdump let's check **xxd**'s **man** page.

```bash
NAME
       xxd - make a hexdump or do the reverse.
```

Ok what we want is to reverse it back to it's original state. We use the `-r` flag to do this.

```bash
bandit12@bandit:/tmp/dirforfiles$ xxd -r data.txt 
�▒▒h��6��@4▒bi���h▒91AY&SY���������ϟ���������������׽��9��
    �mF�h�h44
▒��B��,0��   ��4@�����@2▒C@h�� �
�ɋ�^-K�����}�\,�▒ǿ�}E�F�_!r�U�g?E�i��9x��TB@�lȲ���BF.hM�SC4�V�F��R�Br"�<(Hت$    $���KBs��%l▒~�_�▒ݿ����g�zM�w�#P"2@������

��\��WQO4�p�i�����S�#&��/�#��[j▒�<D�uԐ^_�H.�-��wAt
                                                  �[��UP�G�CP��&:�2�*�)�\�������H�
�\�7��w<bandit12@bandit:/tmp/dirforfiles$
```

Ok. I think i broke it... So what happened was that **xxd** reversed it back to a binary but wrote the result to the standard output. Let's redirect it to a file.

```bash
bandit12@bandit:/tmp/dirforfiles$ xxd -r data.txt > original
bandit12@bandit:/tmp/dirforfiles$ 
```

Ok. It worked. Let's check what we are dealing with by using the **file** command to check some more information on the file we just created.

```bash
bandit12@bandit:/tmp/dirforfiles$ file original 
original: gzip compressed data, was "data2.bin", last modified: Tue Oct 16 12:00:23 2018, max compression, from Unix
```

So it's a gzip file, let's learn how to decompress it by checking **man gzip**. So there is a flag `-d` that is used to decompress, let's do it.

```bash
bandit12@bandit:/tmp/dirforfiles$ gzip -d original
gzip: original: unknown suffix -- ignored
```

Hmmm... Weird. The suffix is what goes at the end of the filename i guess... OH RIGHT the file extension. This file has no extension and **gzip** doesn't like it. Let's give it a proper name.

```bash
bandit12@bandit:/tmp/dirforfiles$ mv original original.gz
```

Ok now let's try it again.

```bash
bandit12@bandit:/tmp/dirforfiles$ gzip -d original.gz 
bandit12@bandit:/tmp/dirforfiles$ 
```

Ok no error. It worked i assume. Now we can list the dir to see what we have.

```bash
bandit12@bandit:/tmp/dirforfiles$ ls -la
total 1896
drwxr-sr-x     2 bandit12 root    4096 Jun 29 16:12 .
drwxrws-wt 54536 root     root 1925120 Jun 29 16:14 ..
-rw-r-----     1 bandit12 root    2581 Jun 29 16:04 data.txt
-rw-r--r--     1 bandit12 root     572 Jun 29 16:09 original
```

Ok so the file named `original` is the result of the decompression. Let's analyze it again with the **file** command.

```bash
bandit12@bandit:/tmp/dirforfiles$ file original 
original: bzip2 compressed data, block size = 900k
```

So now it's compressed with **bzip2**. TO THE **MAN** PAGE!

Once again the `-d` flag does it.

```bash
bandit12@bandit:/tmp/dirforfiles$ bzip2 -d original
bzip2: Can't guess original name for original -- using original.out
```

Hm... I guess it worked. **bzip2** isn't as picky as **gzip** with the whole file extension thing. It just warned us that it couldn't guess the original name so it just used that one. That's ok for us. Let's use **file** again.

```bash
bandit12@bandit:/tmp/dirforfiles$ file original.out
original.out: gzip compressed data, was "data4.bin", last modified: Tue Oct 16 12:00:23 2018, max compression, from Unix
```

Ohhh back to gzip. I know this one. We have to change the file extension before decompressing it.

```bash
bandit12@bandit:/tmp/dirforfiles$ mv original.out original.gz
```

Now decompress it.

```bash
bandit12@bandit:/tmp/dirforfiles$ gzip -d original.gz 
bandit12@bandit:/tmp/dirforfiles$ ls -la
total 1912
drwxr-sr-x     2 bandit12 root    4096 Jun 29 16:21 .
drwxrws-wt 54538 root     root 1925120 Jun 29 16:21 ..
-rw-r-----     1 bandit12 root    2581 Jun 29 16:04 data.txt
-rw-r--r--     1 bandit12 root   20480 Jun 29 16:09 original
```

I'd say it worked. Let's **file** it again.

```bash
bandit12@bandit:/tmp/dirforfiles$ file original 
original: POSIX tar archive (GNU)
```

Ohhhh that's a new one. Let's check the **man tar** page. To be honest i never know how to use **tar** and **tar** is really powerful (a smart way to say that it has way too many flags and information to read the man page), so let's ask google. I came across [this](https://www.cyberciti.biz/faq/tar-extract-linux/), it's way easier than the **man** page (be smart).

Let's decompress it then.

```bash
bandit12@bandit:/tmp/dirforfiles$ tar -xvf original
data5.bin
```

That must mean it worked.

```bash
bandit12@bandit:/tmp/dirforfiles$ ls -la
total 1924
drwxr-sr-x     2 bandit12 root    4096 Jun 29 16:26 .
drwxrws-wt 54542 root     root 1925120 Jun 29 16:26 ..
-rw-r--r--     1 bandit12 root   10240 Oct 16  2018 data5.bin
-rw-r-----     1 bandit12 root    2581 Jun 29 16:04 data.txt
-rw-r--r--     1 bandit12 root   20480 Jun 29 16:09 original
```

Ok now we have a data5.bin file. Let's **file** it. This is starting to get BORING, but we must persist.

```bash
bandit12@bandit:/tmp/dirforfiles$ file data5.bin 
data5.bin: POSIX tar archive (GNU)
```

We got **tar** again. Decompress it.

```bash
bandit12@bandit:/tmp/dirforfiles$ tar -xvf data5.bin
data6.bin
```

By now you should know the steps...

```bash
bandit12@bandit:/tmp/dirforfiles$ file data6.bin 
data6.bin: bzip2 compressed data, block size = 900k
```

Good old **bzip2**. Don't stop now, it will be over soon...

```bash
bandit12@bandit:/tmp/dirforfiles$ bzip2 -d data6.bin
bzip2: Can't guess original name for data6.bin -- using data6.bin.out
```

The names are starting to get kind of awful, if you want you can change it.

```bash
bandit12@bandit:/tmp/dirforfiles$ file data6.bin.out 
data6.bin.out: POSIX tar archive (GNU)
```

We got **tar** again.

```bash
bandit12@bandit:/tmp/dirforfiles$ tar -xvf data6.bin.out
data8.bin
```

**file** it.

```bash
bandit12@bandit:/tmp/dirforfiles$ file data8.bin 
data8.bin: gzip compressed data, was "data9.bin", last modified: Tue Oct 16 12:00:23 2018, max compression, from Unix
```

OH MY GOD!! JUST MAKE IT STOP!!! Oh and don't forget **gzip** is the tricky one with the file extension (you're welcome).

```bash
bandit12@bandit:/tmp/dirforfiles$ mv data8.bin data8.gz
bandit12@bandit:/tmp/dirforfiles$ gzip -d data8.gz 
bandit12@bandit:/tmp/dirforfiles$ 
```

It worked. Let's see what we have in the folder.

```bash
bandit12@bandit:/tmp/dirforfiles$ ls -la
total 1940
drwxr-sr-x     2 bandit12 root    4096 Jun 29 16:33 .
drwxrws-wt 54547 root     root 1925120 Jun 29 16:34 ..
-rw-r--r--     1 bandit12 root   10240 Oct 16  2018 data5.bin
-rw-r--r--     1 bandit12 root   10240 Oct 16  2018 data6.bin.out
-rw-r--r--     1 bandit12 root      49 Oct 16  2018 data8
-rw-r-----     1 bandit12 root    2581 Jun 29 16:04 data.txt
-rw-r--r--     1 bandit12 root   20480 Jun 29 16:09 original
```

If you're not sure what is what by now i can't blame you, but we know that the ones with `.bin` and `.bin.out` are intermediate files. The one we want is `data8`.

```bash
bandit12@bandit:/tmp/dirforfiles$ file data8
data8: ASCII text
```

Finally! This is probably the original file.

```bash
bandit12@bandit:/tmp/dirforfiles$ cat data8
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

It's over. I need a break...

## Level 14


So new level, new challenge. The password is stored in a file but can only be read by the **bandit14** (we are **bandit13**). They give us a SSH key to login to next level though. If whe check the **man** page we learn that we can use the `-i` flag to use a private key to login. Let's try it.

```bash
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
(...connection established text...)
bandit14@bandit:~$ 
```

Ok we got a prompt as **bandit14**. Have in mind that you're 2 levels deep in ssh connections. Now we can **cat** the password file mentioned previously.

```bash
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```

Onto the next one.

## Level 15


We can get the password for the next user if we submit the current one to port **30000**. We can use **nc** (netcat) to make simple TCP and UDP connections let's try it. **nc** takes a **host** and a **port** to connect to. Let's try it then.

```bash
bandit14@bandit:~$ nc localhost 30000
```

Ok now we can write the password.

```bash
bandit14@bandit:~$ nc localhost 30000
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

Next please.

## Level 16


This challenge has a few important notes so i'll just paste it here

>The password for the next level can be retrieved by submitting the password of the current level to port **30001** on localhost using **SSL encryption**.

>Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…

So we have a suggested command named openssl and our port is using ssl encryption. Let's check the **man** page.

In the **man** page there is a field named **s_client** which says that implements a generic SSL/TLS client. That should do it. Let's check the **man s_client** page. Ok we can use the `-connect` flag to insert the address and the port. Let's do it.

```bash
bandit15@bandit:~$ openssl s_client -connect localhost:30001
(...bunch of information...)

```

Now we can type our current password to get the new one.

```bash
bandit15@bandit:~$ openssl s_client -connect localhost:30001
(...bunch of information...)
BfMYroe26WYalil77FoDi9qh59eK5xNr
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```

Ok we got it. Next one.

## Level 17


Now they give us a range of ports to which we have to submit the current password. Let's not bruteforce it. We can use **nmap** to give us some information on the ports. Check the **man** page. We can use the `-p` flag to scan port ranges.

```bash
bandit16@bandit:~$ nmap localhost -p31000-32000

Starting Nmap 7.40 ( https://nmap.org ) at 2019-06-29 17:49 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00021s latency).
Not shown: 999 closed ports
PORT      STATE SERVICE
31518/tcp open  unknown
31790/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

So we have 2 ports open. Now we can do a service scan in both ports and see the results. To do a service scan we use the `-sV` flag.

```bash
bandit16@bandit:~$ nmap localhost -p T:31518,31790 -sV

Starting Nmap 7.40 ( https://nmap.org ) at 2019-06-29 17:52 CEST
Stats: 0:01:18 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 17:54 (0:01:18 remaining)
Stats: 0:01:23 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 17:54 (0:01:23 remaining)
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00013s latency).
PORT      STATE SERVICE     VERSION
31518/tcp open  ssl/echo
31790/tcp open  ssl/unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31790-TCP:V=7.40%T=SSL%I=7%D=6/29%Time=5D17893D%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20cu
SF:rrent\x20password\n")%r(GetRequest,31,"Wrong!\x20Please\x20enter\x20the
SF:\x20correct\x20current\x20password\n")%r(HTTPOptions,31,"Wrong!\x20Plea
SF:se\x20enter\x20the\x20correct\x20current\x20password\n")%r(RTSPRequest,
SF:31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\
SF:n")%r(Help,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x
SF:20password\n")%r(SSLSessionReq,31,"Wrong!\x20Please\x20enter\x20the\x20
SF:correct\x20current\x20password\n")%r(TLSSessionReq,31,"Wrong!\x20Please
SF:\x20enter\x20the\x20correct\x20current\x20password\n")%r(Kerberos,31,"W
SF:rong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\n")%r
SF:(FourOhFourRequest,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20c
SF:urrent\x20password\n")%r(LPDString,31,"Wrong!\x20Please\x20enter\x20the
SF:\x20correct\x20current\x20password\n")%r(LDAPSearchReq,31,"Wrong!\x20Pl
SF:ease\x20enter\x20the\x20correct\x20current\x20password\n")%r(SIPOptions
SF:,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20password
SF:\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.36 seconds
```

(This scan might take a bit)

Ok so both of them speak SSL, but one of them is an `echo` service as we can see. This was an overkill since we could've just tried both, but now you know how to do it properly (imagine if you had 300 ports). The port we want is **31790**, lets submit the password using **openssl s_client**.

```bash
bandit16@bandit:~$ openssl s_client -connect localhost:31790
(...bunch of ssl information...)
cluFn7wTiGryunymYOu4RcffSxQluehd
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```

Now we have an ssh key we can copy it to our own computer to a file and use it to connect like we did in [Level 14](#level-14).

```bash
myuser@myuser:~$ echo "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----" > level17_priv

myuser@myuser:~$ ssh bandit17@bandit.labs.overthewire.org -p 2220 -i level17_priv
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for 'level17_priv' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "level17_priv": bad permissions
bandit17@bandit.labs.overthewire.org's password:
```

Hmmm... It makes sense we shouldn't just have a private key laying around unprotected let's change its permissions (you can google how permissions in linux work).

```bash
myuser@myuser:~$ sudo chmod 600 level17_priv
myuser@myuser:~$ ssh bandit17@bandit.labs.overthewire.org -p 2220 -i level17_priv
(...connection established info...)
bandit17@bandit:~$ 
```

Success! Just in case we should go get this level's password so we don't need the private key to login. The passwords are located in `/etc/bandit_pass/`.

```bash
bandit17@bandit:~$ cat /etc/bandit_pass/bandit17
xLYVMN9WE5zQ5vHacb0sZEVqbrp7nBTn
```

Now we can go to the next one.

## Level 18


So now the password for the next level is the only line different between **passwords.old** and **passwords.new**. Let's check the **diff** command.

```bash
NAME
       diff - compare files line by line
```

This should do it.

```bash
bandit17@bandit:~$ diff passwords.old passwords.new 
42c42
< hlbSBPAWJmL6WFDb06gpTx1pPButblOA
---
> kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
```

So our password should be the one on the bottom since that's the new one. Next one.

## Level 19


Now the problem is that once we login we are automatically kicked out

```bash
myuser@myuser:~$ ssh bandit18@bandit.labs.overthewire.org -p 2220
(...connection established info...)
Byebye !
Connection to bandit.labs.overthewire.org closed.
myuser@myuser:~$ 
```

Hm... Ok, so what about if we try to run a command through ssh. Instead of opening a connection and get a prompt, just run a command. Well let's check the **man ssh** command

```bash
SYNOPSIS
     ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address] [-c cipher_spec] [-D [bind_address:]port] [-E log_file] [-e escape_char]
         [-F configfile] [-I pkcs11] [-i identity_file] [-J destination] [-L address] [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option]
         [-p port] [-Q query_option] [-R address] [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]] destination [command]
```

Well as we can see the last argument of the command is a command so let's try it

```bash
myuser@myuser:~$ ssh bandit18@bandit.labs.overthewire.org -p 2220 'cat readme'
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password: 
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
myuser@myuser:~$ 
```

So we got kicked out but we were still able to run the command which gave us the password. NICE! Next one.

## Level 20


Let's check the challenge description:

>To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), asetuidfter you have used the setuid binary.

Let's execute it without arguments then.

```bash
bandit19@bandit:~$ ./bandit20-do 
Run a command as another user.
  Example: ./bandit20-do id
```

We can see which user we are currently running the command by running **whoami**

```bash
bandit19@bandit:~$ whoami
bandit19
bandit19@bandit:~$ ./bandit20-do whoami
bandit20
```

So this runs a command as **bandit20**. It should immediately pop to your mind the idea of just using **cat** to print the password as the next user.

```bash
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```

So we ran **cat** as **bandit20** and gave it the file we wanted to print as an argument. This should be easy by now.

## Level 21


This challenge is really well detailed in the description so i'll just paste it here

>There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

So we need to run a server on a port that sends the password everytime someone connects to it. So we will need 2 terminals running because the server will hold on to one of them. We can use **screen**. We just need to execute **screen** which will get us into another empty terminal. To detach the current screen just hit **Ctrl+a d**. Then to resume just execute **screen -r** (RTFM on this one). We will also put a job into background by hitting **Ctrl+z** and then running **fg** to bring it to the foreground.

```bash
bandit20@bandit:~$ screen
(...enters a new screen session...)
bandit20@bandit:~$ nc -l -p 30005
(...listening...)
```

Now we detach the screen session and run `./suconnection 30005`.

```bash
bandit20@bandit:~$ ./suconnect 30005
(...waiting...)
```

Let's go back to our netcat server and send the old password. Hit **Ctrl+z** to send `suconnect` to the background and then run **screen -r** to resume the screen session.

```bash
bandit20@bandit:~$ nc -l -p 30005
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
(...waiting...)
```

Ok now finally let's resume our `suconnect` by exiting screen and running **fg**.

```bash
bandit20@bandit:~$ fg
./suconnect 30005
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
bandit20@bandit:~$ 
```

It worked!! Now we just need to go back to the netcat server to get the password received.

```bash
bandit20@bandit:~$ screen -r
(...switched to screen session...)
bandit20@bandit:~$ nc -l -p 30005
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
bandit20@bandit:~$ 
```

There we go. DONE! This was interesting! Next one.

## Level 22


A program is running periodically using **cron**. Let's look into `/etc/cron.d/`.

```bash
bandit21@bandit:~$ ls -la /etc/cron.d
total 24
drwxr-xr-x  2 root root 4096 Oct 16  2018 .
drwxr-xr-x 88 root root 4096 Oct 16  2018 ..
-rw-r--r--  1 root root  120 Oct 16  2018 cronjob_bandit22
-rw-r--r--  1 root root  122 Oct 16  2018 cronjob_bandit23
-rw-r--r--  1 root root  120 Oct 16  2018 cronjob_bandit24
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder
```

The one that interests us for now is `cronjob_bandit22`. **cat** it.

```bash
bandit21@bandit:~$ cd /etc/cron.d
bandit21@bandit:/etc/cron.d$ cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```

So we may not understand this fully, but let's check that file's content.

```bash
bandit21@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit22.sh 
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

Ok this we can understand. So it's printing out the password for the next level to that file. Let's see if we can **cat** that file.

```bash
bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

We got it! Next level.

## Level 23


This one is pretty much like the previous one but it's a different **cron** job running.

```bash
bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
```

So the cronjob is being ran as if it was by user **bandit23**. Let's analyze the file mentioned in here.

```bash
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh 
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

So it prints the password to a directory whose name is generated by the command after `mytarget`. If we execute the command it should give us the name. We just have to replace `$myname` with **bandit22**, since that would be the output of running **whoami** as we've mentioned previously.

```bash
bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
```

Now if we **cat** this file we should get the password.

```bash
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

Done. Onto the next one.

## Level 24


Let's see this challenge description since they have a few importante notes:

>A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

>NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!

>NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

So let's first go to `/etc/crond.d/` and check this level's file.

```bash
bandit23@bandit:/etc/cron.d$ cat cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
```

**cat** the file mentioned in here

```bash
bandit23@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        timeout -s 9 60 ./$i
        rm -f ./$i
    fi
done
```

Once again this **cron** job is being ran as another user in this case **bandit24**. So `myname` will contain `bandit24`, leading us to the `/var/spool/bandit24` directory. The message printed by **echo** tells us that it will execute and delete all scripts in here, so our idea would be to create a script that will **cat** the password file into another file that we create. This very simple to write in a **bash** script, let's do it

```bash
#!/bin/bash

mkdir /tmp/dirforcron
cat /etc/bandit_pass/bandit24 > /tmp/dirforcron/pass
chmod 777 /tmp/dirforcron/pass
```

We will create this file in `/tmp/dirfortest/` and name it `script.sh`.
So what this do is creating a new directory to work in, cat the password file into a file in that directory and then changing the permissions to make it accessible to everyone. Now when we put this file in `/var/spool/bandit24` we have to be sure that the user who will run it has enough permissions to do so. We can do this by doing

```bash
bandit23@bandit:/var/spool/bandit24$ chmod 777 /tmp/dirfortest/script.sh
```

Now that we gave it all the permissions possible we just need to copy it to `/var/spool/bandit24` and wait for it to be ran.

```bash
bandit23@bandit:/var/spool/bandit24$ cat /tmp/dirforcron/pass
cat: /tmp/dirforcron/pass: No such file or directory
bandit23@bandit:/var/spool/bandit24$ cat /tmp/dirforcron/pass
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

Success!!! Let's go onto the next one.

## Level 25



>A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

First let's try to connect and see what it prints. We will use netcat to connect as before.

```
bandit24@bandit:~$ nc localhost 30002
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
(...jibberish...)
Wrong! Please enter the correct current password. Try again.
^C
```

So it expects the password and the pin code in a line separated by a space. You can use your preferred scripting language to try and bruteforce this. I'll use bash since it doesn't depend on anything being preinstalled in the system (besides bash of course).

```bash
#!/bin/bash
rm input1.txt
rm input2.txt
rm output.txt

touch output.txt
touch input.txt
for i in {0000..5000}
do
        echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i" >> input1.txt
done

for i in {5001..9999}
do
        echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i" >> input2.txt
done

echo "input created will start nc connection"

cat input1.txt | nc localhost 30002 >> output.txt
cat input2.txt | nc localhost 30002 >> output.txt

cat output.txt | grep -v Wrong
```

So what this does is it creates 2 input files with all the combinations. I do this because when i tried to do it all in once the connection tended to timeout. After creating the input i pipe it to a **nc** connection and write the result to a file. Finally, i pipe the content of the file to **grep** (the `-v` flag is to do invert macthing, so the lines that don't contain "Wrong") and the correct answer should be there.

```
bandit24@bandit:/tmp/testbash$ bash script.sh 
rm: cannot remove 'input1.txt': No such file or directory
rm: cannot remove 'input2.txt': No such file or directory
input created will start nc connection
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Timeout. Exiting.
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

Exiting.
```

Next one.

## Level 26


So the challenge now says,

> Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

Let's inspect our current directory

```bash
bandit25@bandit:~$ ls -la
total 32
drwxr-xr-x  2 root     root     4096 May 26 18:23 .
drwxr-xr-x 41 root     root     4096 Oct 16  2018 ..
-rw-r-----  1 bandit25 bandit25   33 May 26 18:23 .bandit24.password
-r--------  1 bandit25 bandit25 1679 Oct 16  2018 bandit26.sshkey
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r-----  1 bandit25 bandit25    4 May 26 18:23 .pin
-rw-r--r--  1 root     root      675 May 15  2017 .profile
```

So we have a ssh key which i assume will be enough to log us in. Let's try it. I downloaded the key to my personal machine, **set the right permissions** and then tried to login.

```bash
myuser@myuser:~$ ssh bandit26@bandit.labs.overthewire.org -p 2220 -i ~/Desktop/bandit26.sshkey
(...connection established...)
Connection to bandit.labs.overthewire.org closed.
myuser@myuser:~$
```

Hmmm... So it closed the connection immediately. Let's try to run a command through **ssh** instead of establishing the connection (like in [level 19](#level-19)), more specifically, try to understand what shell user **bandit26** is running. We can do this by checking the content of the `$SHELL` variable.

```bash
myuser@myuser:~$ ssh bandit26@bandit.labs.overthewire.org -p 2220 -i ~/Desktop/bandit26.sshkey 'echo $SHELL'
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames
(...hangs...)
^C
myuser@myuser:~$
```

Well that didn't work. The connection just hanged. Let's go back to **bandit25** and check the content of the `/etc/passwd` file, since this stores information of the system users.

```bash
bandit25@bandit:~$ cat /etc/passwd
(...other users...)
bandit25:x:11025:11025:bandit level 25:/home/bandit25:/bin/bash
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit27:x:11027:11027:bandit level 27:/home/bandit27:/bin/bash
(...other users...)
```

OK we got something. So **bandit26** is running `/usr/bin/showtext` as its default shell. Let's investigate that file.

```bash
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
```

So what this does is pretty much use `more` on file. `more` works like `less` which in sum are commands that help you viewing a file's content that doesn't fit on screen. So let's do that, make the terminal as tiny as we can.

```bash
--More--(16%)
```

Ok so we got `more` running. Now i have no idea what to do. Let's check the **man more** page.
So from there we can see that there is an option that opens `vim` at the current line (vim is a terminal text editor).

```bash
| |                   | (_) | |__ \ / /
 | |__   __ _ _ __   __| |_| |_   ) / /_
 | '_ \ / _` | '_ \ / _` | | __| / / '_ \
 | |_) | (_| | | | | (_| | | |_ / /| (_) |
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/
~                                                                                      
~                                                                                      
```

Now we have it opened in `vim` as user **bandit26**. From vim we can get a shell via the `:shell` command. To do that just hit **Esc** and then type `:shell`

```bash
  _                     _ _ _   ___   __
 | |                   | (_) | |__ \ / /
:shell
```

Now hit enter.

```bash
  _                     _ _ _   ___   __  
 | |                   | (_) | |__ \ / /  
--More--(33%)
```

Wait... What? So that got us back to `more`... Oh right the shell was set to run `more` so we just need to change the `:shell` command in `vim`. We can do this by typing in command mode `:set shell=/bin/bash`.

```bash
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/
~                                                                                      
:set shell=/bin/bash
```

And now run the `:shell` command.

```bash
bandit26@bandit:~$ 
```

WE GOT A SHELL!!! Next challenge then.

## Level 27


We will be using the shell established from the previous level. Let's check the current directory.

```bash
bandit26@bandit:~$ ls -la
total 36
drwxr-xr-x  3 root     root     4096 Oct 16  2018 .
drwxr-xr-x 41 root     root     4096 Oct 16  2018 ..
-rwsr-x---  1 bandit27 bandit26 7296 Oct 16  2018 bandit27-do
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r--r--  1 root     root      675 May 15  2017 .profile
drwxr-xr-x  2 root     root     4096 Oct 16  2018 .ssh
-rw-r-----  1 bandit26 bandit26  258 Oct 16  2018 text.txt
```

This brings us back to [level 20](#level-20) where we had a setuid binary. This is easy then, let's just **cat** the password file.

```bash
bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea
```

Good job! Next.


## Level 28


In this challenge we will have to work with **git** if you know nothing about it you should google it and read a few cheatsheets.

> There is a git repository at ssh://bandit27-git@localhost/home/bandit27-git/repo. The password for the user bandit27-git is the same as for the user bandit27.

> Clone the repository and find the password for the next level.

So i'll first create a directory to clone the repository to, and then clone it.

```bash
bandit27@bandit:~$ mkdir /tmp/gitfolder
bandit27@bandit:~$ cd /tmp/gitfolder
bandit27@bandit:/tmp/gitfolder$ git clone ssh://bandit27-git@localhost/home/bandit27-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit27/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit27/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit27-git@localhost's password: 
remote: Counting objects: 3, done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (3/3), done.
bandit27@bandit:~$
```

Done. Let's inspect the repo we've just cloned.

```bash
bandit27@bandit:/tmp/gitfolder$ ls -la
total 1952
drwxr-sr-x     3 bandit27 root    4096 Jul  6 13:46 .
drwxrws-wt 57125 root     root 1986560 Jul  6 13:47 ..
drwxr-sr-x     3 bandit27 root    4096 Jul  6 13:47 repo
bandit27@bandit:/tmp/gitfolder$ cd repo/
bandit27@bandit:/tmp/gitfolder/repo$ ls -la
total 16
drwxr-sr-x 3 bandit27 root 4096 Jul  6 13:47 .
drwxr-sr-x 3 bandit27 root 4096 Jul  6 13:46 ..
drwxr-sr-x 8 bandit27 root 4096 Jul  6 13:47 .git
-rw-r--r-- 1 bandit27 root   68 Jul  6 13:47 README
```

Let's check that `README` file.

```bash
bandit27@bandit:/tmp/gitfolder/repo$ cat README 
The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2
```

Done.

## Level 29


Once again in this challenge we will have to work with git,

> There is a git repository at ssh://bandit28-git@localhost/home/bandit28-git/repo. The password for the user bandit28-git is the same as for the user bandit28.

> Clone the repository and find the password for the next level.

So let's clone it again and see the repo content.

```bash
bandit28@bandit:~$ mkdir /tmp/gitfolder2
bandit28@bandit:~$ cd /tmp/gitfolder2
bandit28@bandit:/tmp/gitfolder2$ git clone ssh://bandit28-git@localhost/home/bandit28-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit28/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit28/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit28-git@localhost's password: 
remote: Counting objects: 9, done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 2), reused 0 (delta 0)
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (2/2), done.
```

Inspect the repo.

```bash
bandit28@bandit:/tmp/gitfolder2$ cd repo/
bandit28@bandit:/tmp/gitfolder2/repo$ ls -la
total 16
drwxr-sr-x 3 bandit28 root 4096 Jul  6 13:51 .
drwxr-sr-x 3 bandit28 root 4096 Jul  6 13:51 ..
drwxr-sr-x 8 bandit28 root 4096 Jul  6 13:51 .git
-rw-r--r-- 1 bandit28 root  111 Jul  6 13:51 README.md
bandit28@bandit:/tmp/gitfolder2/repo$ cat README.md 
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
```

I saw a `README.md` file so i used **cat** to see it's content and there was nothing there. Let's inspect the commits made by doing `git log`.

```bash
bandit28@bandit:/tmp/gitfolder2/repo$ git log
commit 073c27c130e6ee407e12faad1dd3848a110c4f95
Author: Morla Porla <morla@overthewire.org>
Date:   Tue Oct 16 14:00:39 2018 +0200

    fix info leak

commit 186a1038cc54d1358d42d468cdc8e3cc28a93fcb
Author: Morla Porla <morla@overthewire.org>
Date:   Tue Oct 16 14:00:39 2018 +0200

    add missing data

commit b67405defc6ef44210c53345fc953e6a21338cc7
Author: Ben Dover <noone@overthewire.org>
Date:   Tue Oct 16 14:00:39 2018 +0200

    initial commit of README.md
```

Hmm... So the password used to be there but unfortunately someone was smart enough to remove it. We can go back to that commit by doing `git checkout` followed by the commit id. Let's do it then.

```bash
bandit28@bandit:/tmp/gitfolder2/repo$ git checkout 186a1038cc54d1358d42d468cdc8e3cc28a93fcb
Note: checking out '186a1038cc54d1358d42d468cdc8e3cc28a93fcb'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at 186a103... add missing data
```

Let's see what was the state of the repo in this commit.

```bash
bandit28@bandit:/tmp/gitfolder2/repo$ ls -la
total 16
drwxr-sr-x 3 bandit28 root 4096 Jul  6 13:55 .
drwxr-sr-x 3 bandit28 root 4096 Jul  6 13:51 ..
drwxr-sr-x 8 bandit28 root 4096 Jul  6 13:55 .git
-rw-r--r-- 1 bandit28 root  133 Jul  6 13:55 README.md
```

Still has the `README.md` file. By reading the commit messages we thought that there should be an information leak in this commit. Let's print the file's content.

```bash
bandit28@bandit:/tmp/gitfolder2/repo$ cat README.md 
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: bbc96594b4e001778eee9975372716b2
```

We got the password. Good job! Onto the next one.

## Level 30


Same thing as before. We have a repo we need to clone it to a folder.

```
bandit29@bandit:~$ mkdir /tmp/gitfolder3
bandit29@bandit:~$ cd /tmp/gitfolder3
bandit29@bandit:/tmp/gitfolder3$ git clone ssh://bandit29-git@localhost/home/bandit29-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit29/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit29/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit29-git@localhost's password: 
remote: Counting objects: 16, done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 16 (delta 2), reused 0 (delta 0)
Receiving objects: 100% (16/16), done.
Resolving deltas: 100% (2/2), done.
bandit29@bandit:/tmp/gitfolder3$ ls -la
total 1952
drwxr-sr-x     3 bandit29 root    4096 Jul  6 14:02 .
drwxrws-wt 57133 root     root 1986560 Jul  6 14:02 ..
drwxr-sr-x     3 bandit29 root    4096 Jul  6 14:02 repo
bandit29@bandit:/tmp/gitfolder3$ cd repo/
bandit29@bandit:/tmp/gitfolder3/repo$ ls -al
total 16
drwxr-sr-x 3 bandit29 root 4096 Jul  6 14:02 .
drwxr-sr-x 3 bandit29 root 4096 Jul  6 14:02 ..
drwxr-sr-x 8 bandit29 root 4096 Jul  6 14:02 .git
-rw-r--r-- 1 bandit29 root  131 Jul  6 14:02 README.md
```

Once again let's see `README.md`'s content.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>
```

We've been through this before. Let's check the previous commits.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git log
commit 84abedc104bbc0c65cb9eb74eb1d3057753e70f8
Author: Ben Dover <noone@overthewire.org>
Date:   Tue Oct 16 14:00:41 2018 +0200

    fix username

commit 9b19e7d8c1aadf4edcc5b15ba8107329ad6c5650
Author: Ben Dover <noone@overthewire.org>
Date:   Tue Oct 16 14:00:41 2018 +0200

    initial commit of README.md
```

We can check if that first commit has anything interesting.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git checkout 9b19e7d8c1aadf4edcc5b15ba8107329ad6c5650
Note: checking out '9b19e7d8c1aadf4edcc5b15ba8107329ad6c5650'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at 9b19e7d... initial commit of README.md
```

Now let's check the file's content again.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit29
- password: <no passwords in production!>
```

Hm... Still nothing. Let's go back to our most recent commit by doing `git pull` and the repo link.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git pull ssh://bandit29-git@localhost/home/bandit29-git/repo
Could not create directory '/home/bandit29/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit29/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit29-git@localhost's password: 
From ssh://localhost/home/bandit29-git/repo
 * branch            HEAD       -> FETCH_HEAD
Updating 9b19e7d..84abedc
Fast-forward
 README.md | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)
```

We can see what branches exist by doing `git branch`.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git branch
* (HEAD detached from 9b19e7d)
  master
```

We have 2 branches. Let's switch to the `master` branch since our checkouts may have messed with some changes.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git checkout master
Switched to branch 'master'
Your branch is up-to-date with 'origin/master'.
bandit29@bandit:/tmp/gitfolder3/repo$ git branch
* master
```

Hm... I guess we can see if there are any other branches that don't show up here. 

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git show-branch --all
! [dev] add data needed for development
 * [master] fix username
  ! [origin/HEAD] fix username
   ! [origin/dev] add data needed for development
    ! [origin/master] fix username
     ! [origin/sploits-dev] add some silly exploit, just for shit and giggles
------
     + [origin/sploits-dev] add some silly exploit, just for shit and giggles
+  +   [dev] add data needed for development
+  +   [dev^] add gif2ascii
+*++++ [master] fix username
```

Ok we have some other branches like `dev` and `sploits-dev`. Since i like exploits let's check that one first.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git checkout sploits-dev 
Branch sploits-dev set up to track remote branch sploits-dev from origin.
Switched to a new branch 'sploits-dev'
bandit29@bandit:/tmp/gitfolder3/repo$ ls -la
total 20
drwxr-sr-x 4 bandit29 root 4096 Jul  6 14:27 .
drwxr-sr-x 3 bandit29 root 4096 Jul  6 14:02 ..
drwxr-sr-x 2 bandit29 root 4096 Jul  6 14:27 exploits
drwxr-sr-x 8 bandit29 root 4096 Jul  6 14:27 .git
-rw-r--r-- 1 bandit29 root  131 Jul  6 14:25 README.md
```

That folder seems interesting.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ cd exploits/
bandit29@bandit:/tmp/gitfolder3/repo/exploits$ ls -la
total 12
drwxr-sr-x 2 bandit29 root 4096 Jul  6 14:27 .
drwxr-sr-x 4 bandit29 root 4096 Jul  6 14:27 ..
-rw-r--r-- 1 bandit29 root    1 Jul  6 14:27 horde5.md
```

We HAVE to print that file's content.

```bash
bandit29@bandit:/tmp/gitfolder3/repo/exploits$ cat horde5.md 

```

Oh... It's empty. Let's check the other branch then.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ git checkout dev
Switched to branch 'dev'
Your branch is up-to-date with 'origin/dev'.
bandit29@bandit:/tmp/gitfolder3/repo$ ls -la
total 20
drwxr-sr-x 4 bandit29 root 4096 Jul  6 14:31 .
drwxr-sr-x 3 bandit29 root 4096 Jul  6 14:02 ..
drwxr-sr-x 2 bandit29 root 4096 Jul  6 14:31 code
drwxr-sr-x 8 bandit29 root 4096 Jul  6 14:31 .git
-rw-r--r-- 1 bandit29 root  134 Jul  6 14:31 README.md
```

Let's first check `README.md` to be sure it has nothing new.

```bash
bandit29@bandit:/tmp/gitfolder3/repo$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
```

This should do it. Good job.

## Level 31


This challenge is still related to **git**. So we'll just follow the same steps as before, create the directory and clone the repo in there.

```
bandit30@bandit:~$ mkdir /tmp/gitfolder4
bandit30@bandit:~$ cd /tmp/gitfolder4
bandit30@bandit:/tmp/gitfolder4$ git clone ssh://bandit30-git@localhost/home/bandit30-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit30/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit30/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit30-git@localhost's password: 
remote: Counting objects: 4, done.
remote: Total 4 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (4/4), done.
```

```bash
bandit30@bandit:/tmp/gitfolder4$ ls -la
total 1952
drwxr-sr-x     3 bandit30 root    4096 Jul  6 19:12 .
drwxrws-wt 57253 root     root 1986560 Jul  6 19:14 ..
drwxr-sr-x     3 bandit30 root    4096 Jul  6 19:12 repo
bandit30@bandit:/tmp/gitfolder4$ cd repo
bandit30@bandit:/tmp/gitfolder4/repo$ ls -la
total 16
drwxr-sr-x 3 bandit30 root 4096 Jul  6 19:12 .
drwxr-sr-x 3 bandit30 root 4096 Jul  6 19:12 ..
drwxr-sr-x 8 bandit30 root 4096 Jul  6 19:12 .git
-rw-r--r-- 1 bandit30 root   30 Jul  6 19:12 README.md
bandit30@bandit:/tmp/gitfolder4/repo$ cat README.md 
just an epmty file... muahaha
```

This was me inspecting the files and folders in the repo. There is nothing interesting, so let's check **git**.

```
bandit30@bandit:/tmp/gitfolder4/repo$ git show-branch --all
* [master] initial commit of README.md
 ! [origin/HEAD] initial commit of README.md
  ! [origin/master] initial commit of README.md
---
*++ [master] initial commit of README.md
```

No special hidden branches.

```bash
bandit30@bandit:/tmp/gitfolder4/repo$ git log
commit 3aa4c239f729b07deb99a52f125893e162daac9e
Author: Ben Dover <noone@overthewire.org>
Date:   Tue Oct 16 14:00:44 2018 +0200

    initial commit of README.md
```

Only one commit, nothing interesting... Let's check the tags then.

```bash
bandit30@bandit:/tmp/gitfolder4/repo/.git$ git tag
secret
```

OK this seems interesting! A tag called `secret`. We can see the tag message by doing `git show secret`.

```bash
bandit30@bandit:/tmp/gitfolder4/repo$ git show secret
47e603bb428404d265f59c42920d81e5
```

We got the password. Next one!

## Level 32


Once gain this challenge uses git.

```
bandit31@bandit:~$ ls -la
total 24
drwxr-xr-x  2 root root 4096 Oct 16  2018 .
drwxr-xr-x 41 root root 4096 Oct 16  2018 ..
-rw-r--r--  1 root root  220 May 15  2017 .bash_logout
-rw-r--r--  1 root root 3526 May 15  2017 .bashrc
-rwxr-xr-x  1 root root   59 Oct 16  2018 .gitconfig
-rw-r--r--  1 root root  675 May 15  2017 .profile
bandit31@bandit:~$ mkdir /tmp/gitfolder5
bandit31@bandit:~$ cd /tmp/gitfolder5
bandit31@bandit:/tmp/gitfolder5$ git clone ssh://bandit31-git@localhost/home/bandit31-git/repo
Cloning into 'repo'...
Could not create directory '/home/bandit31/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit31-git@localhost's password: 
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 4 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (4/4), done.
```

Let's inspect the repo.

```
bandit31@bandit:/tmp/gitfolder5$ ls -la
total 1952
drwxr-sr-x     3 bandit31 root    4096 Jul  6 19:37 .
drwxrws-wt 57264 root     root 1986560 Jul  6 19:38 ..
drwxr-sr-x     3 bandit31 root    4096 Jul  6 19:37 repo
bandit31@bandit:/tmp/gitfolder5$ cd repo/
bandit31@bandit:/tmp/gitfolder5/repo$ ls -la
total 20
drwxr-sr-x 3 bandit31 root 4096 Jul  6 19:37 .
drwxr-sr-x 3 bandit31 root 4096 Jul  6 19:37 ..
drwxr-sr-x 8 bandit31 root 4096 Jul  6 19:37 .git
-rw-r--r-- 1 bandit31 root    6 Jul  6 19:37 .gitignore
-rw-r--r-- 1 bandit31 root  147 Jul  6 19:37 README.md
bandit31@bandit:/tmp/gitfolder5/repo$ cat README.md 
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
```

So the `README.md` mentions a `key.txt` file, and that we should push a file to the repo. Let's do it then.

```
bandit31@bandit:/tmp/gitfolder5/repo$ vi key.txt 
bandit31@bandit:/tmp/gitfolder5/repo$ git add .
bandit31@bandit:/tmp/gitfolder5/repo$ git commit -a
On branch master
Your branch is up-to-date with 'origin/master'.
nothing to commit, working tree clean
```

Well we couldn't push since it says we are up to date. Maybe it's the gitignore. Let's see it.

```
bandit31@bandit:/tmp/gitfolder5/repo$ cat .gitignore 
*.txt
```

So as i suspected **git** is ignoring all the files with the `txt` extension, so `key.txt` would be ignored. We can for the file to be added anyways by using the `-f` flag.

```
bandit31@bandit:/tmp/gitfolder5/repo$ git add key.txt -f
bandit31@bandit:/tmp/gitfolder5/repo$ git commit -a
Unable to create directory /home/bandit31/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

[master e67c6e5] Added key.txt file
 1 file changed, 1 insertion(+)
 create mode 100644 key.txt
```

Now we only need to push the file.

```
bandit31@bandit:/tmp/gitfolder5/repo$ git push
Could not create directory '/home/bandit31/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit31-git@localhost's password: 
Counting objects: 3, done.
Delta compression using up to 4 threads.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 326 bytes | 0 bytes/s, done.
Total 3 (delta 0), reused 0 (delta 0)
remote: ### Attempting to validate files... ####
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Well done! Here is the password for the next level:
remote: 56a9bf19c63d650ce78e6ec0354ee45e
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
To ssh://localhost/home/bandit31-git/repo
 ! [remote rejected] master -> master (pre-receive hook declined)
error: failed to push some refs to 'ssh://bandit31-git@localhost/home/bandit31-git/repo'
```

We got the password! Good job.

## Level 33


> After all this git stuff its time for another escape. Good luck!

Enough of **git** then. Now we have to escape.

```
WELCOME TO THE UPPERCASE SHELL
>>
```

So now we are stuck inside of a uppercase shell. Any command that we run is ran in upper case.

```
>> ls
sh: 1: LS: not found
>> "ls"
sh: 1: LS: not found
```

Not even as a string.

Well i had to google this one because this wasn't really that easy. So it happens that the `$0` variable runs a shell, so that should be enough.

```
>> $0
$ 
```

We got a shell. Now it should be easy to just see the file content.

```
$ ls -la
total 28
drwxr-xr-x  2 root     root     4096 Oct 16  2018 .
drwxr-xr-x 41 root     root     4096 Oct 16  2018 ..
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r--r--  1 root     root      675 May 15  2017 .profile
-rwsr-x---  1 bandit33 bandit32 7556 Oct 16  2018 uppershell
$ cat /etc/bandit_pass/bandit33
c9c3199ddf4121b10cf581a98d51caee
```

Done! Next one!

## Level 34


```
bandit33@bandit:~$ ls -la
total 24
drwxr-xr-x  2 root     root     4096 Oct 16  2018 .
drwxr-xr-x 41 root     root     4096 Oct 16  2018 ..
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r--r--  1 root     root      675 May 15  2017 .profile
-rw-------  1 bandit33 bandit33  430 Oct 16  2018 README.txt
bandit33@bandit:~$ cat README.txt 
Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new level, please let us know!
```

We did it! We finished all the levels! At the moment (July 6th, 2019) there are no more challenges. So bye bye and thanks for checking out this walkthrough.
