# CTF Tools
List of tools and resources for CTFs.

## Table of Content
- [General Tools](#beginner-tools)
- [Cryptography](#cryptography)
- [Forensics](#forensics)
- [Programming](#programming)
- [Network Exploitation](#network-exploitation)
- [Reverse Engineering](#reverse-engineering)
- [Virtual Machines](#virtual-machines)
- [Web Exploitation](#web-exploitation)
- [Write-Ups and Tutorials](#write-ups-and-tutorials)

## General Tools
- [Visual Studio Code](https://code.visualstudio.com/) - IDE, Programming, text/binary, etc - it can do it all.

## Cryptography 

### Resources
- [XOR Cypher](https://en.wikipedia.org/wiki/XOR_cipher) - Explains the algorithm (understand XOR is always useful - not only in cybersecurity)

### Tools
- [gchq CyberChef](https://gchq.github.io/CyberChef/) - Encryption, encoding, compression, data analysis tool.

## Forensics

### Tools
- [binwalk](https://tools.kali.org/forensics/binwalk) - Extracts hidden files in files.
- [WinRAR](https://www.rarlab.com/download.htm) - Decompression on Windows.

## Programming

### Languages
- [Python](https://www.python.org/) - Useful for basically all CTF challenges. (Recommend using [Google Colab](https://colab.research.google.com/))

### Resources
- [Esoteric Languages](https://esolangs.org/wiki/Main_Page) - Obscure programming languages.

## Network Explotation

### Tools
- [ipconfig / ifconfig](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig) - Get information about computer network.
- [Wireshark](https://www.wireshark.org/) - Network traffic monitoring.
- [nmap](https://nmap.org/) - Port analysis.

## Reverse Engineering 

### Resources
- [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) - Reference for Return-Oriented Programming.
- [trailofbits Forensics](https://trailofbits.github.io/ctf/forensics/) - Reference for forensics challenges in CTF.

### Tools
- [Android Emulator](https://developer.android.com/studio/run/emulator) - Android Emulator.
- [Cheat Engine](https://www.cheatengine.org/) - Data debugger for Windows.
- [dex2jar](https://github.com/pxb1988/dex2jar) - APK to JAR.
- [edb](https://tools.kali.org/reverse-engineering/edb-debugger) - Visual debugger for Linux.
- [gdb](https://www.gnu.org/software/gdb/) - Standard debugger for Linux.
- [Ghidra](https://ghidra-sre.org/) - Universal decompiler with C integrated.
- [IDA Freeware](https://www.hex-rays.com/products/ida/support/download_freeware.shtml) - Universal decompiler with Visual Graphs.
- [ILSpy](https://github.com/icsharpcode/ILSpy/releases) - Decompiler for C# DLL and Executables.
- [JD-GUI](http://java-decompiler.github.io/) - Visual Decompiler for Java.
- [ollydbg](http://www.ollydbg.de/) - Visual debugger cross platform (usually for Windows).

## Virtual Machines

### Images
- [CTF-Env](https://github.com/alexandre-lavoie/ctf-env) - Linux CTF Image for Docker.
- [Kali Linux](https://www.kali.org/) - Robust Linux Cybersecurity Image.
- [LiveOverflow Dockerfile](https://github.com/LiveOverflow/pwn_docker_example/blob/master/ctf/Dockerfile) - Dockerfile VM.

### Tools
- [Docker](https://www.docker.com/) - Lightweight linux virtualization.
- [VirutalBox](https://www.virtualbox.org/) - Full OS virutalization.

## Web Exploitation

### Resources
- [SQL Injection](https://www.w3schools.com/sql/sql_injection.asp) - Understanding an SQL Injection Attack.
- [XSS Scenarios](https://pentest-tools.com/blog/xss-attacks-practical-scenarios/) - Scenarios / demonstration for typical XSS attacks.
- [XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) - Understanding an XXE Injection Attack.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Reference for most web exploits. 

### Tools
- [BurpSuite Community](https://portswigger.net/burp/communitydownload) - HTTP and HTTPS traffic editing and monitoring
- [Firefox](https://www.mozilla.org/firefox/) - Browser with built-in proxy (easy to use with BurpSuite).
- [Flask](https://www.flaskapi.org/) - Customize API with Python.
- [PostBin](https://postb.in/) - GET and POST endpoint for testing requests.
- [Postman](https://www.getpostman.com/) - Customize web request.
- [gobuster](https://github.com/OJ/gobuster) - Website URL fuzzing.
- [wfuzz](https://github.com/xmendez/wfuzz) - Website fuzzing.

## Write-Ups and Tutorials
- [LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w) - Tutorials on many cybersecurity topics and write-ups for CTFs.
- [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) - Write-ups on HackTheBox VMs.