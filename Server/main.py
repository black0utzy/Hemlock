import os
import random
import threading
import socket
import sys

vermelho = "\033[0;31m"
roxo = "\033[0;35m"
verde = "\033[0;32m"
null = "\033[0m"

#banners
def banners(text):
    try:
        with open(text, 'r', encoding='utf-8') as f:
            strip = f.read()
        banners = [banner.strip() for banner in strip.split('"""') if banner.strip()]
        return banners
    except FileNotFoundError:
        print(f"{vermelho}Arquivo de banner faltando! | {text}{null}")
        return []
    except Exception as e:
        print(f"{vermelho}Erro: {e}{null}")
        return []

def rndm(banners):
    if not banners:
        print(f"{vermelho}Nenhum banner encontrado!{null}")
        return
    banner = random.choice(banners)
    print(f"{roxo}{banner}{null}")

def RecvData(sock):
    while True:
        
        raw_data = sock.recv(1024)
        if raw_data:
            print(raw_data.decode())


def SendData(sock):
    while True:
        raw_data = input(f"{verde}---> ")
        raw_data += "\n"
        sock.send(raw_data.encode())

def StartS(port, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen()
    print(f"{null}aguardando a conection")
    con, client = s.accept()
    print(f"{roxo}a conexão foi aceita {client}")
    return con


def main():
    file = "banners.txt"
    text = banners(file)

    while True:
        rndm(text)
        
        ip = input(f"{verde}SET IP --> {null}")
        print(f"{vermelho}IP: {ip} SET{null}")
        port = int(input(f"{verde}SET PORT --> {null}"))
        print(f"{vermelho}PORT: {port} SET{null}")

        try:    
            sock = StartS(port, ip)
            recv = threading.Thread(target=RecvData, args=(sock,))
            send = threading.Thread(target=SendData, args=(sock,))
            recv.start()
            send.start()
            break
        except:
            print(f"{vermelho}lost the connection")
        
if __name__ == "__main__":
    main()
