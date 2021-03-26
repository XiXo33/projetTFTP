"""
TFTP Module.
"""

import socket
import sys
OK = '\033[92m'
END = '\033[0m'
WARNING = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[33m'
PINK = '\033[95m'

class opCode:
    RRQ = '\x00\x01'
    WRQ = '\x00\x02'
    DATA = '\x00\x03'
    ACK = '\x00\x04'
    ERROR = '\x00\x05'

########################################################################
#                          COMMON ROUTINES                             #
########################################################################
def getOpCode(message):
    opcode = message[:-15]

    if opcode == bytes(opCode.RRQ, 'ascii'):
        return "RRQ"
    elif opcode == bytes(opCode.WRQ, 'ascii'):
        return "WRQ"

def initSocket():
    """Fonction permettant l'initalisation d'un socket"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(OK + "[+] L'intitalisation du socket s'est bien passé" + END)
        return s
    except Exception as e:
        print(WARNING + "[-] Erreur : " + END, e)
        sys.exit(1)
    
def envoyerMessage(socket, addr, message):
    try:
        socket.sendto(message.encode('ascii'), addr)
        print(OK + "[+] Requête correctement envoyé" + END)
    except Exception as e:
        print(WARNING + "[-] Erreur : " + END, e)
        sys.exit(3)

########################################################################
#                             SERVER SIDE                              #
########################################################################


def runServer(addr, timeout, thread):
    s = initSocket()
    try:
        s.bind(('', addr[1]))
        print(OK + "[+] Connexion en cours ..." + END)
    except:
        print(WARNING + "[-] La connection a échoué" + END)
        sys.exit(2)

    while True:
        data, addr_client = s.recvfrom(1500)
        message_type = getOpCode(data)
        print(PINK + "[myclient:" + str(addr_client[1]) + " -> myserver:" + str(addr[1]) + "] "+ CYAN + message_type + "=" + str(data) + END)


    s.close()

########################################################################
#                             CLIENT SIDE                              #
########################################################################


def put(addr, filename, targetname, blksize, timeout):
    s = initSocket()
    messageAenvoyer = opCode.WRQ+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    s.close()

########################################################################


def get(addr, filename, targetname, blksize, timeout):
    s = initSocket()
    messageAenvoyer = opCode.RRQ+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    s.close()


