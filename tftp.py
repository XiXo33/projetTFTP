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


########################################################################
#                          COMMON ROUTINES                             #
########################################################################

def initSocket():
    """Fonction permettant l'initalisation d'un socket"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(OK + "[+] L'intitalisation du socket s'est bien passé" + END)
        return s
    except:
        print(WARNING + "[-] L'initialisation du socket a échoué " + END)
        sys.exit(1)
    
def envoyerMessage(socket, addr, message):
    try:
        socket.sendto(message.encode('ascii'), addr)
    except:
        print(WARNING + "[-] Echec de l'envoi du message" + END)

###############################
#########################################
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
        data, addr = s.recvfrom(1500)
        print(CYAN + "Le client " + PINK + "[{}:{}]" + CYAN + "a fait la requête suivante : " + YELLOW + "{}".format(addr[0], addr[1], data) + END)
        s.sendto(data, addr)
    s.close()

########################################################################
#                             CLIENT SIDE                              #
########################################################################


def put(addr, filename, targetname, blksize, timeout):
    s = initSocket()

    s.close()

########################################################################


def get(addr, filename, targetname, blksize, timeout):
    s = initSocket()

    s.close()


