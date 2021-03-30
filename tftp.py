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

class Opcodes:
    RRQ = "\x00\x01"
    WRQ = "\x00\x02"
    DATA = "\x00\x03"
    ACK = "\x00\x04"
    ERROR = "\x00\x05"
########################################################################
#                          COMMON ROUTINES                             #
########################################################################
def initSocket():
    """Fonction permettant l'initalisation d'un socket"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # print(OK + "[+] L'intitalisation du socket s'est bien passé" + END)
        return s
    except Exception as e:
        print(WARNING + "[-] Erreur : " + END, e)
        sys.exit(1)
    
def envoyerMessage(socket, addr, message):
    try:
        socket.sendto(message.encode('ascii'), addr)
    except Exception as e:
        print(WARNING + "[-] Erreur : " + END, e)
        sys.exit(3)

def connect(socket, port):
    """Fonction permettant de se connecter à un port donné"""
    try:
        socket.bind(('', port)) 
        # print(OK + "[+] Connexion réussi" + END)
    except:
        print(WARNING + "[-] La connection a échoué" + END)
        sys.exit(2)
        
def decode_messageOFclient(message):
    """fonction permettant de récupérer l'opcode, le nom du fichier et le mode de transfert d'une requête et le renvoie dans un tuple"""        # sample of WRQ as byte array
    message1 = message[0:2]                            
    message2 = message[2:]                                
    opcode = int.from_bytes(message1, byteorder='big') 
    args = message2.split(b'\x00')                      
    filename = args[0].decode('ascii')                
    mode = args[1].decode('ascii')  
    return opcode, filename, mode

def quelOpcode(opcode):
    if opcode == 1:
        return "RRQ"
    elif opcode == 2:
        return "WRQ"
    elif opcode == 3:
        return "DAT"
    
def request(filename, addr_client):
    s = initSocket()
    connect(s, 0)
    addr_server = s.getsockname()
    with open(filename, "rb") as fileToGet:
        i = 1
        while True:
            paquet = fileToGet.read(512)
            message_a_envoyer = "[myserver:" + str(addr_server[1]) + " -> myclient:" + str(addr_client[1]) + "] " + "DAT" + str(i) + "=" + str(paquet)
            envoyerMessage(s, addr_client, message_a_envoyer)
            data, _ = s.recvfrom(1500)
            message_a_envoyer = "[myclient:" + str(addr_client[1]) + " -> myserver:" + str(addr_server[1]) + "] " + "ACK" + str(i) + "=" + str(data)
            envoyerMessage(s, addr_client, message_a_envoyer)
            if len(paquet) < 512:
                break
        i += 1

########################################################################
#                             SERVER SIDE                              #
########################################################################


def runServer(addr, timeout, thread):
    s = initSocket() #Initialisation du socket
    connect(s, addr[1]) # Connexion au port par défault 6969
    while True:
        data, addr_client = s.recvfrom(1500)
        print(CYAN + "Le client " + PINK + str(addr_client[1]) + CYAN + " s'est connecté" + END)
        opcode, filename, mode = decode_messageOFclient(data)
        opcode = quelOpcode(opcode)
        message_a_envoyer = "[myclient:" + str(addr_client[1]) + " -> myserveur:" + str(addr[1]) + "] " + opcode + "=" + str(data)
        envoyerMessage(s, addr_client, message_a_envoyer)
        if opcode == "RRQ":
            request(filename, addr_client)
            break     
    s.close()

########################################################################
#                             CLIENT SIDE                              #
########################################################################


def put(addr, filename, targetname, blksize, timeout):
    s = initSocket()
    messageAenvoyer = Opcodes.WRQ+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    data, _ = s.recvfrom(1024)
    print(data.decode("ascii"))
    s.close()

########################################################################


def get(addr, filename, targetname, blksize, timeout):
    s = initSocket()
    messageAenvoyer = Opcodes.RRQ+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    i = 1
    while True:
        data, addr_serv = s.recvfrom(1024)
        messageAenvoyer = Opcodes.ACK+"\x00\x01"
        envoyerMessage(s, addr_serv, messageAenvoyer)
        print(data.decode("ascii"))
        i += 1
    s.close()


