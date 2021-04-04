"""
TFTP Module.
"""

import socket
import sys
from typing import Container
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
        # print(OK + "[+] L'intitalisation du socket s'est bien passé" + END)
        return s
    except Exception as e:
        print(WARNING + "[-] Erreur : " + END, e)
        sys.exit(1)
    
def envoyerMessage(socket, addr, message):
    try:
        if type(message) == bytes:
            socket.sendto(message, addr)
        else:
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
        
def decode_WRQandRRQ(message):
    """fonction permettant de récupérer l'opcode, le nom du fichier et le mode de transfert d'une requête et le renvoie dans un tuple"""        # sample of WRQ as byte array
    message1 = message[0:2]                            
    message2 = message[2:]                                
    opcode = int.from_bytes(message1, byteorder='big') 
    args = message2.split(b'\x00')                      
    filename = args[0].decode('ascii')                
    mode = args[1].decode('ascii')   

    return quelOpcode(opcode), filename, mode

def is_ACK(message):
    frame1 = message[0:2]
    return int.from_bytes(frame1, byteorder='big')


def quelOpcode(opcode):
    if opcode == 1:
        return "RRQ"
    elif opcode == 2:
        return "WRQ"
    elif opcode == 3:
        return "DAT"
    elif opcode == 4:
        return "ACK"
    
def envoieDAT(socket, addr_server, addr_client, paquet, a):
    """Envoi un message propre avec le contenu d'une portion du fichier"""
    opcodeDAT = b'\x00\x03' # \x00\x03
    enTETE = PINK + "[myserver:" + str(addr_server[1]) + " -> myclient:" + str(addr_client[1]) + "] " # [myclient:x -> myserveur:y] 
    DATx = YELLOW + "DAT" + str(int.from_bytes(a, byteorder='big')) # DAT{i}
    message_a_envoyer = enTETE + DATx + CYAN + "="  + str(opcodeDAT + a + paquet) + END
    
    envoyerMessage(socket, addr_client, message_a_envoyer)
    
def get_file(filename, addr_client, data):
    s = initSocket()
    connect(s, 0) # Mettre 0 comme numéro de port permet d'en choisir un aléatoirement parmi ceux de libre
    addr_server = s.getsockname() # On récupère l'adresse du serveur et donc le nouvel numéro de port qui sera utilisé durant l'échange avec le client
    a = b'\x00\x01'
    with open(filename, "rb") as fileToGet:
        while True:
            paquet = fileToGet.read(512) 
            envoieDAT(s, addr_server, addr_client, paquet, a) 
            
            data, _ = s.recvfrom(1500)

            if quelOpcode(is_ACK(data)) == "ACK": # Si le message a bien été acquité alors on affiche le message d'acquittement
                message_a_envoyer = PINK + "[myclient:" + str(addr_client[1]) + " -> myserver:" + str(addr_server[1]) + "] " + YELLOW + "ACK" + str(int.from_bytes(a, byteorder='big')) + CYAN + "=" + str(data) + END
                envoyerMessage(s, addr_client, message_a_envoyer)
            else:
                message_erreur = WARNING + "[-] Aucun acquitement" + END
                envoyerMessage(s, addr_client, message_erreur)
                break
            
            a = increment(a)   
                   
            if len(paquet) < 512:
                break
            
        s.close()
        
def put_file():
    s = initSocket()
    connect(s, 0) # Mettre 0 comme numéro de port permet d'en choisir un aléatoirement parmi ceux de libre
    addr_server = s.getsockname() # On récupère l'adresse du serveur et donc le nouvel numéro de port qui sera utilisé durant l'échange avec le client
    a = b'\x00\x01'
    opcodeACK = b'\x00\x04'
    messageAenvoyer = opcodeACK + a
    envoyerMessage(s, addr_server, messageAenvoyer) 


def isDAT(message):
    message = message.split(']')
    return message[1][6:9] == 'DAT'

def connexionOFClient(list_client, addr_client):
    """Ajoute un client à la liste des clients en ligne et affiche un messsage côté serveur de connexion"""
    list_client.append(addr_client[1]) 
    print(CYAN + "Le client " + PINK + str(addr_client[1]) + CYAN + " s'est connecté" + END)

def whatHewants(opcode, addr_client, filename):
    """Affiche un message côté serveur de si le client veut récupérer ou envoyer un fichier"""
    if opcode == "RRQ": choice = "récupérer"
    else: choice = "déposer"
    print(CYAN + "Le client " + PINK + str(addr_client[1]) + CYAN + " souhaite " + choice + " le fichier " + YELLOW + filename + END)

def send_whatHewants(socket, addr_server, addr_client, data, opcode):
    """Envoie au client la requête qu'il a demandé"""
    message_a_envoyer = PINK + "[myclient:" + str(addr_client[1]) + " -> myserveur:" + str(addr_server[1]) + "] " + YELLOW + opcode + CYAN + "=" + str(data) + END
    envoyerMessage(socket, addr_client, message_a_envoyer)
    
def increment(a):
    """incrémente de 1 un byte"""
    a = int.from_bytes(a, byteorder='big') + 1
    return a.to_bytes(2, byteorder='big')
########################################################################
#                             SERVER SIDE                              #
########################################################################

list_client = []

def runServer(addr, timeout, thread):
    s = initSocket() # Initialisation du socket
    connect(s, addr[1]) # Connexion au port par défault 6969
    while True:
        data, addr_client = s.recvfrom(1500)
        if addr_client not in list_client: 
            connexionOFClient(list_client, addr_client)
            opcode, filename, mode = decode_WRQandRRQ(data) # On décode la requête client
            whatHewants(opcode, addr_client, filename)
            send_whatHewants(s, addr, addr_client, data, opcode)
                                    
        if opcode == "RRQ":
            get_file(filename, addr_client, data)
        elif opcode == "WRQ":
            put_file()
            
    s.close()

########################################################################
#                             CLIENT SIDE                              #
########################################################################


def put(addr, filename, targetname, blksize, timeout):
    putting_file = open(targetname, "rb")
    s = initSocket() 
    messageAenvoyer = "\x00\x02"+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    while True:
        data, addr_server = s.recvfrom(1024)
        print(data.decode("ascii"))
    s.close()

########################################################################

def get(addr, filename, targetname, blksize, timeout):
    getting_file = open(targetname, "wb")
    s = initSocket()
    messageAenvoyer = "\x00\x01"+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    a = b'\x00\x01'
    continuer = True
    while continuer:
        data, addr_serv = s.recvfrom(1024)
        print(data.decode("ascii"))
        if isDAT(data.decode('ascii')):
            opcodeACK = b'\x00\x04'
            messageAenvoyer = opcodeACK + a
            a = increment(a)
            envoyerMessage(s, addr_serv, messageAenvoyer) 
            getting_file.write(data) # On écrit à chaque tour de boucle le paquet de taille blksize dans le fichier targetname
            
    getting_file.close() # On ferme le fichier car on en a plus besoin
    s.close()


  