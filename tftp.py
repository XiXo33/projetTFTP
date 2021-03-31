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
    
def get_file(filename, addr_client, data):
    s = initSocket()
    connect(s, 0)
    addr_server = s.getsockname()
    with open(filename, "rb") as fileToGet:
        i = 1
        while True:
            paquet = fileToGet.read(512)  
            message_a_envoyer = PINK + "[myserver:" + str(addr_server[1]) + " -> myclient:" + str(addr_client[1]) + "] " + "DAT" + str(i) + CYAN + "=" + str(paquet) + END
            envoyerMessage(s, addr_client, message_a_envoyer)
            
            data, _ = s.recvfrom(1500)
            
            if quelOpcode(is_ACK(data)) == "ACK": # Si le message a bien été acquité alors on affiche le message d'acquittement
                message_a_envoyer = PINK + "[myclient:" + str(addr_client[1]) + " -> myserver:" + str(addr_server[1]) + "] " + YELLOW + "ACK" + str(i) + CYAN + "=" + str(data) + END
                envoyerMessage(s, addr_client, message_a_envoyer)
            else:
                message_erreur = WARNING + "[-] Aucun acquitement" + END
                envoyerMessage(s, addr_client, message_erreur)
                break
            
                
            if len(paquet) < 512:
                break
                
            i += 1
        s.close()
        
def put_file():
    pass

def isDAT(message):
    message = message.split(b"]")
    return message[1][1:4] == b"DAT"

def connexionOFClient(list_client, addr_client):
    """Ajoute un client à la liste des clients en ligne et affiche un messsage côté serveur de connexion"""
    list_client.append(addr_client) 
    print(CYAN + "Le client " + PINK + str(addr_client[1]) + CYAN + " s'est connecté" + END)

def whatHewants(opcode, addr_client, filename):
    """Affiche un message côté serveur de ce que le client veut faire"""
    if opcode == "RRQ": choice = "récupérer"
    else: choice = "déposer"
    print(CYAN + "Le client " + PINK + str(addr_client[1]) + CYAN + " souhaite " + choice + " le fichier " + YELLOW + filename + END)

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
            message_a_envoyer = PINK + "[myclient:" + str(addr_client[1]) + " -> myserveur:" + str(addr[1]) + "] " + YELLOW + opcode + CYAN + "=" + str(data) + END
            envoyerMessage(s, addr_client, message_a_envoyer)
            
        if opcode == "RRQ":
            get_file(filename, addr_client, data)
        elif opcode == "WRQ":
            put_file()
            
    s.close()

########################################################################
#                             CLIENT SIDE                              #
########################################################################


def put(addr, filename, targetname, blksize, timeout):
    s = initSocket()
    messageAenvoyer = "\x00\x02"+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    data, _ = s.recvfrom(1024)
    print(data.decode("ascii"))
    s.close()

########################################################################

def get(addr, filename, targetname, blksize, timeout):
    getting_file = open(targetname, "wb")
    s = initSocket()
    messageAenvoyer = "\x00\x01"+filename+"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    i = 1
    continuer = True
    while continuer:
        data, addr_serv = s.recvfrom(1024)
        print(data.decode("ascii"))
        if isDAT(data):
            messageAenvoyer = "\x00\x04" + "\x00"
            envoyerMessage(s, addr_serv, messageAenvoyer)
            data = data.split(b']')
            data = data[1][11:-4]
            getting_file.write(data)
            if len(data) < 512:
                break
        i += 1
        
    getting_file.close()
    s.close()


  