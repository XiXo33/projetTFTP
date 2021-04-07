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
        socket.sendto(message, addr)
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

    return opcode, filename, mode
    
def get_file(filename, addr_client, data):
    s = initSocket()
    connect(s, 0) # Mettre 0 comme numéro de port permet d'en choisir un aléatoirement parmi ceux de libre
    addr_server = s.getsockname() # On récupère l'adresse du serveur et donc le nouvel numéro de port qui sera utilisé durant l'échange avec le client
    a = b'\x00\x01'
    opcodeDAT = b'\x00\x03' 
    with open(filename, "rb") as fileToGet:
        while True:
            paquet = fileToGet.read(512) 
            envoyerMessage(s, addr_client, opcodeDAT + a + paquet)
            
            data, _ = s.recvfrom(1500)
            if decodeOPCODE(data) != 4: # Si le message n'a pas été acquité alors on affiche un message d'erreur
                print(WARNING + "ERROR" + END)
                break
            
            a = increment(a)   
                   
            if len(paquet) < 512:
                break
            
        s.close()
        
def put_file(addr_client):
    s = initSocket()
    connect(s, 0) # Mettre 0 comme numéro de port permet d'en choisir un aléatoirement parmi ceux de libre
    addr_server = s.getsockname() # On récupère l'adresse du serveur et donc le nouvel numéro de port qui sera utilisé durant l'échange avec le client
    a = b'\x00\x00'
    opcodeACK = b'\x00\x04'
    while True:
        messageAenvoyer = opcodeACK + a
        envoyerMessage(s, addr_client, messageAenvoyer) # Le message je dois l'envoyer au client 
        data, _ = s.recvfrom(1500)
        if decodeOPCODE(data) != 3: # Si le data n'a pas été envoyé alors on affiche un message d'erreur
                print(WARNING + "ERROR" + END)
                break
        if len(data) < 512:
            break
        
    s.close()
    

def decodeOPCODE(message):
    message1 = message[0:2]                                                          
    opcode = int.from_bytes(message1, byteorder='big') 
    return opcode

def connexionOFClient(list_client, addr_client):
    """Ajoute un client à la liste des clients en ligne et affiche un messsage côté serveur de connexion"""
    list_client.append(addr_client[1]) 
    print(CYAN + "Le client " + PINK + str(addr_client[1]) + CYAN + " s'est connecté" + END)

def whatHewants(opcode, addr_client, filename):
    """Affiche un message côté serveur de si le client veut récupérer ou envoyer un fichier"""
    if opcode == "RRQ": choice = "récupérer"
    else: choice = "déposer"
    print(CYAN + "Le client " + PINK + str(addr_client[1]) + CYAN + " souhaite " + choice + " le fichier " + YELLOW + filename + END)
    
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
                                    
        if opcode == 1:
            get_file(filename, addr_client, data)
        elif opcode == 2:
            put_file(addr_client)
            
    s.close()

########################################################################
#                             CLIENT SIDE                              #
########################################################################

def put(addr, filename, targetname, blksize, timeout):
    putting_file = open(targetname, "rb")
    s = initSocket() 
    addr_client = s.getsockname()
    messageAenvoyer = b"\x00\x02"+filename.encode('ascii')+b"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    
    print(PINK + "[myclient:" + str(addr_client[1]) + " -> myserveur:" + str(addr[1]) + "] " + YELLOW + "WRQ" + CYAN + "=" + str(messageAenvoyer) + END)

    a = b'\x00\x00'
    opcodeDAT = b'\x00\x03' 
    
    while True:
        data, addr_serv = s.recvfrom(1024)
        if decodeOPCODE(data) == 4:
            print(PINK + "[myserver:" + str(addr_serv[1]) + " -> myclient:" + str(addr_client[1]) + "] " + YELLOW + "ACK" + str(int.from_bytes(a, byteorder='big')) + CYAN + "=" + str(messageAenvoyer) + END)
           
            
            paquet = putting_file.read(512) 
            envoyerMessage(s, addr_serv, opcodeDAT + a + paquet)
            
            print(PINK + "[myclient:" + str(addr_client[1]) + " -> myserveur:" + str(addr_serv[1]) + "] " + YELLOW + "DAT" + str(int.from_bytes(a+b'\x00\x01', byteorder='big')) + CYAN + "=" + str(paquet) + END)
            
            if len(paquet) < 512: 
                break
            
            increment(a)
        else:
            print(WARNING + "ERROR" + END)
            
    putting_file.close()
    s.close()

########################################################################

def get(addr, filename, targetname, blksize, timeout):
    getting_file = open(targetname, "wb+")
    
    s = initSocket()
    addr_client = s.getsockname()
    
    messageAenvoyer = b"\x00\x01"+filename.encode('ascii')+b"\x00octet\x00"
    envoyerMessage(s, addr,messageAenvoyer)
    
    print(PINK + "[myclient:" + str(addr_client[1]) + " -> myserveur:" + str(addr[1]) + "] " + YELLOW + "RRQ" + CYAN + "=" + str(messageAenvoyer) + END)
    
    a = b'\x00\x01'
    while True:
        data, addr_serv = s.recvfrom(1024)
        if decodeOPCODE(data) == 3: 
            print(PINK + "[myserver:" + str(addr_serv[1]) + " -> myclient:" + str(addr_client[1]) + "] " + YELLOW + "DAT" + str(int.from_bytes(a, byteorder='big')) + CYAN + "="  + str(data) + END)
            
            opcodeACK = b'\x00\x04'
            messageAenvoyer = opcodeACK + a
            
            print(PINK + "[myclient:" + str(addr_client[1]) + " -> myserver:" + str(addr_serv[1]) + "] " + YELLOW + "ACK" + str(int.from_bytes(a, byteorder='big')) + CYAN + "=" + str(messageAenvoyer) + END)
            a = increment(a)
            envoyerMessage(s, addr_serv, messageAenvoyer) 
            
            getting_file.write(data[4:]) # On écrit à chaque tour de boucle le paquet de taille blksize dans le fichier targetname
            
            if len(data) < 512: 
                break

    getting_file.close() 
    s.close()


  