import logging
import secrets
import sys
import socket
from usim import *
from utils import *
from os.path import exists

# Définition du niveau de logging
logging.basicConfig(level=logging.DEBUG)

# Paramètres de connexion
host = 'localhost'
port = 34963
buffer_size = 2**16

def UMTS(mode,path_to_input_file, path_to_output_file, Ki):
       
    if exists(path_to_output_file):
        chosen = False
        while not chosen:
            logging.warning(f"The file {path_to_output_file} already exists, do you want to override this file? [Y/N]")
            choice = input().lower()
            if choice == "n":
                return
            elif choice == "y":
                chosen = True
            
    logging.debug(f"Ki : {Ki}")

    
    if mode == "server":
        # Créer le socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        logging.info("Server waiting for connection...")

        # Accepter la connexion
        client_socket, address = server_socket.accept()
        logging.info(f"Connection accepted : {address}")

        # Générer les clés
        RAND = secrets.token_hex(16)
        SQN = '00000001'
        AMF = '69696969'
        MAC = f1(Ki, RAND, SQN, AMF)
        XRES = f2(Ki, RAND)
        CK = f3(Ki, RAND)
        IK = f4(Ki, RAND)
        AK = f5(Ki, RAND)

        SQN_AK = sxor(SQN, AK)
        AUTN = SQN_AK + AMF + MAC
        
        logging.debug(f"RAND : {RAND}")
        logging.debug(f"MAC : {MAC}")
        logging.debug(f"XRES : {XRES}")
        logging.debug(f"CK : {CK}")
        logging.debug(f"IK : {IK}")
        logging.debug(f"AK : {AK}")
        logging.debug(f"SQN_AK : {SQN_AK}")
        logging.debug(f"AUTN : {AUTN}")
        
        # Envoi du RAND et AUTN au client
        logging.info("Sending RAND + AUTN to client")
        client_socket.send((RAND + AUTN).encode())
        
        # Recupération du RES du client
        logging.info("Getting RES from client")
        RES = client_socket.recv(buffer_size).decode()
        print(f"RES : {RES}")

        # Authentifier le client
        if RES != XRES:
            logging.info("This client is not the one you think")
            return
        else:
            logging.info("Client authenticated")

        # Générer les clés de confidentialité et d'intégrité
        SCK = f8(CK,SQN, "00",4)
        logging.debug(f"SCK : {SCK}")
        CCK = f8(CK,SQN, "01",4)
        logging.debug(f"CCK : {CCK}")
        IIK = f9(IK, RAND)
        logging.debug(f"IIK : {IIK}")
        
        def regenerate_key(CK, SQN, IK):
            # Regénérer le random, l'envoyer au client et regénérer les clés
            RAND = secrets.token_hex(16)
            client_socket.send((RAND + AUTN).encode())
            SCK = f8(CK,SQN, "00",4)
            logging.debug(f"SCK : {SCK}")
            CCK = f8(CK,SQN, "01",4)
            logging.debug(f"CCK : {CCK}")
            IIK = f9(IK, RAND)
            logging.debug(f"IIK : {IIK}")


        # Modifier le random et regénérer la clé toutes les 20 minutes
        timer = set_interval(regenerate_key,20*60)
        
        # Reception du fichier client
        file_content = decrypt_file(client_socket.recv(buffer_size), CCK + IIK)
        open(path_to_output_file,"w+").write(file_content.decode())
        logging.info("File from client received")
        logging.info("File sending file to client")
        # Envoi du fichier au client
        file_content = open(path_to_input_file).read()
        client_socket.send(encrypt_file(file_content, SCK + IIK ))

        ## Tuer le timer de regénération de clés
        timer.cancel()
        
        ## Fermer la socket
        server_socket.shutdown(socket.SHUT_RDWR)
        server_socket.close()
        
    if mode == "client":
        
        # Ouvrir une connexion avec le serveur
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        logging.info("Client connected")

        logging.info("Getting RAND + AUTN from server")
        RAND_AUTN = client_socket.recv(buffer_size).decode()
        RAND = RAND_AUTN[:32]
        AUTN = RAND_AUTN[32:]
        SQN_AK = AUTN[:8]
        AMF = AUTN[8:16]
        MAC = AUTN[16:]
        logging.debug(f"RAND : {RAND}")
        logging.debug(f"AUTN : {AUTN}")
        logging.debug(f"SQN_AK : {SQN_AK}")
        logging.debug(f"AMF : {AMF}")
        logging.debug(f"MAC : {MAC}")

        RES = f2(Ki, RAND)
        CK = f3(Ki, RAND)
        IK = f4(Ki, RAND)
        AK = f5(Ki, RAND)
        SQN = sxor(SQN_AK, AK)
        logging.debug(f"RES : {RES}")
        logging.debug(f"CK : {CK}")
        logging.debug(f"IK : {IK}")
        logging.debug(f"AK : {AK}")
        logging.debug(f"SQN : {SQN}")
        
        try:
            XMAC = f1(Ki, RAND, SQN, AMF)
            logging.debug(f"XMAC : {XMAC}")
        except ValueError:
            logging.info("This server is not the one you think")

        # Authentifier le serveur
        if MAC != XMAC:
            logging.info("This server is not the one you think")
            return
        else:
            logging.info("Server authenticated")

        # Envoi du RES au server
        logging.info("Sending RES to server")
        client_socket.send(RES.encode())
                
        # Générer les clés de confidentialité et d'intégrité
        SCK = f8(CK,SQN, "00",4)
        logging.debug(f"SCK : {SCK}")
        CCK = f8(CK,SQN, "01",4)
        logging.debug(f"CCK : {CCK}")
        IIK = f9(IK, RAND)
        logging.debug(f"IIK : {IIK}")

        # Envoi du fichier au server
        file_content = open(path_to_input_file).read()
        client_socket.send(encrypt_file(file_content, CCK + IIK ))
        
        logging.info("File sending file to server")
        logging.info("File from server received")

        # Reception du fichier server
        file_content = decrypt_file(client_socket.recv(buffer_size), SCK + IIK)
        open(path_to_output_file,"w+").write(file_content.decode())


if __name__ == "__main__":
    if len(sys.argv) < 4:
        logging.info(f"Usage: {sys.argv[0]} <client/server> <path to input file> <path to ouput file> [optional]<fail (if you want to test with mismatching keys)>")
        sys.exit(0)
        
    # Arguments du programe
    mode = sys.argv[1]
    path_to_input_file = sys.argv[2]
    path_to_output_file = sys.argv[3]
    
    # C'est parti!
    if len(sys.argv) == 5:
        fail = sys.argv[4]
        UMTS(mode,path_to_input_file, path_to_output_file,secrets.token_hex(16))
    else:
        UMTS(mode,path_to_input_file, path_to_output_file,'0123456789abcdef0123456789abcdef')
    

