import socket
import ssl
from datetime import datetime
import pickle
import re
import subprocess
import platform
import mysql.connector



class Port():
    def __init__(self, numero, protocole):
        self.numero = numero
        self.protocole = protocole
        self.servers = []

class ServeurPort:
    def __init__(self, server_id, port_id):
        self.server_id = server_id
        self.port_id = port_id

class Server():
    def __init__(self,name, adress):
        self.name = name
        self.adress = adress
        self.ports= []
        

        self.history = []
        self.alert = False

    def check_connection(self):
        msg = ""
        success = False
        now = datetime.now()
        ping_time = None 

        try:
            for port in self.ports:
                if port.protocole == "plain":
                    socket.create_connection((self.adress, port.numero), timeout=10)
                    msg = f"{self.adress} is up. On port {port.numero} with plain."
                    success = True
                    self.alert = False
                    ping_time = self.ping()
                    if ping_time is not None:
                        msg += f" Latency: {ping_time} ms"
                elif port.protocole == "ssl":
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    ssl_socket = ssl_context.wrap_socket(socket.create_connection((self.adress, port.numero), timeout=10))
                    msg = f"{self.adress} is up. On port {port.numero} with SSL."
                    success = True
                    self.alert = False
                    ping_time = self.ping()
                    if ping_time is not None:
                        msg += f" Latency: {ping_time} ms"
                else:
                    ping_time = self.ping()
                    if ping_time is not None:
                        msg = f"{self.adress} is up with latency: {ping_time} ms. On port {port.numero} with {port.protocole}."
                        success = True
                        self.alert = False

        except socket.timeout:
            msg = f"server: {self.adress} timeout. On port {port.numero}"
        except (ConnectionRefusedError, ConnectionResetError) as e:
            msg = f"server: {self.adress} {e}"
        except Exception as e:
            msg = str(e)

        if success == False and self.alert == False:
            self.alert = True

        self.create_history(msg, success, now, ping_time)

    def create_history(self, msg, success, now, ping_time):
        history_max = 100
        self.history.append((msg, success, now, ping_time))

        while len(self.history) > history_max:
            self.history.pop(0)

    def ping(self):
        try:
            output = subprocess.check_output("ping -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c', self.adress), shell=True, universal_newlines=True)
            if 'unreachable' in output:
                return None
            else:
                ping_time_match = re.search(r"temps=(\d+) ms", output)
                if ping_time_match:
                    ping_time = int(ping_time_match.group(1))
                    return ping_time
        except Exception:
            return None








try:
    cnx = mysql.connector.connect(user='root', password='',
                                  host='127.0.0.1',
                                  port=3306,
                                  database='server_status')
    if cnx.is_connected():
        print("Connexion réussie à la base de données MySQL.")
        
        cursor = cnx.cursor()

        servers = [
            Server("reddit","reddit.com"),
            Server("msn","msn.com",),
            Server("gmail","smtp.gmail.com"),
            Server("yahoo","yahoo.com")
        ]



        server_ids = []
        for server in servers:
            query = "INSERT INTO serveur (nom, ip) VALUES (%s, %s)"
            cursor.execute(query, (server.name, server.adress))
            server_ids.append(cursor.lastrowid)
            
        port_ids = []
        for port in ports:
            query = "INSERT INTO port (numero, protocole) VALUES (%s, %s)"
            cursor.execute(query, (port.numero, port.protocole))
            port_ids.append(cursor.lastrowid)

        for server_id in server_ids:
            for port_id in port_ids:
                query = "INSERT INTO serveurPort (id_serveur, id_port) VALUES (%s, %s)"
                cursor.execute(query, (server_id, port_id))

        cnx.commit()

    else:
        print("Échec de la connexion à la base de données MySQL.")

except mysql.connector.Error as err:
    print(f"Erreur lors de la connexion à la base de données MySQL : {err}")

finally:
    if 'cnx' in locals() and cnx.is_connected():
        cnx.close()
        print("Connexion à la base de données MySQL fermée.")