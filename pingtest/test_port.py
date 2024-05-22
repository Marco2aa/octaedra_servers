import subprocess
import os
import mysql.connector

os.environ['PATH'] += r';C:\Program Files (x86)\Nmap'

class Url:
    def __init__(self, url):
        self.url = url
        self.ports = []

class Port:
    def __init__(self, port, state, service):
        self.port = port
        self.state = state
        self.service = service

class serveurPort:
    def __init__(self, id_url, id_port):
        self.id_url = id_url
        self.id_port = id_port

def scan_ports(url: Url):
    command = f"nmap -p- {url.url}"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            open_ports = []
            for line in result.stdout.split('\n'):
                if '/tcp' in line:
                    port, state, service = line.split()[:3]
                    port_obj = Port(port, state, service)
                    url.ports.append(port_obj)
                    open_ports.append((port, state, service))
            return open_ports
        else:
            print(f"Erreur lors de l'exécution de la commande nmap sur {url.url}: {result.stderr}")

    except subprocess.TimeoutExpired:
        print(f"Nmap a pris trop de temps pour scanner : {url.url}")

    except Exception as e:
        print(f"Erreur lors du scan de {url.url} : {e}")

urls = [
    Url('corsicalinea.octaedra.com'),
    Url('resaportcorse.com'),
    Url('appli.magelan-eresa.com'),
    Url('www.eboutique.ajaccio-tourisme.com'),
    Url('boutique.taravo-ornano-tourisme.com'),
    Url('2d.magelan-eresa.com'),
    Url('management.octaedra.com')
]

try:
    cnx = mysql.connector.connect(user='root', password='',
                                  host='127.0.0.1',
                                  port=3306,
                                  database='octaedra_servers')
    if cnx.is_connected():
        print("Connexion réussie à la base de données MySQL.")
        
        cursor = cnx.cursor()

        url_ids = {}

        for url in urls:
            print(f"Inserting URL {url.url} into database...")
            query = 'INSERT INTO url (url) VALUES (%s)'
            cursor.execute(query ,(url.url,))
            url_id = cursor.lastrowid
            url_ids[url.url] = url_id


            open_ports = scan_ports(url)
            if open_ports:
                for port_obj in url.ports:
                    port_without_tcp = port_obj.port.split("/")[0]
                    print("Port:", port_without_tcp)
                    print("State:", port_obj.state)
                    print("Service:", port_obj.service)
                    print()
                    query = 'INSERT INTO port (port, state, service) VALUES (%s, %s, %s)'
                    cursor.execute(query, (port_obj.port, port_obj.state, port_obj.service))
                    port_id = cursor.lastrowid

                    query = 'INSERT INTO serveurPort (id_url, id_port) VALUES (%s, %s)'
                    cursor.execute(query, (url_id, port_id))

        cnx.commit()
        print("Données insérées avec succès dans la base de données.")

    else:
        print("Échec de la connexion à la base de données MySQL.")

except mysql.connector.Error as err:
    print(f"Erreur lors de la connexion à la base de données MySQL : {err}")

finally:
    if 'cnx' in locals() and cnx.is_connected():
        cnx.close()
        print("Connexion à la base de données MySQL fermée.")
