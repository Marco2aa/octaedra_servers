import subprocess
import os

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
                    site.ports.append(port_obj)
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
]

for site in urls:
    open_ports = scan_ports(site)
    if open_ports:
        for port_obj in site.ports:
            print("Port:", port_obj.port)
            print("State:", port_obj.state)
            print("Service:", port_obj.service)
            print()