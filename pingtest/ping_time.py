import re
import subprocess

def ping_time_ms(ip_address):
    try:
        output = subprocess.check_output(["ping", "-n", "1", ip_address], shell=True, universal_newlines=True)
        match = re.search(r"temps=(\d+) ms", output)
        if match:
            return int(match.group(1)) 
        else:
            return None  
    except subprocess.CalledProcessError:
        return None  


ping_result = ping_time_ms("192.168.1.1")
if ping_result is not None:
    print(f"Temps de ping vers 192.168.1.1 : {ping_result} ms")
else:
    print("Le ping a échoué ou le temps de ping est indisponible.")
