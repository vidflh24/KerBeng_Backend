from Metode import *
from pathlib import Path
from utils import Logger
import keyring

log = Logger()

class NmapScanner(Scanner):

    def __init__(self) -> None:
        super().__init__()
        self._scanParams = {
            "scnParams":["sudo", "-S","nmap", "-sV", "-sC", "-Pn", "-O"],
            "oputFile":"CVE/CVE12_2122/nmap_results.txt"
        }
    
    def scanTarget(self, prm):
        self.targetIP = [prm]
        p = Path(f'Run/{prm}')
        p.mkdir(parents=True, exist_ok=True)
        self.outScanParam = self._scanParams['oputFile']
        self.outScanFile = self._scanParams['oputFile']
        #self.params = self._scanParams['scnParams']
        Path(self.outScanFile).parent.mkdir(parents=True, exist_ok=True)
        #print(f"target IP: {self.targetIP}")
        base_params = self._scanParams["scnParams"].copy()
        #nmap_command = self.params
        #nmap_command.extend(self.targetIP)
        #nmap_command.extend(self.outScanParam)
        #print(f"nmap_command is: {nmap_command}")
        nmap_command = (
            base_params
            + ["-oN", self.outScanFile]   # tell nmap to write normal output to file
            + self.targetIP
        )
        result_data = {
            'success' : False,
            'output' : '',
            'error' : '',
            'message' : ''
        }
        log.debugger(nmap_command)
        sudo_pass = keyring.get_password("system", "sudo")
        #print(f"[DEBUG] sudo_pass from keyring: {repr(sudo_pass)}")
        
        try:
            result = subprocess.run(nmap_command,
                                    input=sudo_pass,
                                    capture_output=True,
                                    text=True,
                                    check=True)
            result_data['success'] = True
            result_data['output'] = result.stdout
            result_data['message'] = "Scan complated successfully."
        except FileNotFoundError as ef:
            result_data['error'] = str(ef)
            result_data['message'] = f"Nmap not found {ef}.\nPlease make sure Nmap is installed and in your system's PATH."
        except subprocess.CalledProcessError as cpe:
            result_data['error'] = cpe.stderr
            result_data['message'] = f"CalledProcessError: Command failed with return code {cpe.returncode}"
        except Exception as e:
            result_data['error'] = str(e)
            result_data['message'] = "CVE12_2122's IoC: MySQL is not detected"
            print(f"{e}.eor\n")
        return result_data
    
