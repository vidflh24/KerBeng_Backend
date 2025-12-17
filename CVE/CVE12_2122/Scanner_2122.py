from Metode import *
from pathlib import Path
from utils import Logger
import keyring

log = Logger()

class NmapScanner(Scanner):

    def __init__(self) -> None:
        super().__init__()
        self._scanParams = {
            "scnParams":["sudo", "-S","nmap", "-sV", "-Pn", "-O"],
            #"oputFile":"CVE/CVE12_2122/nmap_results.txt"
        }
    
    def scanTarget(self, prm):
        self.targetIP = [prm]

        run_dir = Path("Run") / prm
        run_dir.mkdir(parents=True, exist_ok=True)

        out_file = run_dir / "nmap_results.txt"
        self.outScanFile = str(out_file)
        self.outScanParam = str(out_file)

        base_params = self._scanParams["scnParams"].copy()

        nmap_command = (
            base_params
            + ["-oN", self.outScanFile]
            + self.targetIP
        )

        result_data = {
            'success': False,
            'output': '',
            'error': '',
            'message': ''
        }

        sudo_pass = keyring.get_password("system", "sudo")

        try:
            result = subprocess.run(
                nmap_command,
                input=sudo_pass,
                capture_output=True,
                text=True,
                check=True
            )
            result_data['success'] = True
            result_data['output'] = result.stdout
            result_data['message'] = "Scan completed successfully."

        except FileNotFoundError as ef:
            result_data['error'] = str(ef)
            result_data['message'] = "Nmap not found."

        except subprocess.CalledProcessError as cpe:
            result_data['error'] = cpe.stderr
            result_data['message'] = f"Command failed ({cpe.returncode})"

        except Exception as e:
            result_data['error'] = str(e)
            result_data['message'] = "MySQL not detected"

        return result_data
        
