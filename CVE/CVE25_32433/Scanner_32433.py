from Metode import *
from pathlib import Path
from utils import Logger
import keyring
import subprocess

log = Logger()

class NmapScanner(Scanner):

    def __init__(self) -> None:
        super().__init__()
        self._scanParams = {
            "scnParams": [
                "sudo", "-S",
                "nmap",
                "-sV",
                "-Pn",
                "--version-all",
                "-p", "2222",
                "--script", "ssh2-enum-algos,ssh-hostkey"
            ],
            "oputFile": "CVE/CVE25_32433/nmap_results.txt"
        }

    def scanTarget(self, prm):
        log.debugger(prm)

        self.targetIP = [prm]
        p = Path(f"Run/{prm}")
        p.mkdir(parents=True, exist_ok=True)

        self.outScanParam = self._scanParams["oputFile"]
        self.outScanFile = self._scanParams["oputFile"]
        Path(self.outScanFile).parent.mkdir(parents=True, exist_ok=True)

        base_params = self._scanParams["scnParams"].copy()
        nmap_command = base_params + ["-oN", self.outScanFile] + self.targetIP

        result_data = {
            "success": False,
            "output": "",
            "error": "",
            "message": ""
        }

        log.debugger(nmap_command)
        sudo_pass = keyring.get_password("system", "sudo")

        try:
            result = subprocess.run(
                nmap_command,
                input=sudo_pass,
                capture_output=True,
                text=True,
                check=True
            )
            result_data["success"] = True
            result_data["output"] = result.stdout
            result_data["message"] = "Scan completed successfully."
        except FileNotFoundError as ef:
            result_data["error"] = str(ef)
            result_data["message"] = f"Nmap not found {ef}.\nPlease make sure Nmap is installed and in your system's PATH."
        except subprocess.CalledProcessError as cpe:
            result_data["error"] = cpe.stderr
            result_data["message"] = f"CalledProcessError: Command failed with return code {cpe.returncode}"
        except Exception as e:
            result_data["error"] = str(e)
            result_data["message"] = "CVE-2025-32433 scan error."
            print(f"{e}.eor\n")

        return result_data
