from Metode import *
import re
from utils import Logger

log = Logger()

class CVulnAnalist(VulnerAnalist):

    def __init__(self):
        super().__init__()
        self._vulnerable_otp_versions = {
            "OTP": (None, None)
        }

    def startAnalising(self):
        with open(self.targets, "r") as file:
            lines = file.readlines()
            for line in lines:
                data = line.strip().split()
                if len(data) >= 2:
                    ip = data[0]
                    port = data[1]
                    version_str = ""
                    if len(data) >= 3:
                        version_str = " ".join(data[2:])

                    print(f"Processing Check Vulnerability: {ip} {port} {version_str}")
                    self.isVulner = True
                    log.debugger(self.is_target_potentially_vulnerable(ip, version_str))
                    if self.is_target_potentially_vulnerable(ip, version_str):
                        vulnList = [ip, port]
                        log.debugger(vulnList)
                        self.addToList(vulnList)
                        print(f"Target {self.listVulners} is seem to be vulnerable :)")

        with open(self.outAnalFile, "w") as outFile:
            for line in lines:
                data = line.strip().split()
                if len(data) >= 1:
                    ip = data[0]
                    try:
                        with open(f"CVE/CVE25_32433/{ip}_vuln.txt", "r") as vulnFile:
                            outFile.write(f"\n\n=========== Vulnerability scanning result of target {ip} \n\n")
                            outFile.write(vulnFile.read())
                    except FileNotFoundError:
                        print(f"No vulnerability file found for {ip}")

    def parse_version(self, version_str):
        return tuple(map(int, re.findall(r"\d+", version_str)))

    def extract_otp_version(self, text):
        m = re.search(r"(?:OTP|Erlang/OTP)\s*[-/]?\s*(\d+(?:\.\d+){0,2})", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\b(\d+(?:\.\d+){1,2})\b", text)
        return m.group(1) if m else None

    def is_target_potentially_vulnerable(self, ip, version_str):
        s = (version_str or "").lower()

        is_erlang_ssh = ("erlang" in s) or ("otp" in s)
        if not is_erlang_ssh:
            return self.isVulner

        otp_ver = self.extract_otp_version(version_str or "")
        self.isVulner = True

        details = []
        details.append("Service appears to be Erlang/OTP SSH based on version/banner fingerprint.")
        details.append("CVE-2025-32433 affects Erlang/OTP SSH server implementations (pre-auth risk).")
        if otp_ver:
            details.append(f"Detected OTP version indicator: {otp_ver}")
        else:
            details.append("OTP version could not be reliably extracted from scan output.")

        details.append("Recommendation: verify Erlang/OTP SSH package version against vendor advisory and patch if needed.")
        details.append("This tool flags POTENTIAL based on fingerprint only, not proof of exploitation.")

        output = "\n".join(details)
        with open(f"CVE/CVE25_32433/{ip}_vuln.txt", "w") as f:
            f.write(output)

        return self.isVulner
