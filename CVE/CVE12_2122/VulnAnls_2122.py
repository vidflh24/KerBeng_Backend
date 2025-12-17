from Metode import *
import re
from pathlib import Path
from utils import Logger

log = Logger()

class CVulnAnalist(VulnerAnalist):

    def __init__(self):
        super().__init__()
        # Daftar versi MySQL dan MariaDB yang rentan berdasarkan CVE-2012-2122
        self._vulnerable_mysql_versions = {
            "5.1": (None, "5.1.63"),
            "5.5": (None, "5.5.24"),
            "5.6": (None, "5.6.6"),
        }

        self._vulnerable_mariadb_versions = {
            "5.1": (None, "5.1.62"),
            "5.2": (None, "5.2.12"),
            "5.3": (None, "5.3.6"),
            "5.5": (None, "5.5.23"),
        }

    def startAnalising(self):
        run_dir = Path(self.targets).parent   # Run/<ip>

        with open(self.targets, "r") as file:
            lines = file.readlines()

            for line in lines:
                data = line.strip().split()
                if len(data) >= 4:
                    ip = data[0]
                    port = data[1]
                    service = data[2]
                    version = f"{data[2]} {data[3]}"

                    print(f"Processing Check Vulnerability: {ip} {port} {version}")
                    self.isVulner = False

                    if self.is_version_vulnerable(run_dir, ip, version, service):
                        vulnList = [ip, port]
                        self.addToList(vulnList)
                        print(f"Target {ip} seems to be vulnerable :)")

        # write analyst_results.txt
        with open(self.outAnalFile, "w") as outFile:
            for line in lines:
                data = line.strip().split()
                if len(data) >= 1:
                    ip = data[0]
                    vuln_file = run_dir / f"{ip}_vuln.txt"
                    if vuln_file.exists():
                        outFile.write(f"\n\n=========== Vulnerability scanning result of target {ip} \n\n")
                        outFile.write(vuln_file.read_text())

    def parse_version(self, version_str):
        return tuple(map(int, re.findall(r'\d+', version_str)))

    def is_version_vulnerable(self, run_dir, ip, version_str, service):
        version_match = re.search(r'(\d+\.\d+(\.\d+)?)', version_str)
        if not version_match:
            return self.isVulner

        version_num = version_match.group(1)
        version_tuple = self.parse_version(version_num)
        major_minor = f"{version_tuple[0]}.{version_tuple[1]}"

        if "mysql" in service.lower():
            vuln_versions = self._vulnerable_mysql_versions
        elif "mariadb" in service.lower():
            vuln_versions = self._vulnerable_mariadb_versions
        else:
            return self.isVulner

        if major_minor in vuln_versions:
            _, upper_bound = vuln_versions[major_minor]
            if self.parse_version(version_num) < self.parse_version(upper_bound):
                self.isVulner = True
                output = f"{service} on {version_str} seems to be vulnerable"

                vuln_file = run_dir / f"{ip}_vuln.txt"
                vuln_file.write_text(output)

        return self.isVulner
