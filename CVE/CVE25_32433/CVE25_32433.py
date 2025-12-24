from AutoPentest import APentest
from Metode import *
from .Banner_32433 import CBanner
from .Enum_32433 import CEnum
from .VulnAnls_32433 import CVulnAnalist
from .Scanner_32433 import NmapScanner
from .Exploit_32433 import CExploit
from .Report_32433 import CReport
from utils import PentestUtils as pu
from utils import Logger
from pathlib import Path

log = Logger()

class CVE25_32433(APentest):
    """
    CVE25_32433 adalah concrete class yang mewarisi abstract class
    AutoPentest berisi implementasi langkah-langkah automation pentesting
    untuk indikator CVE-2025-32433 (Erlang/OTP SSH)
    """
    def __init__(self) -> None:
        super().__init__()

    def banner(self) -> None:
        ban = CBanner()
        ban.setBanner()
        del ban

    def scanning(self, params) -> Scanner:
        if not self.getTargets:
            print(f"Invalid target ({self.getTargets})")
            exit(0)

        print(f"Auto Pentester says I'm scanning target {self.getTargets} from {self.getLHost}")
        for ip in self.getTargets:
            if pu.isPrivateIP(ip) == True:
                pindai = NmapScanner()
            else:
                pindai = Shodan()
            scan_result = pindai.scanTarget(ip)

            if not scan_result["success"]:
                print("[-] Scan failed")
                print(scan_result["message"])
                print(scan_result["error"])
                raise RuntimeError("Scan failed, aborting pentest flow")

            log.debugger(pindai.outScanFile)
            self.scnOutFile = pindai.outScanFile
        del pindai

    def enumerating(self, params) -> Enumerator:
        print("Auto Pentester says I'm enumerating network target")
        enum = CEnum()
        enum.outEnumFile = "CVE/CVE25_32433/enum_results.txt"
        enum.sourceFile = self.scnOutFile
        enum.enumTarget()
        self.enumOutFile = enum.outEnumFile
        log.debugger(enum.dataEnum)
        self.bufHub = enum.dataEnum
        del enum

    def vulnerAnalysist(self, params) -> VulnerAnalist:
        print("Auto Pentester says I'm analysing vulnerability network target")
        vulnAnls = CVulnAnalist()
        vulnAnls.targets = self.enumOutFile
        vulnAnls.bufHub = self.bufHub
        vulnAnls.outAnalFile = "CVE/CVE25_32433/analyst_results.txt"
        vulnAnls.startAnalising()
        self.setItem("vulnList", vulnAnls.listVulners)
        log.debugger(vulnAnls.listVulners)
        log.debugger(vulnAnls.targets)
        del vulnAnls

    def exploitingTarget(self, params) -> Exploit:
        print("Auto Pentester says I'm exploiting network target")

        exp = CExploit()
        exp.outExpFile = "CVE/CVE12_2122/"
        vuln_list = self.getItem("vulnList")
        cmd = params['command']
        vuln_list_with_cmd = [
            row + [cmd] for row in vuln_list
        ]
        log.debugger(vuln_list_with_cmd)
        exp.makePayload(vuln_list_with_cmd)
        exp.startExploit()
        del exp

    def reporting(self, params):
        rep = CReport()
        rep.outRepFile = "CVE/CVE25_32433/"
        print(f"data :\n {self.bufHub}")
        rep.dataReport = self.bufHub
        rep.generate_report()
        del rep
