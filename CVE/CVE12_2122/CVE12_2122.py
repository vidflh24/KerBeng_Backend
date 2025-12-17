from AutoPentest import APentest
from Metode import *
from .Banner_2122 import CBanner
from .Enum_2122 import CEnum
from .VulnAnls_2122 import CVulnAnalist
from .Scanner_2122 import NmapScanner
from .Exploit_2122 import CExploit
from .Report_2122 import CReport
from utils import PentestUtils as pu
from utils import Logger
from pathlib import Path

log = Logger()

class CVE12_2122(APentest):
    """
    CVE12_2122 adalah concrate class yang mewarisi abstract class
    AutoPentest berisi implementasi unik dari langkah-langkah automation
    pentesting 
    """
    def __init__(self) -> None:
        super().__init__()

    def banner(self) -> None:
        ban = CBanner()
        ban.setBanner()
        #ipAddrs = ban.makeChoice()
        #self._targets = ipAddrs
        del ban
        #print(f"Your target is {self.getTargets}")

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
                # optionally: exit / raise, so we don't go to enumeration
                raise RuntimeError("Scan failed, aborting pentest flow")

            #log.debugger(pindai.outScanFile)
            self.scnOutFile = pindai.outScanFile
        del pindai

    def enumerating(self, params) -> Enumerator:
        print("Auto Pentester says I'm enumerating network target")

        enum = CEnum()

        scan_path = Path(self.scnOutFile)              # Run/127.0.0.1/nmap_results.txt
        run_dir = scan_path.parent                    # Run/127.0.0.1
        enum_out = run_dir / "enum_results.txt"

        enum.sourceFile = str(scan_path)
        enum.outEnumFile = str(enum_out)

        enum.enumTarget()

        self.enumOutFile = str(enum_out)
        self.bufHub = enum.dataEnum

        del enum

    def vulnerAnalysist(self, params) -> VulnerAnalist:
        print("Auto Pentester says I'm analysing vulnerability network target")
        vulnAnls = CVulnAnalist()
        vulnAnls.targets = self.enumOutFile
        vulnAnls.bufHub = self.bufHub
        run_dir = Path(self.enumOutFile).parent
        vulnAnls.outAnalFile = str(run_dir / "analyst_results.txt")
        vulnAnls.startAnalising()
        self.setItem("vulnList", vulnAnls.listVulners)
        #log.debugger(vulnAnls.listVulners)
        #log.debugger(vulnAnls.targets)
        del vulnAnls

    def exploitingTarget(self, params) -> Exploit:
        print("Auto Pentester says I'm exploiting network target")
        exp = CExploit()
        run_dir = Path(self.enumOutFile).parent
        exp.outExpFile = str(run_dir)
        #log.debugger(self.getItem("vulnList"))
        exp.makePayload(self.getItem("vulnList"))
        exp.startExploit()
        del exp
    
    def reporting(self, params):
        rep = CReport()
        run_dir = Path(self.enumOutFile).parent
        rep.outRepFile = str(run_dir)
        print(f"data :\n {self.bufHub}")
        rep.dataReport = self.bufHub
        rep.generate_report()
        del rep
