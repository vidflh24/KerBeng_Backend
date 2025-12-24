from argparse import ArgumentParser
from colorama import init
from AutoPentest import APentest
from CVE import *
from utils import Logger

log = Logger()

init(autoreset=True)

# map CVE ID string -> class
CVE_FACTORY = {
    "CVE12_2122": CVE12_2122.CVE12_2122,
    "CVE25_32433": CVE25_32433.CVE25_32433
    # add others here:
    # "CVE22_46169": CVE22_46169Cacti1.CVE22_46169Cacti1,
}

def client_code(autoPentest: APentest, params) -> None:
    autoPentest.startPentest(params)

def main():
    parser = ArgumentParser()
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--cve", required=True, help="CVE id / module key")
    parser.add_argument("--com", required=False, help="Command Untuk RCE")
    args = parser.parse_args()

    params = {
        "ipAddrs": args.ip,   # your backend expects this key
        "command": args.com,
    }

    if args.cve not in CVE_FACTORY:
        raise ValueError(f"Unsupported CVE: {args.cve}")

    pentest_cls = CVE_FACTORY[args.cve]
    log.debugger(params)
    client_code(pentest_cls(), params)

if __name__ == "__main__":
    main()
