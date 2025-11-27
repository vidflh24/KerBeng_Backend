from argparse import ArgumentParser
from colorama import init
from AutoPentest import APentest
from CVE import *

init(autoreset=True)

# map CVE ID string -> class
CVE_FACTORY = {
    "CVE12_2122": CVE12_2122.CVE12_2122,
    # add others here:
    # "CVE22_46169": CVE22_46169Cacti1.CVE22_46169Cacti1,
}

def client_code(autoPentest: APentest, params) -> None:
    autoPentest.startPentest(params)

def main():
    parser = ArgumentParser()
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--cve", required=True, help="CVE id / module key")
    args = parser.parse_args()

    params = {
        "ipAddrs": args.ip,   # your backend expects this key
    }

    if args.cve not in CVE_FACTORY:
        raise ValueError(f"Unsupported CVE: {args.cve}")

    pentest_cls = CVE_FACTORY[args.cve]
    client_code(pentest_cls(), params)

if __name__ == "__main__":
    main()
