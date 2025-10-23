from AutoPentest import APentest
from CVE import *

def client_code(autoPentest: APentest, params) -> None:
    autoPentest.startPentest(params)

if __name__ == "__main__":
    params = {
        "ipAddrs":""
    }
    params["ipAddrs"] = input("Input targets' IP Address: ")
    #client_code(CVE12_2122.CVE12_2122(), params)
    #client_code(CVE22_46169.CVE22_46169Cacti1(), params)
    client_code(CVE_pgadmin_0001.CVE_PGADMIN_0001(), params)
