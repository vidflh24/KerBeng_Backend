from AutoPentest import APentest
from CVE import *

def client_code(autoPentest: APentest, params) -> None:
    
    autoPentest.startPentest(params)

if __name__ == "__main__":

    params = {
        "ipAddrs":"10.33.102.225"
    }
    client_code(CVE12_2122.CVE12_2122(), params)
    #client_code(CVE22_46169.CVE22_46169Cacti1(), params)
