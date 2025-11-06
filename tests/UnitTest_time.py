from AutoPentest import APentest
from CVE import *
import time

params = {
        "ipAddrs":"10.33.102.225"
    }

def format_time(seconds):
    minutes = int(seconds // 60)
    seconds = seconds % 60
    return {f"{minutes} m {seconds:.2f}s"}

def testWaktuEksekusi(iterasi=10):
    total_waktu = []
    daftar_waktu = []
    for _ in range(iterasi):
        startTime = time.time()
        client_code(CVE22_46169.CVE22_46169Cacti1(), params)
        daftar_waktu.append(format_time(time.time() - startTime))
        total_waktu.append(time.time() - startTime)
    print(f"\ntotal waktu: {daftar_waktu}\n")
    rerata_waktu = sum(total_waktu) / iterasi
    daftar_waktu.append(format_time(rerata_waktu))
    print(f"\n\n+++++Waktu eksekusi autopentest: {format_time(rerata_waktu)} +++++++\n\n")
    saveData(daftar_waktu)


def saveData(dataTime):
    with open("timeRecord.txt", "w") as file:
        file.write(f"{dataTime}\n")

def client_code(autoPentest: APentest, params) -> None:
    autoPentest.startPentest(params)


if __name__ == "__main__":
    testWaktuEksekusi()