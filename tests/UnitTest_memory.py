import tracemalloc
from AutoPentest import APentest
from CVE import *
import time

params = {
        "ipAddrs":"10.33.102.225"
    }

def testMemoriEksekusi(iterasi=100):
    # memulai tracemalloc
    tracemalloc.start()

    # snapshot sebelum memulai
    snapshot_sebelum = tracemalloc.take_snapshot()

    for _ in range(iterasi):
        client_code(CVE22_46169.CVE22_46169Cacti1(), params)

    time.sleep(1)

    # ambil snapshot setelah pembuatan dan penghapusan objek
    snapshot_sesudah = tracemalloc.take_snapshot()

    # hitung perbedaan penggunaan memori
    top_stats = snapshot_sesudah.compare_to(snapshot_sesudah, 'lineno')

    print("Perbedaan penggunaan memori: ")
    for stat in top_stats[:10]:
        print(stat)

    # stop tracking penggunaan memori
    tracemalloc.stop()
    


def client_code(autoPentest: APentest, params) -> None:
    autoPentest.startPentest(params)
    del autoPentest


if __name__ == "__main__":
    testMemoriEksekusi()