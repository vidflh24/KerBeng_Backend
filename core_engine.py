from typing import Dict
from AutoPentest import APentest
from CVE import *  # CVE12_2122, CVE22_46169Cacti1, ...

# map a simple string key (from GUI) to the CVE class
CVE_FACTORY: Dict[str, type[APentest]] = {
    "CVE-2012-2122": CVE12_2122.CVE12_2122,
    # "CVE-2022-46169": CVE22_46169Cacti1.CVE22_46169Cacti1,
    # add the others here...
}

def run_pentest(ip_addrs: str, cve_id: str = "CVE-2012-2122", extra_params: dict | None = None) -> dict:
    """
    Core engine entry point used by BOTH CLI and Flask.
    Returns a small dict with metadata (you can extend it later).
    """
    params: dict = {
        "ipAddrs": ip_addrs,
    }
    if extra_params:
        params.update(extra_params)

    if cve_id not in CVE_FACTORY:
        raise ValueError(f"Unsupported CVE id: {cve_id}")

    pentest_cls = CVE_FACTORY[cve_id]
    pentest_obj: APentest = pentest_cls()

    # this is your Template Method entry-point
    pentest_obj.startPentest(params)

    # if your APentest subclasses store results somewhere,
    # you can read them and return here:
    # report_path = pentest_obj.report_path
    # status = pentest_obj.status
    return {
        "ipAddrs": ip_addrs,
        "cve_id": cve_id,
        # "report_path": report_path,
        # "status": status,
    }
