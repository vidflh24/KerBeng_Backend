from Metode import *
from utils import Logger

log = Logger()

class CEnum(Enumerator):

    def __init__(self):
        super().__init__()

    def enumTarget(self):
        results = self.parse_nmap_results(self.sourceFile)
        log.debugger(self.sourceFile)
        print(f"\nhasilparse {results}\n")
        self.save_results_to_txt(results)

    def parse_nmap_results(self, filename):
        open_ports = {}
        if filename is None:
            raise ValueError("Filename cannot be none. Please provide a valid file path")

        with open(filename, "r") as file:
            lines = file.readlines()
            ip = None
            for line in lines:
                if "Nmap scan report for" in line:
                    raw = line.split()[-1].strip()
                    if raw.startswith("(") and raw.endswith(")"):
                        ip = raw[1:-1]
                    else:
                        ip = raw
                    open_ports[ip] = []
                    open_ports["ssh"] = []
                elif "/tcp" in line and ip:
                    lower = line.lower()
                    if "ssh" in lower:
                        parts = line.split()
                        if len(parts) < 3:
                            continue

                        port = parts[0].split("/")[0]
                        protocol = parts[0].split("/")[1]
                        state = parts[1]

                        service_info = {}
                        service_info["service"] = parts[2]
                        if len(parts) > 3:
                            service_info["version"] = " ".join(parts[3:])
                        else:
                            service_info["version"] = ""

                        current_port_info = {
                            "port": port,
                            "protocol": protocol,
                            "state": state,
                            "service": service_info.get("service"),
                            "info": service_info
                        }
                        open_ports[ip].append(current_port_info)

        return open_ports

    def save_results_to_txt(self, results):
        with open(self._outEnumFile, "w") as file:
            for ip, info in results.items():
                if ip == "ssh":
                    continue
                for item in info:
                    if item.get("state") == "open":
                        version = ""
                        try:
                            version = item["info"].get("version", "")
                        except Exception:
                            version = ""

                        file.write(f"{ip}  {item['port']} {version}\n")
                        data = {"port": item["port"], "service": item["service"], "version": version}
                        self.dataEnum = {ip: data}
                        print(f"{ip}  {item['port']} {item['info']}\n")

    def setTarget(self, IPAddrs):
        return super().setTarget(IPAddrs)

    def setTool(self, tool, params):
        return super().setTool(tool, params)
