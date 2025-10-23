from Metode import *
import pprint
import re

class CEnum(Enumerator):

    def __init__(self):
        super().__init__()

    def enumTarget(self):
        print("[DEBUG] Starting Nmap parsing...")
        results = self.parse_nmap_results(self.sourceFile)
        print("[DEBUG] Finished parsing. Now saving results...")
        self.save_results_to_txt(results)
        print("[DEBUG] Enum complete. Output written to:", self._outEnumFile)

    def parse_nmap_results(self, filename):
        open_ports = {}
        if filename is None:
            raise ValueError("Filename cannot be None. Please provide a valid file path")
        
        print(f"[DEBUG] Opening Nmap file: {filename}")
        ip_re = re.compile(r'\((\d{1,3}(?:\.\d{1,3}){3})\)')  # matches (127.0.0.1)
        ip_simple_re = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')  # matches 127.0.0.1 anywhere

        with open(filename, "r") as fh:
            lines = fh.readlines()
            ip = None
            current_port_info = None

            for line_num, raw in enumerate(lines, start=1):
                line = raw.strip()
                # optional: reduce noise in debug
                # print(f"[RAW LINE {line_num}] {line}")

                if "Nmap scan report for" in line:
                    # try to extract ip inside parentheses first: "host (1.2.3.4)"
                    m = ip_re.search(line)
                    if m:
                        ip = m.group(1)
                    else:
                        # fallback: try to find any dotted-quad in the line
                        m2 = ip_simple_re.search(line)
                        if m2:
                            ip = m2.group(1)
                        else:
                            # if there's no numeric ip, take last token (could be hostname)
                            ip = line.split()[-1].strip()
                    # normalize: ensure we don't keep parentheses or surrounding text
                    ip = ip.strip("()")
                    open_ports[ip] = []
                    print(f"\033[92m[DEBUG] Found/normalized target IP: {ip}\033[0m")
                    current_port_info = None

                elif "/tcp" in line and ip:
                    parts = line.split()
                    # try-safe parsing in case of weird spacing
                    port_proto = parts[0]
                    if '/' in port_proto:
                        port = port_proto.split("/")[0]
                        protocol = port_proto.split("/")[1]
                    else:
                        port = port_proto
                        protocol = "tcp"

                    state = parts[1] if len(parts) > 1 else "unknown"
                    service = parts[2] if len(parts) > 2 else "unknown"
                    service_info = {"service": service}
                    if len(parts) > 3:
                        service_info["version"] = " ".join(parts[3:])

                    current_port_info = {
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "info": service_info
                    }

                    print(f"\033[94m[DEBUG] Found port entry for {ip}: {current_port_info}\033[0m")

                    # By default, append port entries immediately if open.
                    # If you want to only append when certain script output appears,
                    # comment the following block and let script-specific branches append.
                    if state.lower() == "open":
                        open_ports[ip].append(current_port_info)
                        # keep current_port_info around in case a following script line adds extra info

                # handle script lines that annotate the last port (http-enum style)
                elif line.startswith("|_") and current_port_info:
                    # generic handling: try to capture http-title or script findings
                    # example lines:
                    #   "|_http-title: Apache2 Ubuntu Default Page: It works"
                    #   "|_  /docs/: Potentially interesting folder"
                    # We attach the entire script text to the port info under 'scripts'
                    script_text = line[2:].lstrip()  # remove leading "|_"
                    # a more advanced parser could split by ":" etc.
                    current_port_info.setdefault("scripts", []).append(script_text)

                    # try to capture http-title specifically
                    if "http-title" in script_text:
                        # e.g. "http-title: Apache2 Ubuntu Default Page"
                        parts = script_text.split(":", 1)
                        if len(parts) == 2:
                            current_port_info["info"]["http-title"] = parts[1].strip()
                            print(f"[DEBUG] Attached http-title to {ip}:{current_port_info['port']}: {current_port_info['info']['http-title']}")

                    # ensure port is in the open_ports list (if not already)
                    if current_port_info not in open_ports[ip]:
                        open_ports[ip].append(current_port_info)

                    # keep or reset current_port_info depending on whether more script lines are expected
                    # We'll keep it to allow multiple script lines to collect
                else:
                    # any other line — reset current_port_info sometimes
                    # but don't be too aggressive; keep it for multi-line scripts
                    pass

        # Pretty-print all parsed results for final inspection
        print("\n\033[95m[DEBUG] Final parsed Nmap results:\033[0m")
        pprint.pprint(open_ports, sort_dicts=False)
        print("open_ports: ", open_ports)

        return open_ports

    def save_results_to_txt(self, results):
        print(f"[DEBUG] Writing parsed open ports to: {self._outEnumFile}")
        with open(self._outEnumFile, "w") as file:
            for ip, ports in results.items():
                print(f"[DEBUG] IP: {ip}")
                for port in ports:
                    if port["state"] == "open":
                        print(f"   [DEBUG] Open port: {port['port']} ({port['service']})")
                        file.write(f"{ip}  {port['port']}\n")

    def setTarget(self, IPAddrs):
        return super().setTarget(IPAddrs)
    
    def setTool(self, tool, params):
        return super().setTool(tool, params)
