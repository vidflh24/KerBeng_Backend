from colorama import init, Fore, Style
import re
import inspect
init(autoreset=True)

class Logger():
    def __init__(self) -> None:
        pass

    def debugger(self, var):
        # Get the source code line where debugger() was called
        frame = inspect.currentframe().f_back
        line = inspect.getframeinfo(frame).code_context[0].strip()

        # Extract the variable name from inside the parentheses
        match = re.search(r'debugger\((.+)\)', line)
        var_name = match.group(1).strip() if match else "<?>"

        print(f"{Fore.RED}[DEBUG]{Style.RESET_ALL} {var_name} = {Fore.YELLOW}{repr(var)}{Style.RESET_ALL}")
