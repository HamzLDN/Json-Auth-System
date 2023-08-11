import colorama, datetime

colorama.init(autoreset=True)

''' Use PrintDebug function only when the code is going well '''
def PrintDebug(*message:str, verbose) -> None:
    if verbose: print("[+] {} {}".format(colorama.Fore.GREEN + datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S.%f]"), colorama.Fore.WHITE + " ".join(message)))

''' Use PrintError function only when the code is going bad/unexpected '''
def PrintError(*message:str, verbose) -> None:
    if verbose: print("[-] {} {} -> ERROR: {}".format(colorama.Fore.RED + datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S.%f]"), colorama.Fore.WHITE, message))