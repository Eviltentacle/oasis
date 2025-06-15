import sys
import time
import os

# Import all your existing scan modules
import scan_ip
import scan_domain
import scan_hash
import scan_url
#import scan_email

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_oasis_banner():
    banner = r"""
        ▄██████▄     ▄████████    ▄████████  ▄█     ▄████████ 
       ███    ███   ███    ███   ███    ███ ███    ███    ███ 
       ███    ███   ███    ███   ███    █▀  ███▌   ███    █▀  
       ███    ███   ███    ███   ███        ███▌   ███        
       ███    ███ ▀███████████ ▀███████████ ███▌ ▀███████████ 
       ███    ███   ███    ███          ███ ███           ███
       ███    ███   ███    ███    ▄█    ███ ███     ▄█    ███
       ▀██████▀    ███    █▀   ▄████████▀  █▀    ▄████████▀  
                                                           
           [  One America Security Intelligence Scanner   ]                                                 
                                                        """
    print(banner)
def show_menu():
    print_oasis_banner()
    print("Usage: python.exe main.py -o [output.file]")
    print("\n--- IOC Scanning Menu ---")
    print("1. Scan ALL IOCs")
    print("2. Scan IPs")
    print("3. Scan Domains")
    print("4. Scan URLs")
    print("5. Scan Hashes")
    #print("6. Scan Emails")
    print("0. Exit")
    print(" ") 
def run_selection(option):
    if option == "1":
        print("\n[+] Running all IOC scans...\n")
        scan_ip.main()
        scan_domain.main()
        scan_url.main()
        scan_hash.main()
    elif option == "2":
        print("\n[+] Running IP scan...\n")
        scan_ip.main()
    elif option == "3":
        print("\n[+] Running Domain scan...\n")
        scan_domain.main()
    elif option == "4":
        print("\n[+] Running URL scan...\n")
        scan_url.main()
    elif option == "5":
        print("\n[+] Running Hash scan...\n")
        scan_hash.main()
    #elif option == "6":
    #    print("\n[+] Running Email scan...\n")
    #    scan_email.main()
    elif option == "0":
        print("\n[+] Exiting...")
        sys.exit(0)
    else:
        print("[!] Invalid option. Please enter 0 to 5.")
    
def main():
    clear_screen()
    show_menu()
    while True:
        choice = input("Select an option (0-5): ").strip()
        run_selection(choice)
        time.sleep(1)

if __name__ == "__main__":

    main()
