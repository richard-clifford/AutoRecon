from __future__ import print_function
from __future__ import with_statement
import requests
import argparse
import subprocess
import requests
import json
import sys
import threading
import time

"""
Todo: use threads

1. Get Passive Data (DNSdumpster, google, etc) - Done via amass; subfinder
2. Brute force the domains using a wordlist
    - done via amass active;
    - Maybe use massdns for this instead?
3. Run AltDNS with the found domains (may be tricky to extract useful info) & run through massdns
4. Run Wayback & urinteresting

"""

class Recon:

    found_domains = []
    top_domain = ''
    current_domain = ''
    config = {}
    output = ''

    def __init__(self, output):
        self.parse_config()
        self.output = output
        # self.options = options
        pass

    def __exit__(self, exception_type, exception_value, traceback):
        print("Hit __exit__")
        print(self.normalize_results())

    def start(self, domain):
        self.current_domain = domain
        threads = []
        threads.append(threading.Thread(target=self.do_amass).start().join())
        threads.append(threading.Thread(target=self.do_aquatone).start().join())
        threads.append(threading.Thread(target=self.do_crtsh).start().join())
        
        dead_count = 0
        while dead_count < len(threads):
            for t in threads:
                if not t.is_alive():
                    dead_count = dead_count + 1
                else: 
                    pass
        if dead_count == len(threads):
            self.do_dirsearch()
        pass

    def do_dirsearch(self):
        wordlist = self.config["settings"]["wordlist"]
        print("[*] Running Passive dirsearch for {0}".format(self.current_domain))
        dirsearch_call = subprocess.Popen([
            self.config["tools"]["dirsearch"], 
            '-e', self.config['settings']['dirsearch_extensions'], # Maybe pass in a argument 
            '-t', '100', # Threads
            '-r', # Recursive
            '-f', # Force extensions
            '-w', wordlist, #Wordlists
            '-b', # Use domain instead of IP
            '--simple-report', domain.replace(":", "_").replace('/', '') # Write the report
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        stdout,stderr = dirsearch_call.communicate()
        print(stdout)
        return stdout

    def parse_config(self):
        with open('config.json') as config_file:
            self.config = json.load(config_file)
        return self.config

    def do_crtsh(self):
        print("[*] Gathering crt.sh info for {0}".format(self.current_domain))
        url = 'https://crt.sh/?q=%25.{0}&output=json'.format(self.current_domain)
        r = requests.get(url)
        if r.status_code == 200:
            data = json.loads(r.text)
            for d in data:
                self.add_domain_to_found(d["name_value"])
        return True

    def do_shodan(self):
        self.config["shodan_key"]
        pass

    def do_amass(self, mode='passive'):
        if mode == 'passive':
            print("[*] Running Passive Amass for {0}".format(self.current_domain))
            amass_call = subprocess.Popen([
                self.config["tools"]["amass"], 
                'enum',
                '-d', self.current_domain, 
                '-passive',
                '-o', self.output
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        elif mode == 'active':
            print("[*] Running Active Amass for {0}".format(self.current_domain))
            amass_call = subprocess.Popen([
                self.config["tools"]["amass"], 
                'enum',
                '-d', self.current_domain, 
                '-active', 
                '-brute', 
                '-w', self.config["settings"]["dns_wordlist"], 
                '-ip', 
                '-src',
                '-o',
                self.output
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            # default to passive?
            self.do_amass(mode='passive')
        
        stdout,stderr = amass_call.communicate()
        results = stdout.decode().split("\n")
        for line in results:
            if len(line.strip()) == 0 or 'OWASP Amass' in line or '------------------------' in line or 'names discovered' in line:
                pass
            else:
                self.add_domain_to_found(line)
        return stdout

    def do_aquatone(self):
        print("[*] Running Aquatone for {0}".format(self.current_domain))
        domain = self.current_domain
        aquatone_call = subprocess.Popen([
            self.config["tools"]["aquatone"], 
            '-d', domain, 
            '-t', '100'
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout,stderr = aquatone_call.communicate()
        return stdout

    def do_meg(self):
        pass

    def extract_interesting_alts(self):
        pass

    def add_domain_to_found(self, domain):
        if domain not in self.found_domains:
            self.found_domains.append(domain)
            print("[+] Domain found: {0}".format(domain))
        return self.found_domains

    def normalize_results(self):
        print("YESS MATE")
        # Parse out the aquatone results
        with open(self.config["settings"]["aquatone_results"] + self.current_domain + '/hosts.json', 'r') as aquatone_results:
            for key, value in aquatone_results:
                self.add_domain_to_found(key)

        # # Write the data to the file                    
        with open(self.output, 'a') as out:
            out.write(self.found_domains)
        return self.found_domains

    def store_data(self):
        pass

    def get_subdomains(self):
        pass

    # Resolve domain to IP and add each uniq IP with the domain to a list
    def resolve_ips(self, domain):
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--domain', '-d', nargs='*', required=True, help='The domain to perform recon on')
    parser.add_argument('--threads', '-t', required=False, type=int, default=10, help='Number of threads')
    parser.add_argument('--output', '-o', required=False, default='autorecon_results_{0}'.format(int(time.time())) + '.txt', help='Output file')
    parser.add_argument('--ports', '-p', required=False, default=[80,443,445,22,21,25,8080,8000,8001,8081,3000], help='The ports to scan')
    parser.add_argument('--scan-type', '-s', required=False, default="passive", help='The ports to scan')
    args = parser.parse_args()
    
    threads = []
    domains = args.domain
    threads = []

    recon = Recon(output=args.output)

    # Do domain searching
    while len(threads) <= args.threads and len(domains) > 0:
        dom = domains.pop()
        threads.append(threading.Thread(target=recon.start, args=(dom,)).start())
