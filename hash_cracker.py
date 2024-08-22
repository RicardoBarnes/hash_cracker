#!/usr/bin/env python3

import re
import os
import requests
import argparse
import concurrent.futures

def parse_args():
    parser = argparse.ArgumentParser(description="Hash Cracking Script")
    parser.add_argument('-s', help='Hash to crack', dest='hash')
    parser.add_argument('-f', help='File containing hashes', dest='file')
    parser.add_argument('-d', help='Directory containing files with hashes', dest='dir')
    parser.add_argument('-t', help='Number of threads', dest='threads', type=int, default=4)
    return parser.parse_args()

# Color and formatting codes
class Colors:
    END = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    WHITE = '\033[97m'
    D_GREEN = '\033[32m'
    YELLOW = '\033[93m'
    BACK = '\033[7;91m'
    RUN = '\033[97m[~]\033[0m'
    QUE = '\033[94m[?]\033[0m'
    BAD = '\033[91m[-]\033[0m'
    INFO = '\033[93m[!]\033[0m'
    GOOD = '\033[92m[+]\033[0m'

def print_banner():
    print (f'''{Colors.WHITE}_  _ ____ ____ _  _    ___  _  _ ____ ___ ____ ____
|__| |__| [__  |__|    |__] |  | [__   |  |___ |__/
|  | |  | ___] |  |    |__] |__| ___]  |  |___ |  \  {Colors.RED}v3.0{Colors.END}\n''')

# API Functions
def alpha(hashvalue, hashtype):
    return False

def beta(hashvalue, hashtype):
    try:
        response = requests.get(f'https://hashtoolkit.com/reverse-hash/?hash={hashvalue}')
        match = re.search(r'/generate-hash/\?text=(.*?)"', response.text)
        return match.group(1) if match else False
    except requests.RequestException as e:
        print(f"{Colors.BAD} Error connecting to hashtoolkit.com: {e}")
        return False

def gamma(hashvalue, hashtype):
    try:
        response = requests.get(f'https://www.nitrxgen.net/md5db/{hashvalue}', verify=False)
        return response.text if response.text else False
    except requests.RequestException as e:
        print(f"{Colors.BAD} Error connecting to nitrxgen.net: {e}")
        return False

def delta(hashvalue, hashtype):
    # This is a placeholder function, previously connected to hashcrack.com
    return False

def theta(hashvalue, hashtype):
    try:
        response = requests.get(f'https://md5decrypt.net/Api/api.php?hash={hashvalue}&hash_type={hashtype}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728')
        return response.text if response.text else False
    except requests.RequestException as e:
        print(f"{Colors.BAD} Error connecting to md5decrypt.net: {e}")
        return False

# Map of hash length to corresponding functions
HASH_FUNCTIONS = {
    32: [gamma, alpha, beta, theta, delta],
    40: [alpha, beta, theta, delta],
    64: [alpha, beta, theta],
    96: [alpha, beta, theta],
    128: [alpha, beta, theta],
}

def crack(hashvalue):
    hash_len = len(hashvalue)
    if hash_len in HASH_FUNCTIONS:
        if not args.file:
            print(f'{Colors.INFO} Hash function : {hash_len}-bit')
        for func in HASH_FUNCTIONS[hash_len]:
            result = func(hashvalue, hash_len)
            if result:
                return result
    else:
        if not args.file:
            print(f'{Colors.BAD} This hash type is not supported.')
    return False

result = {}

def threaded_crack(hashvalue):
    resp = crack(hashvalue)
    if resp:
        print(f'{Colors.GOOD} {hashvalue} : {resp}')
        result[hashvalue] = resp

def grep_hashes(directory):
    os.system(f'''grep -Pr "[a-f0-9]{{128}}|[a-f0-9]{{96}}|[a-f0-9]{{64}}|[a-f0-9]{{40}}|[a-f0-9]{{32}}" {directory} --exclude=\*.{{png,jpg,jpeg,mp3,mp4,zip,gz}} |
        grep -Po "[a-f0-9]{{128}}|[a-f0-9]{{96}}|[a-f0-9]{{64}}|[a-f0-9]{{40}}|[a-f0-9]{{32}}" >> {os.getcwd()}/{os.path.basename(directory)}.txt''')
    print(f'{Colors.INFO} Results saved in {os.path.basename(directory)}.txt')

def process_file(file):
    lines = []
    found = set()
    with open(file, 'r') as f:
        for line in f:
            lines.append(line.strip())
    for line in lines:
        matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
        found.update(matches)
    print(f'{Colors.INFO} Hashes found: {len(found)}')

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(threaded_crack, hashvalue) for hashvalue in found]
        for i, _ in enumerate(concurrent.futures.as_completed(futures)):
            if i + 1 == len(found) or (i + 1) % args.threads == 0:
                print(f'{Colors.INFO} Progress: {i + 1}/{len(found)}', end='\r')

    with open(f'cracked-{os.path.basename(file)}', 'w+') as f:
        for hashvalue, cracked in result.items():
            f.write(f'{hashvalue}:{cracked}\n')
    print(f'{Colors.INFO} Results saved in cracked-{os.path.basename(file)}')

def process_single_hash(hashvalue):
    result = crack(hashvalue)
    if result:
        print(result)
    else:
        print(f'{Colors.BAD} Hash was not found in any database.')

if __name__ == '__main__':
    args = parse_args()
    print_banner()

    if args.dir:
        try:
            grep_hashes(args.dir)
        except KeyboardInterrupt:
            print(f'{Colors.BAD} Process interrupted by user.')

    elif args.file:
        try:
            process_file(args.file)
        except KeyboardInterrupt:
            print(f'{Colors.BAD} Process interrupted by user.')

    elif args.hash:
        process_single_hash(args.hash)
    else:
        print(f'{Colors.INFO} Please provide a hash (-s), a file (-f), or a directory (-d) to proceed.')
