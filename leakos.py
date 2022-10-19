import argparse
import httpx
import json
import os
import random
import string
import subprocess
import sys
import tempfile

from github import Github
from itertools import repeat
from multiprocessing.pool import ThreadPool
from os.path import exists
from threading import Semaphore



#########################
##### GITHUB LEAKS ######
#########################

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""

    # from whichcraft import which
    from shutil import which

    return which(name) is not None

def id_generator(size=8, chars=string.ascii_uppercase + string.digits):
    """Generate random string"""

    return ''.join(random.choice(chars) for _ in range(size))


def get_repos_users_from_org(org_name, git_client):
    """Get all repos and users from a github org"""

    org = git_client.get_organization(org_name)
    org_users = []
    org_repos = []
    for member in org.get_members():
        org_users.append(member)
    for repo in org.get_repos():
        org_repos.append(repo)
    return org_users, org_repos


def get_repos_from_user(github_user):
    """Get all repos from a github user"""

    user_repos = []
    for repo in github_user.get_repos():
        user_repos.append(repo)
    return user_repos


def get_gitleaks_repo_leaks(github_repo, github_token, avoid_sources, debug):
    """Download github repo and search for leaks"""

    global ALL_LEAKS

    if debug:
        print(f"Gitleaks checking for leaks in {github_repo.full_name}")
    
    folder_name = id_generator()
    subprocess.call(["git", "clone", f'https://{github_token}@github.com/{github_repo.full_name}', f"/tmp/{folder_name}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
    subprocess.call(["gitleaks", "detect", "-s", f"/tmp/{folder_name}", "--report-format", "json", "--report-path", f"/tmp/{folder_name}.json"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
    subprocess.call(["rm", "-rf", f"/tmp/{folder_name}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))

    try:
        with open(f"/tmp/{folder_name}.json", "r") as f:
            results = json.load(f)
        
        subprocess.call(["rm", "-rf", f"/tmp/{folder_name}.json"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
        
        already_known = set()
        for result in results:
            if not result["Secret"] in already_known:
                already_known.add(result["Secret"])

                if len(result["Secret"]) > MAX_SECRET_LENGTH:
                    continue

                url = f"https://github.com/{github_repo.full_name}/commit/{result['Commit']}"

                # Remove tokens starting with "0x"
                if "generic" in result['Description'].lower() and result["Secret"].startswith("0x"):
                    continue

                if any(res.lower() in result['Description'].lower() for res in avoid_sources):
                    print(f"Avoiding {result['Description']}")
                    continue
                
                print(f"[+] Found: {result['Secret']} ({result['Description']}) in {url} with match {result['Match']}")
                
                semaph.acquire()
                if not result["Secret"] in ALL_LEAKS:
                    ALL_LEAKS[result["Secret"]] = {
                        "name": result["Secret"],
                        "match": result["Match"],
                        "description": result["Description"],
                        "url": url,
                        "verified": False,
                        "tool": "gitleaks"
                    }
                semaph.release()
    
    except Exception as e:
        print(e, file=sys.stderr)


def get_trufflehog_repo_leaks(github_repo, github_token, avoid_sources, debug, from_trufflehog_only_verified):

    global ALL_LEAKS

    if debug:
        print(f"Trufflehog checking for leaks in {github_repo.full_name}")
    
    already_known = set()

    # Get trufflehog results
    repo_url = f'https://github.com/{github_repo.full_name}'
    if not from_trufflehog_only_verified:
        p = subprocess.Popen(["trufflehog", "github", "--repo", repo_url, "--json", "--token", github_token, "--no-update"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(["trufflehog", "github", "--repo", repo_url, "--json", "--token", github_token, "--no-update", "--only-verified"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    if not output:
        return
    
    for line in output.splitlines():
        line_json = json.loads(line)
        if not line_json["Raw"] in already_known:
            if not line_json["Verified"] and any(res.lower() in line_json["DetectorName"].lower() for res in avoid_sources):
                    print(f"Avoiding {line_json['DetectorName']}")
                    continue

            already_known.add(line_json["Raw"])

            if len(line_json["Raw"]) > MAX_SECRET_LENGTH:
                continue
            
            url = f"{repo_url}/commit/{line_json['SourceMetadata']['Data']['Github']['commit']}"
            print(f"[+] Found by trufflehog: {line_json['Raw']} ({line_json['DetectorName']}) in {url}")

            semaph.acquire()
            if not line_json["Raw"] in ALL_LEAKS:
                ALL_LEAKS[line_json["Raw"]] = {
                    "name": line_json["Raw"],
                    "match": "",
                    "description": line_json["DetectorName"],
                    "url": url,
                    "verified": line_json["Verified"],
                    "tool": "trufflehog"
                }
            elif line_json["Verified"]: #Only overwrite if this is verified
                ALL_LEAKS[line_json["Raw"]] = {
                    "name": line_json["Raw"],
                    "match": "",
                    "description": line_json["DetectorName"],
                    "url": f"{repo_url}/commit/{repo_url['Github']['Commit']}",
                    "verified": line_json["Verified"],
                    "tool": "trufflehog"
                }
            semaph.release()
    

def check_github(github_token, github_users_str, github_orgs, threads, avoid_sources, debug, from_trufflehog_only_verified, only_verified):
    """Check github for leaks"""

    github_users = []
    github_repos = []

    if github_token:
        git_client = Github(github_token)
    
    # Get github users objs
    if github_users_str:
        for user in github_users_str:
            try:
                github_users.append(git_client.get_user(user))
            except Exception as e:
                print(e, file=sys.stderr)

    # Get users and repos from orgs
    if github_orgs:
        for org in github_orgs:
            print(f"Getting users and users repos from org {org}")
            try:
                org_users, org_repos = get_repos_users_from_org(org, git_client)
                github_users += org_users
                github_repos += org_repos
            except Exception as e:
                print(e, file=sys.stderr)
    
    # Get repos from all users
    if github_users:
        for user in github_users:
            user_repos = get_repos_from_user(user)
            github_repos += user_repos
    
    pool = ThreadPool(processes=threads)
    pool.starmap(get_trufflehog_repo_leaks, zip((repo for repo in github_repos), repeat(github_token), repeat(avoid_sources), repeat(debug), repeat(from_trufflehog_only_verified)))
    if not only_verified:
        pool.starmap(get_gitleaks_repo_leaks, zip((repo for repo in github_repos), repeat(github_token), repeat(avoid_sources), repeat(debug)))
    pool.close()


#########################
####### WEB LEAKS #######
#########################

def check_web(urls_file, stdin, threads, avoid_sources, debug, generic_leak_in_web, no_exts, from_trufflehog_only_verified, only_verified):
    """Check web for leaks"""

    # Read file
    if urls_file:
        with open(urls_file, "r") as f:
            urls = f.read().splitlines()
    # Or read from stdin
    elif stdin:
        for line in sys.stdin:
            urls.append(line)
    else:
        print("No urls or stdin provided", file=sys.stderr)
        return
    
    pool = ThreadPool(processes=threads)
    pool.starmap(get_web_leaks, zip((url for url in urls), repeat(avoid_sources), repeat(debug), repeat(generic_leak_in_web), repeat(no_exts), repeat(from_trufflehog_only_verified), repeat(only_verified)))
    pool.close()


def get_trufflehog_web_leaks(dirpath, url, avoid_sources, from_trufflehog_only_verified):
    """Use trufflehog to search for leaks in the downloaded we page"""

    already_known = set()

    # Get trufflehog results
    if not from_trufflehog_only_verified:
        p = subprocess.Popen(["trufflehog", "filesystem", "--directory", f"{dirpath}", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(["trufflehog", "filesystem", "--directory", f"{dirpath}", "--json", "--only-verified"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    if not output:
        return
    
    for line in output.splitlines():
        line_json = json.loads(line)
        if not line_json["Raw"] in already_known:
            if not line_json["Verified"] and any(res.lower() in line_json["DetectorName"].lower() for res in avoid_sources):
                print(f"Avoiding {line_json['DetectorName']}")
                continue

            already_known.add(line_json["Raw"])

            if len(line_json["Raw"]) > MAX_SECRET_LENGTH:
                continue
            
            print(f"[+] Found by trufflehog: {line_json['Raw']} ({line_json['DetectorName']}) in {url}")

            semaph.acquire()
            if not line_json["Raw"] in ALL_LEAKS:
                ALL_LEAKS[line_json["Raw"]] = {
                    "name": line_json["Raw"],
                    "match": "",
                    "description": line_json["DetectorName"],
                    "url": url,
                    "verified": line_json["Verified"],
                    "tool": "trufflehog"
                }
            elif line_json["Verified"]: #Only overwrite if this is verified
                ALL_LEAKS[line_json["Raw"]] = {
                    "name": line_json["Raw"],
                    "match": "",
                    "description": line_json["DetectorName"],
                    "url": url,
                    "verified": line_json["Verified"],
                    "tool": "trufflehog"
                }
            semaph.release()


def get_gitleaks_web_leaks(dirpath, url, avoid_sources, generic_leak_in_web):
    """Use trufflehog to search for leaks in the downloaded we page"""
    
    global ALL_LEAKS
    already_known = set()
    json_name = id_generator()

    # Get gitleaks results
    subprocess.call(["gitleaks", "detect", "-s", f"{dirpath}", "--no-git", "--report-format", "json", "--report-path", f"{tmpdirname}/{json_name}.json"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))

    with open(f"{dirpath}/{json_name}.json", "r") as f:
        results = json.load(f)
    
    for result in results:
        if not result["Secret"] in already_known:
            if not generic_leak_in_web and "generic" in result['Description'].lower():
                continue
            
            if any(res.lower() in result['Description'].lower() for res in avoid_sources):
                print(f"Avoiding {result['Description']}")
                continue

            already_known.add(result["Secret"])

            if len(result["Secret"]) > MAX_SECRET_LENGTH:
                continue
            
            print(f"[+] Found by gitleaks: {result['Secret']} ({result['Description']}) in {url} with match {result['Match']}")
            
            semaph.acquire()
            if not result["Secret"] in ALL_LEAKS:
                ALL_LEAKS[result["Secret"]] = {
                    "name": result["Secret"],
                    "match": result["Match"],
                    "description": result["Description"],
                    "url": url,
                    "verified": False,
                    "tool": "gitleaks"
                }
            semaph.release()


def get_web_leaks(url, avoid_sources, debug, generic_leak_in_web, no_exts, from_trufflehog_only_verified, only_verified):
    """Check url for leaks"""

    global ALL_LEAKS

    if any(ext in url for ext in no_exts):
        return

    if debug:
        print(f"Checking for leaks in {url}")

    try:
        r = httpx.get(url)
    except Exception as e:
        print(f"{url}: {e}", file=sys.stderr)
        return
    
    text = r.text

    with tempfile.TemporaryDirectory() as tmpdirname:
        with open(f"{tmpdirname}/web_text", "w") as f:
            f.write(text)
        
        get_trufflehog_web_leaks(tmpdirname, url, avoid_sources, from_trufflehog_only_verified)
        if not only_verified:
            get_gitleaks_web_leaks(tmpdirname, url, avoid_sources, generic_leak_in_web)







### MAIN ###

semaph = Semaphore(1)
ALL_LEAKS = {}
MAX_SECRET_LENGTH = 1500

def main():
    global MAX_SECRET_LENGTH
    parser = argparse.ArgumentParser(description='Search leaks in a github org or in the responses of urls')
    parser.add_argument('--github-token', help='Token to access github api (doesn\'t require any permission)')
    parser.add_argument('--github-orgs', help='Github orgs names (comma separated). Users will be searched also in the orgs.')
    parser.add_argument('--github-orgs-file', help='Github orgs names from file')
    parser.add_argument('--github-users', help='Github user names (comma separated)')
    parser.add_argument('--github-users-file', help='Github users names from file')
    parser.add_argument('--urls-file', help='Search leaks in responses from web urls. Path to file containing URLs to search for leaks.')
    parser.add_argument('--stdin-urls', help='Get URLs from stdin')
    parser.add_argument('--not-exts', help='Do not search for leaks in urls with these extensions (comma separated)', default="7z,tar,zip,avi,mp3,mp4,wav,wmf,wmv,dbf,doc,docm,docx,dot,dotm,dotx,odt,odp,pdf,pps,ppt,ppsm,ppsx,wps,xls,xlsm,xps,ico,eot,fnt,fon,otf,odttf,ttc,ttf,woff,woff2,woff3,bmp,emf,gif,jif,jfi,jfif,jpe,jpeg,jpg,png,psd,svgz,tif,tiff,webp")
    parser.add_argument('--json-file', help='Store json results in the indicated file')
    parser.add_argument('--threads', help='Number of threads to use', default=10)
    parser.add_argument('--debug', help='Debug', action='store_true')
    parser.add_argument('--generic-leak-in-web', help='Accept generic leaks in web (disabled by defult)', action='store_true', default=False)
    parser.add_argument('--from-trufflehog-only-verified', help='From trufflehog get only verified leaks', action='store_true', default=False)
    parser.add_argument('--only-verified', help='Get only verified leaks (only use trufflehog)', action='store_true', default=False)
    parser.add_argument('--avoid-sources', help='Lower case comma separated list of sources from trufflehog and gitleaks to avoid')
    parser.add_argument('--max-secret-length', help='Max length of valid secrets', default=1500)

    args = parser.parse_args()
    github_token = args.github_token
    github_orgs = args.github_orgs
    if github_orgs:
        github_orgs = github_orgs.split(",")
    github_orgs_file = args.github_orgs_file
    github_users_str = args.github_users
    if github_users_str:
        github_users_str = github_users_str.split(",")
    github_users_file = args.github_users_file
    urls_file = args.urls_file
    stdin_urls = args.stdin_urls
    out_json_file = args.json_file
    threads = int(args.threads)
    debug = args.debug
    generic_leak_in_web = args.generic_leak_in_web
    no_exts = args.not_exts.split(",")
    from_trufflehog_only_verified = args.from_trufflehog_only_verified
    only_verified = args.only_verified
    avoid_sources = args.avoid_sources
    if avoid_sources:
        avoid_sources = avoid_sources.split(",")
    max_secret_length = int(args.max_secret_length)
    MAX_SECRET_LENGTH = max_secret_length

    if not is_tool("gitleaks"):
        print("gitleaks not found. Please install it in PATH", file=sys.stderr)
        exit(1)
    
    if not is_tool("trufflehog"):
        print("trufflehog not found. Please install it in PATH", file=sys.stderr)
        exit(1)

    if not github_orgs and not github_users_str and not github_orgs_file and not github_users_file and not urls_file and not stdin_urls:
        print("Nothing to do")
        return
    
    if urls_file and not exists(urls_file):
        print(f"File {urls_file} does not exist")
        exit(1)
    
    if github_orgs_file:
        if not exists(github_orgs_file):
            print(f"File {github_orgs_file} does not exist")
            exit(1)
        else:
            github_orgs = open(github_orgs_file, "r").read().splitlines()
    
    if github_users_file:
        if not exists(github_users_file):
            print(f"File {github_users_file} does not exist")
            exit(1)
        else:
            github_users_str = open(github_users_file, "r").read().splitlines()
    
    # Look in github
    if github_token:
        if github_orgs or github_users_str:
            check_github(github_token, github_users_str, github_orgs, threads, avoid_sources, debug, from_trufflehog_only_verified, only_verified)
        else:
            print("No github orgs or users to check", file=sys.stderr)
            return
    
    # Look in web files
    if urls_file or stdin_urls:
        check_web(urls_file, stdin_urls, threads, avoid_sources, debug, generic_leak_in_web, no_exts, from_trufflehog_only_verified, only_verified)
    

    if out_json_file:
        with open(out_json_file, "w") as f:
            json.dump(ALL_LEAKS, f)



if __name__ == "__main__":
    main()
