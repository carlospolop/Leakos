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


def get_repo_leaks(github_repo, github_token, debug):
    """Download github repo and search for leaks"""

    global ALL_LEAKS

    if debug:
        print(f"Checking for leaks in {github_repo.full_name}")
    
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
                url = f"https://github.com/{github_repo.full_name}/commit/{result['Commit']}"
                
                print(f"[+] Found: {result['Secret']} ({result['Description']}) in {url} with match {result['Match']}")
                
                semaph.acquire()
                ALL_LEAKS[result["Secret"]] = {
                    "name": result["Secret"],
                    "match": result["Match"],
                    "description": result["Description"],
                    "url": url
                }
                semaph.release()
    
    except Exception as e:
        print(e, file=sys.stderr)
    

def check_github(github_token, github_users_str, github_orgs, threads, debug):
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
            print(f"Checking org {org}")
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
    pool.starmap(get_repo_leaks, zip((repo for repo in github_repos), repeat(github_token), repeat(debug)))
    pool.close()


#########################
####### WEB LEAKS #######
#########################

def check_web(urls_file, stdin, threads, debug, generic_leak_in_web, no_exts):
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
    pool.starmap(get_web_leaks, zip((url for url in urls), repeat(debug), repeat(generic_leak_in_web), repeat(no_exts)))
    pool.close()


def get_web_leaks(url, debug, generic_leak_in_web, no_exts):
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
        json_name = id_generator()
        
        with open(f"{tmpdirname}/web_text", "w") as f:
            f.write(text)
        
        subprocess.call(["gitleaks", "detect", "-s", f"{tmpdirname}", "--no-git", "--report-format", "json", "--report-path", f"{tmpdirname}/{json_name}.json"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
        
        with open(f"{tmpdirname}/{json_name}.json", "r") as f:
            results = json.load(f)
        
        already_known = set()
        for result in results:
            if not result["Secret"] in already_known:
                if not generic_leak_in_web and "generic" in result['Description'].lower():
                    continue

                already_known.add(result["Secret"])
                
                print(f"[+] Found: {result['Secret']} ({result['Description']}) in {url} with match {result['Match']}")
                
                semaph.acquire()
                ALL_LEAKS[result["Secret"]] = {
                    "name": result["Secret"],
                    "match": result["Match"],
                    "description": result["Description"],
                    "url": url
                }
                semaph.release()


semaph = Semaphore(1)
ALL_LEAKS = {}

def main():
    parser = argparse.ArgumentParser(description='Search leaks in a github org or in web files')
    parser.add_argument('--github-token', help='Token to access github api (doesn\'t require any permission)')
    parser.add_argument('--github-orgs', help='Github orgs names (comma separated). Users will be searched also in the orgs.')
    parser.add_argument('--github-users', help='Github user names (comma separated)')
    parser.add_argument('--urls-file', help='Search leaks in responses from web urls. Path to file containing URLs to search for leaks.')
    parser.add_argument('--stdin-urls', help='Get URLs from stdin')
    parser.add_argument('--not-exts', help='Do not search for leaks in urls with these extensions (comma separated)', default="7z,tar,zip,avi,mp3,mp4,wav,wmf,wmv,dbf,doc,docm,docx,dot,dotm,dotx,odt,odp,pdf,pps,ppt,ppsm,ppsx,wps,xls,xlsm,xps,ico,eot,fnt,fon,otf,odttf,ttc,ttf,woff,woff2,woff3,bmp,emf,gif,jif,jfi,jfif,jpe,jpeg,jpg,png,psd,svgz,tif,tiff,webp")
    parser.add_argument('--json-file', help='Store json results in the indicated file')
    parser.add_argument('--threads', help='Number of threads to use', default=10)
    parser.add_argument('--debug', help='Debug', action='store_true')
    parser.add_argument('--generic-leak-in-web', help='Accept generic leaks in web (disabled by defult)', action='store_true', default=False)

    args = parser.parse_args()
    github_token = args.github_token
    github_orgs = args.github_orgs
    if github_orgs:
        github_orgs = github_orgs.split(",")
    github_users_str = args.github_users
    if github_users_str:
        github_users_str = github_users_str.split(",")
    urls_file = args.urls_file
    stdin_urls = args.stdin_urls
    out_json_file = args.json_file
    threads = args.threads
    debug = args.debug
    generic_leak_in_web = args.generic_leak_in_web
    no_exts = args.not_exts.split(",")

    if not github_orgs and not github_users_str and not urls_file and not stdin_urls:
        print("Nothing to do")
        return
    
    if urls_file and not exists(urls_file):
        print(f"File {urls_file} does not exist")
        exit(1)
    
    # Look in github
    if github_token:
        if github_orgs or github_users_str:
            check_github(github_token, github_users_str, github_orgs, threads, debug)
        else:
            print("No github orgs or users to check", file=sys.stderr)
            return
    
    # Look in web files
    if urls_file or stdin_urls:
        check_web(urls_file, stdin_urls, threads, debug, generic_leak_in_web, no_exts)
    

    if out_json_file:
        with open(out_json_file, "w") as f:
            json.dump(ALL_LEAKS, f)



if __name__ == "__main__":
    main()
