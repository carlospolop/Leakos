import argparse
import httpx
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import time
import requests

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


def get_repos_users_from_org(org_name, git_client, add_org_repos_forks, debug):
    """Get all repos and users from a github org"""

    org = git_client.get_organization(org_name)
    org_users = []
    org_repos = []
    for member in org.get_members():
        if debug:
            print("[+] Member: " + str(member))
        org_users.append(member)
    for repo in org.get_repos():
        if not repo.fork or add_org_repos_forks:
            if debug:
                print("[+] Repo: " + str(repo.full_name))
            org_repos.append(repo)
    
    return org_users, org_repos


def get_repos_from_user(github_user, add_user_repos_forks):
    """Get all repos from a github user"""

    user_repos = []
    for repo in github_user.get_repos():
        if not repo.fork or add_user_repos_forks:
            user_repos.append(repo)
    return user_repos


def get_gitleaks_repo_leaks(github_repo, github_token, avoid_sources, debug, repo_path=None):
    """Download github repo and search for leaks"""

    global ALL_LEAKS, TIMEOUT

    start_time = time.time()
    if debug:
        print(f"Gitleaks checking for leaks in {github_repo.full_name}")
    
    folder_name = id_generator()
    cleanup_needed = repo_path is None
    
    try:
        if repo_path is None:
            subprocess.run(["git", "clone", f'https://{github_token}@github.com/{github_repo.full_name}', f"/tmp/{folder_name}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
            repo_path = f"/tmp/{folder_name}"
        
        subprocess.run(["gitleaks", "detect", "-s", repo_path, "--report-format", "json", "--report-path", f"/tmp/{folder_name}.json"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
        
        if cleanup_needed:
            subprocess.run(["rm", "-rf", repo_path], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
    except Exception as e:
        print(f"Gitleaks repo: {github_repo.full_name} , error: {e}", file=sys.stderr)
        return

    if debug:
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Gitleaks checked {github_repo.full_name} in {execution_time}s")

    try:
        with open(f"/tmp/{folder_name}.json", "r") as f:
            results = json.load(f)
        
        subprocess.call(["rm", "-rf", f"/tmp/{folder_name}.json"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
        
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
                
                print(f"[+] Gitleaks found: {result['Secret']} ({result['Description']}) in {url} with match {result['Match']}")
                
                semaph.acquire()
                try:
                    if not result["Secret"] in ALL_LEAKS:
                        ALL_LEAKS[result["Secret"]] = {
                            "name": result["Secret"],
                            "match": result["Match"],
                            "description": result["Description"],
                            "url": url,
                            "verified": False,
                            "tool": "gitleaks"
                        }
                finally:
                    semaph.release()
    
    except Exception as e:
        print(e, file=sys.stderr)


def get_rex_repo_leaks(github_repo, github_token, rex_regex_path, rex_all_regexes, avoid_sources, debug):
    """Download github repo and search for leaks"""

    global ALL_LEAKS, TIMEOUT

    start_time = time.time()
    if debug:
        print(f"Rex checking for leaks in {github_repo.full_name}")
    
    try:
        if rex_all_regexes:
            p = subprocess.run(["Rex", "-g", f'https://github.com/{github_repo.full_name}', "-r", rex_regex_path, "-t", github_token], stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'), timeout=300)
        else:
            p = subprocess.run(["Rex", "-g", f'https://github.com/{github_repo.full_name}', "-r", rex_regex_path, "-t", github_token, "-c"], stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'), timeout=300)
        results = p.stdout.decode('utf-8')
    except Exception as e:
        print(f"Rex repo: {github_repo.full_name} , error: {e}", file=sys.stderr)
        return

    if debug:
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Rex checked {github_repo.full_name} in {execution_time}s")

    try:        
        already_known = set()
        for result in results.splitlines():
            result = json.loads(result)
            if not result["match"] in already_known:
                already_known.add(result["match"])

                if len(result["match"]) > MAX_SECRET_LENGTH:
                    continue
                
                url = f"https://github.com/{github_repo.full_name}"

                # Remove tokens starting with "0x"
                if result["match"].startswith("0x"):
                    continue

                if any(res.lower() in result['regexName'].lower() for res in avoid_sources):
                    print(f"Avoiding {result['regexName']}")
                    continue
                
                print(f"[+] Rex found: {result['match']} ({result['regexName']})")
                
                semaph.acquire()
                try:
                    if not result["match"] in ALL_LEAKS:
                        ALL_LEAKS[result["match"]] = {
                            "name": result["regexName"],
                            "match": result["match"],
                            "description": result["regex"],
                            "url": url,
                            "verified": False,
                            "tool": "Rex"
                        }
                finally:
                    semaph.release()
    
    except Exception as e:
        print(e, file=sys.stderr)


def get_noseyparker_repo_leaks(github_repo, github_token, avoid_sources, debug, repo_path=None):
    """Use noseyparker to search for leaks in GitHub repo"""

    global ALL_LEAKS, TIMEOUT

    start_time = time.time()
    if debug:
        print(f"Noseyparker checking for leaks in {github_repo.full_name}")
    
    folder_name = id_generator()
    cleanup_needed = repo_path is None
    
    try:
        if repo_path is None:
            subprocess.run(["git", "clone", f'https://{github_token}@github.com/{github_repo.full_name}', f"/tmp/{folder_name}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
            repo_path = f"/tmp/{folder_name}"
        
        subprocess.run(["noseyparker", "scan", "--datastore", f"/tmp/{folder_name}.np", repo_path], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
        result = subprocess.run(["noseyparker", "report", "--datastore", f"/tmp/{folder_name}.np", "--format", "json"], stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
        subprocess.run(["rm", "-rf", f"/tmp/{folder_name}.np"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
        
        if cleanup_needed:
            subprocess.run(["rm", "-rf", repo_path], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
    except Exception as e:
        print(f"Noseyparker repo: {github_repo.full_name} , error: {e}", file=sys.stderr)
        return

    if debug:
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Noseyparker checked {github_repo.full_name} in {execution_time}s")

    try:
        results = json.loads(result.stdout.decode('utf-8'))
        
        already_known = set()
        for finding in results:
            for match in finding.get('matches', []):
                secret = match['snippet']['matching']
                if not secret in already_known:
                    already_known.add(secret)

                    if len(secret) > MAX_SECRET_LENGTH:
                        continue

                    url = f"https://github.com/{github_repo.full_name}"

                    if any(res.lower() in finding['rule_name'].lower() for res in avoid_sources):
                        print(f"Avoiding {finding['rule_name']}")
                        continue
                    
                    print(f"[+] Noseyparker found: {secret} ({finding['rule_name']}) in {url}")
                    
                    semaph.acquire()
                    try:
                        if not secret in ALL_LEAKS:
                            ALL_LEAKS[secret] = {
                                "name": secret,
                                "match": secret,
                                "description": finding['rule_name'],
                                "url": url,
                                "verified": False,
                                "tool": "noseyparker"
                            }
                    finally:
                        semaph.release()
    
    except Exception as e:
        print(e, file=sys.stderr)


def get_ggshield_repo_leaks(github_repo, github_token, avoid_sources, debug, repo_path=None):
    """Use ggshield to search for leaks in GitHub repo"""

    global ALL_LEAKS, TIMEOUT

    start_time = time.time()
    if debug:
        print(f"GGShield checking for leaks in {github_repo.full_name}")
    
    folder_name = id_generator()
    cleanup_needed = repo_path is None
    
    try:
        if repo_path is None:
            subprocess.run(["git", "clone", f'https://{github_token}@github.com/{github_repo.full_name}', f"/tmp/{folder_name}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
            repo_path = f"/tmp/{folder_name}"
        
        result = subprocess.run(["ggshield", "secret", "scan", "repo", repo_path, "--recursive", "--json"], stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'), timeout=TIMEOUT, env={**os.environ, "GITGUARDIAN_API_KEY": ""})
        
        if cleanup_needed:
            subprocess.run(["rm", "-rf", repo_path], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
    except Exception as e:
        print(f"GGShield repo: {github_repo.full_name} , error: {e}", file=sys.stderr)
        return

    if debug:
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"GGShield checked {github_repo.full_name} in {execution_time}s")

    try:
        output = result.stdout.decode('utf-8')
        if not output or output.strip() == "":
            return
            
        results = json.loads(output)
        
        already_known = set()
        # GGShield has a complex JSON structure, need to parse it
        for scan_result in results.get('scans', []):
            for entity in scan_result.get('entities_with_incidents', []):
                for incident in entity.get('incidents', []):
                    for occurrence in incident.get('occurrences', []):
                        secret = occurrence.get('match', '')
                        if not secret in already_known and secret:
                            already_known.add(secret)

                            if len(secret) > MAX_SECRET_LENGTH:
                                continue

                            url = f"https://github.com/{github_repo.full_name}"
                            detector_name = incident.get('type', 'Unknown')

                            if any(res.lower() in detector_name.lower() for res in avoid_sources):
                                print(f"Avoiding {detector_name}")
                                continue
                            
                            print(f"[+] GGShield found: {secret} ({detector_name}) in {url}")
                            
                            semaph.acquire()
                            try:
                                if not secret in ALL_LEAKS:
                                    ALL_LEAKS[secret] = {
                                        "name": secret,
                                        "match": secret,
                                        "description": detector_name,
                                        "url": url,
                                        "verified": False,
                                        "tool": "ggshield"
                                    }
                            finally:
                                semaph.release()
    
    except Exception as e:
        print(f"GGShield parsing error: {e}", file=sys.stderr)


def get_kingfisher_repo_leaks(github_repo, github_token, avoid_sources, debug, repo_path=None):
    """Use kingfisher to search for leaks in GitHub repo"""

    global ALL_LEAKS, TIMEOUT

    start_time = time.time()
    if debug:
        print(f"Kingfisher checking for leaks in {github_repo.full_name}")
    
    folder_name = id_generator()
    cleanup_needed = repo_path is None
    
    try:
        if repo_path is None:
            subprocess.run(["git", "clone", f'https://{github_token}@github.com/{github_repo.full_name}', f"/tmp/{folder_name}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
            repo_path = f"/tmp/{folder_name}"
        
        result = subprocess.run(["kingfisher", "scan", repo_path, "--format", "jsonl", "--no-validate", "--git-history", "full"], stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
        
        if cleanup_needed:
            subprocess.run(["rm", "-rf", repo_path], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
    except Exception as e:
        print(f"Kingfisher repo: {github_repo.full_name} , error: {e}", file=sys.stderr)
        return

    if debug:
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Kingfisher checked {github_repo.full_name} in {execution_time}s")

    try:
        output = result.stdout.decode('utf-8')
        if not output or output.strip() == "":
            return
            
        already_known = set()
        # Kingfisher JSONL: one finding per line, last line is summary
        for line in output.strip().split('\n'):
            if not line.startswith('{'):
                continue
            
            try:
                data = json.loads(line)
                # Skip the summary line (doesn't have 'rule' key)
                if 'rule' not in data:
                    continue
                    
                secret = data.get('finding', {}).get('snippet', '')
                if not secret or secret in already_known:
                    continue
                    
                already_known.add(secret)

                if len(secret) > MAX_SECRET_LENGTH:
                    continue

                url = f"https://github.com/{github_repo.full_name}"
                rule_name = data.get('rule', {}).get('name', 'Unknown')

                if any(res.lower() in rule_name.lower() for res in avoid_sources):
                    print(f"Avoiding {rule_name}")
                    continue
                
                print(f"[+] Kingfisher found: {secret} ({rule_name}) in {url}")
                
                semaph.acquire()
                try:
                    if not secret in ALL_LEAKS:
                        ALL_LEAKS[secret] = {
                            "name": secret,
                            "match": secret,
                            "description": rule_name,
                            "url": url,
                            "verified": data.get('finding', {}).get('validation', {}).get('status', '') == 'Valid',
                            "tool": "kingfisher"
                        }
                finally:
                    semaph.release()
            except json.JSONDecodeError:
                continue
    
    except Exception as e:
        print(f"Kingfisher parsing error: {e}", file=sys.stderr)


def get_trufflehog_repo_leaks(github_repo, github_token, avoid_sources, debug, from_trufflehog_only_verified):

    global ALL_LEAKS, TIMEOUT

    start_time = time.time()
    if debug:
        print(f"Trufflehog checking for leaks in {github_repo.full_name}")
    
    already_known = set()

    # Get trufflehog results
    repo_url = f'https://github.com/{github_repo.full_name}'
    
    try:
        if not from_trufflehog_only_verified:
            result = subprocess.run(["trufflehog", "github", "--repo", repo_url, "--json", "--token", github_token, "--no-update"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
        else:
            result = subprocess.run(["trufflehog", "github", "--repo", repo_url, "--json", "--token", github_token, "--no-update", "--only-verified"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
        output = result.stdout.decode('utf-8')
        err = result.stderr.decode('utf-8')
    except Exception as e:
        print(f"Trufflehog repo: {repo_url} , error: {e}", file=sys.stderr)
        return

    if debug:
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Trufflehog checked {github_repo.full_name} in {execution_time}s")

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
            print(f"[+] Trufflehog found: {line_json['Raw']} ({line_json['DetectorName']}) in {url}")

            semaph.acquire()
            try:
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
                    try:
                        ALL_LEAKS[line_json["Raw"]] = {
                            "name": line_json["Raw"],
                            "match": "",
                            "description": line_json["DetectorName"],
                            "url": f"{repo_url}/commit/{line_json['SourceMetadata']['Data']['Github']['commit']}",
                            "verified": line_json["Verified"],
                            "tool": "trufflehog"
                        }
                    except (KeyError, TypeError):
                        pass
            finally:
                semaph.release()


def scan_repo_with_all_tools(github_repo, github_token, avoid_sources, debug, from_trufflehog_only_verified, only_verified, not_gitleaks, not_trufflehog, not_rex, rex_regex_path, rex_all_regexes, not_noseyparker, not_ggshield, not_kingfisher):
    """Clone repo once and scan with all enabled tools in parallel"""
    
    global TIMEOUT, MAX_TIMEOUT, START_TIME
    
    # Check if we've exceeded max timeout before starting
    if MAX_TIMEOUT > 0 and (time.time() - START_TIME) >= MAX_TIMEOUT:
        print(f"[!] Maximum timeout of {MAX_TIMEOUT}s reached. Skipping repo {github_repo.full_name}", file=sys.stderr)
        return
    
    # Clone repo once for all tools that need it
    folder_name = id_generator()
    repo_path = f"/tmp/{folder_name}"
    
    try:
        subprocess.run(["git", "clone", f'https://{github_token}@github.com/{github_repo.full_name}', repo_path], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
    except Exception as e:
        print(f"Failed to clone repo {github_repo.full_name}: {e}", file=sys.stderr)
        return
    
    # Run all tools in parallel using threads
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    futures = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        # Trufflehog doesn't need cloned repo (uses GitHub API)
        if not not_trufflehog:
            futures.append(executor.submit(get_trufflehog_repo_leaks, github_repo, github_token, avoid_sources, debug, from_trufflehog_only_verified))
        
        # Tools that use the cloned repo
        if not only_verified and not not_gitleaks:
            futures.append(executor.submit(get_gitleaks_repo_leaks, github_repo, github_token, avoid_sources, debug, repo_path))
        
        if not only_verified and not not_rex:
            futures.append(executor.submit(get_rex_repo_leaks, github_repo, github_token, rex_regex_path, rex_all_regexes, avoid_sources, debug))
        
        if not only_verified and not not_noseyparker:
            futures.append(executor.submit(get_noseyparker_repo_leaks, github_repo, github_token, avoid_sources, debug, repo_path))
        
        if not only_verified and not not_ggshield:
            futures.append(executor.submit(get_ggshield_repo_leaks, github_repo, github_token, avoid_sources, debug, repo_path))
        
        if not only_verified and not not_kingfisher:
            futures.append(executor.submit(get_kingfisher_repo_leaks, github_repo, github_token, avoid_sources, debug, repo_path))
        
        # Wait for all tools to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Tool execution error for {github_repo.full_name}: {e}", file=sys.stderr)
    
    # Clean up cloned repo
    try:
        subprocess.run(["rm", "-rf", repo_path], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
    except Exception as e:
        print(f"Failed to cleanup {repo_path}: {e}", file=sys.stderr)
    

def check_github(github_token, github_users_str, github_orgs, github_repos, threads, avoid_sources, debug, from_trufflehog_only_verified, only_verified, add_org_repos_forks, add_user_repos_forks, max_repos, not_gitleaks, not_trufflehog, not_rex, rex_regex_path, rex_all_regexes, not_noseyparker, not_ggshield, not_kingfisher):
    """Check github for leaks"""

    github_users = []

    from github import Auth
    auth = Auth.Token(github_token)
    git_client = Github(auth=auth)
    
    # Get github repos objs
    if github_repos:
        github_repos_temp = []
        for repo in github_repos:
            try:
                github_repos_temp.append(git_client.get_repo(repo))
            except Exception as e:
                print(f"Continuing without checking repo {repo}: {e}", file=sys.stderr)
        github_repos = github_repos_temp
    else:
        github_repos = []
    
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
                org_users, org_repos = get_repos_users_from_org(org, git_client, add_org_repos_forks, debug)
                github_users += org_users
                github_repos += org_repos
            except Exception as e:
                print(e, file=sys.stderr)
    
    # Get repos from all users
    if github_users:
        for user in github_users:
            user_repos = get_repos_from_user(user, add_user_repos_forks)
            github_repos += user_repos
    
    # Limit number of repos if specified
    original_count = len(github_repos)
    if max_repos and len(github_repos) > max_repos:
        github_repos = github_repos[:max_repos]
        print(f"Limiting to {max_repos} repos out of {original_count} total repos found")
    
    # NEW: Scan each repo with all tools in parallel
    pool = ThreadPool(processes=threads)
    
    # Process repos one by one, checking timeout between each
    for repo in github_repos:
        # Check if we've exceeded max timeout
        if MAX_TIMEOUT > 0 and (time.time() - START_TIME) >= MAX_TIMEOUT:
            print(f"[!] Maximum timeout of {MAX_TIMEOUT}s reached after scanning some repos. Stopping and returning results.", file=sys.stderr)
            break
        
        # Scan this repo
        pool.apply(scan_repo_with_all_tools, args=(
            repo,
            github_token,
            avoid_sources,
            debug,
            from_trufflehog_only_verified,
            only_verified,
            not_gitleaks,
            not_trufflehog,
            not_rex,
            rex_regex_path,
            rex_all_regexes,
            not_noseyparker,
            not_ggshield,
            not_kingfisher
        ))

    pool.close()


#########################
####### WEB LEAKS #######
#########################

def check_web(urls_file, stdin, threads, avoid_sources, debug, generic_leak_in_web, no_exts, from_trufflehog_only_verified, only_verified, max_urls, not_gitleaks, not_trufflehog, not_rex, rex_regex_path, rex_all_regexes):
    """Check web for leaks"""

    urls = []
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
    
    # Limit urls
    if max_urls:
        urls = urls[:max_urls]
    
    pool = ThreadPool(processes=threads)
    
    # Process URLs one by one, checking timeout between each
    for url in urls:
        # Check if we've exceeded max timeout
        if MAX_TIMEOUT > 0 and (time.time() - START_TIME) >= MAX_TIMEOUT:
            print(f"[!] Maximum timeout of {MAX_TIMEOUT}s reached after scanning some URLs. Stopping and returning results.", file=sys.stderr)
            break
        
        # Scan this URL
        pool.apply(get_web_leaks, args=(
            url,
            avoid_sources,
            debug,
            generic_leak_in_web,
            no_exts,
            from_trufflehog_only_verified,
            only_verified,
            not_gitleaks,
            not_trufflehog,
            not_rex,
            rex_regex_path,
            rex_all_regexes
        ))
    
    pool.close()


def get_trufflehog_web_leaks(dirpath, url, avoid_sources, from_trufflehog_only_verified):
    """Use trufflehog to search for leaks in the downloaded we page"""

    global ALL_LEAKS, GENERIC_ERRORS, MAX_GENERIC_ERRORS, TIMEOUT
    try:
        already_known = set()

        # Get trufflehog results
        try:
            if not from_trufflehog_only_verified:
                result = subprocess.run(["trufflehog", "filesystem", "--directory", f"{dirpath}", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
            else:
                result = subprocess.run(["trufflehog", "filesystem", "--directory", f"{dirpath}", "--json", "--only-verified"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
        except subprocess.TimeoutExpired as e:
            print(f"repo: {dirpath} , error: {e}", file=sys.stderr)
            return

        output = result.stdout.decode('utf-8')
        err = result.stderr.decode('utf-8')
        
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
    
    except Exception as e:
        if GENERIC_ERRORS < MAX_GENERIC_ERRORS:
            GENERIC_ERRORS += 1
            print(e, file=sys.stderr)


def get_gitleaks_web_leaks(dirpath, url, avoid_sources, generic_leak_in_web):
    """Use gitleaks to search for leaks in the downloaded web page"""
    
    global ALL_LEAKS, GENERIC_ERRORS, MAX_GENERIC_ERRORS, TIMEOUT
    try:
        already_known = set()
        json_name = id_generator()

        # Get gitleaks results
        try:
            subprocess.run(["gitleaks", "detect", "-s", f"{dirpath}", "--no-git", "--report-format", "json", "--report-path", f"{dirpath}/{json_name}.json"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"Timeout for {url}", file=sys.stderr)
            return

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
    
    except Exception as e:
        if GENERIC_ERRORS < MAX_GENERIC_ERRORS:
            GENERIC_ERRORS += 1
            print(e, file=sys.stderr)


def get_rex_web_leaks(dirpath, url, avoid_sources, rex_regex_path, rex_all_regexes):
    """Use Rex to search for leaks in the downloaded web page"""
    
    global ALL_LEAKS, GENERIC_ERRORS, MAX_GENERIC_ERRORS, TIMEOUT
    try:
        already_known = set()

        # Get gitleaks results
        try:
            if rex_all_regexes:
                p = subprocess.run(["Rex", "-d", f"{dirpath}", "-r", rex_regex_path], stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
            else:
                p = subprocess.run(["Rex", "-d", f"{dirpath}", "-r", rex_regex_path, "-c"], stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'), timeout=TIMEOUT)
            results = p.stdout.decode('utf-8')
        except subprocess.TimeoutExpired:
            print(f"Timeout for {url}", file=sys.stderr)
            return

        for result in results.splitlines():
            result = json.loads(result)
            if not result["match"] in already_known:
                if any(res.lower() in result['regexName'].lower() for res in avoid_sources):
                    print(f"Avoiding {result['regexName']}")
                    continue

                already_known.add(result["match"])

                if len(result["match"]) > MAX_SECRET_LENGTH:
                    continue
                
                print(f"[+] Found by Rex: {result['match']} ({result['regexName']}) in {url}")
                
                semaph.acquire()
                if not result["match"] in ALL_LEAKS:
                    ALL_LEAKS[result["match"]] = {
                        "name": result["regexName"],
                        "match": result["match"],
                        "description": result["regex"],
                        "url": url,
                        "verified": False,
                        "tool": "Rex"
                    }
                semaph.release()
    
    except Exception as e:
        if GENERIC_ERRORS < MAX_GENERIC_ERRORS:
            GENERIC_ERRORS += 1
            print(e, file=sys.stderr)


def get_web_leaks(url, avoid_sources, debug, generic_leak_in_web, no_exts, from_trufflehog_only_verified, only_verified, not_gitleaks, not_trufflehog, not_rex, rex_regex_path, rex_all_regexes):
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
        
        if not not_trufflehog:
            get_trufflehog_web_leaks(tmpdirname, url, avoid_sources, from_trufflehog_only_verified)
        
        if not only_verified and not not_gitleaks:
            get_gitleaks_web_leaks(tmpdirname, url, avoid_sources, generic_leak_in_web)
        
        if not only_verified and not not_rex:
            get_rex_web_leaks(tmpdirname, url, avoid_sources, rex_regex_path, rex_all_regexes)







### MAIN ###

semaph = Semaphore(1)
ALL_LEAKS = {}
MAX_SECRET_LENGTH = 1500
GENERIC_ERRORS = 0
MAX_GENERIC_ERRORS = 5
TIMEOUT = 300
MAX_TIMEOUT = 0
START_TIME = 0

def main():
    global MAX_SECRET_LENGTH, MAX_TIMEOUT, START_TIME
    START_TIME = time.time()
    parser = argparse.ArgumentParser(description='Search leaks in a github org or in the responses of urls')
    parser.add_argument('--github-token', help='Token to access github api (doesn\'t require any permission)')
    parser.add_argument('--github-orgs', help='Github orgs names (comma separated). Users will be searched also in the orgs.')
    parser.add_argument('--github-orgs-file', help='Github orgs names from file')
    parser.add_argument('--github-users', help='Github user names (comma separated)')
    parser.add_argument('--github-users-file', help='Github users names from file')
    parser.add_argument('--github-repos', help='Github repos (comma separated)')
    parser.add_argument('--github-repos-file', help='Github repos from file.')
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
    parser.add_argument('--add-org-repos-forks', help="Check an org repo even if it's a fork", action='store_true', default=False)
    parser.add_argument('--add-user-repos-forks', help="Check an user repo even if it's a fork", action='store_true', default=False)
    parser.add_argument('--max-urls', help="Maximun number of URLs to check", type=int, default=10000)
    parser.add_argument('--max-repos', help="Maximum number of repos to check from orgs/users", type=int, default=50)
    parser.add_argument('--not-gitleaks', help="Don't use gitleaks", action='store_true', default=False)
    parser.add_argument('--not-trufflehog', help="Don't use trufflehog", action='store_true', default=False)
    parser.add_argument('--not-rex', help="Don't use Rex", action='store_true', default=False)
    parser.add_argument('--not-noseyparker', help="Don't use noseyparker", action='store_true', default=False)
    parser.add_argument('--not-ggshield', help="Don't use ggshield", action='store_true', default=False)
    parser.add_argument('--not-kingfisher', help="Don't use kingfisher", action='store_true', default=False)
    parser.add_argument('--rex-regex-path', help="Path to regex file for Rex (auto download if nothign specified)")
    parser.add_argument('--tools-timeout', default=300, help="Timeout in seconds whe launching the tools")
    parser.add_argument('--max-timeout', type=int, help="Maximum total execution time in seconds (0 for unlimited)", default=0)
    parser.add_argument('--rex-all-regexes', help="Allow Rex to use all the regexes (more noise, but more potential findings)", action='store_true', default=False)

    args = parser.parse_args()

    # Tools
    not_gitleaks = args.not_gitleaks
    not_trufflehog = args.not_trufflehog
    not_rex = args.not_rex
    not_noseyparker = args.not_noseyparker
    not_ggshield = args.not_ggshield
    not_kingfisher = args.not_kingfisher

    if not_gitleaks and not_trufflehog and not_rex and not_noseyparker and not_ggshield and not_kingfisher:
        print("No tool to use...", file=sys.stderr)
        return
    
    # Github
    github_token = args.github_token
    
    github_orgs = args.github_orgs
    if github_orgs:
        github_orgs = github_orgs.split(",")
    github_orgs_file = args.github_orgs_file
    
    github_users_str = args.github_users
    if github_users_str:
        github_users_str = github_users_str.split(",")
    github_users_file = args.github_users_file
    
    github_repos = args.github_repos
    if github_repos:
        github_repos = github_repos.split(",")
    github_repos_file = args.github_repos_file
    if not github_repos: github_repos = []

    add_org_repos_forks = args.add_org_repos_forks
    add_user_repos_forks = args.add_user_repos_forks
    max_repos = args.max_repos
    
    # Trufflehog options
    from_trufflehog_only_verified = args.from_trufflehog_only_verified
    only_verified = args.only_verified
    if only_verified:
        from_trufflehog_only_verified = True
    
    if only_verified and not_trufflehog:
        print("Only verified leaks only works with trufflehog, don't remove it", file=sys.stderr)
        exit(1)
    
    # Rex
    rex_all_regexes = args.rex_all_regexes
    rex_regex_path = args.rex_regex_path
    if not rex_regex_path or not os.path.exists(rex_regex_path):
        print(f"Rex regex path '{rex_regex_path}' does not exist. Trying to download from the default location...", file=sys.stderr)
        
        url = "https://raw.githubusercontent.com/JaimePolop/RExpository/main/regex.yaml"
        
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, "regex.yaml")
        
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()  # Raise an exception for HTTP errors
            with open(temp_path, 'wb') as f:
                f.write(response.content)
            rex_regex_path = temp_path
            print(f"Downloaded regex file to {rex_regex_path}", file=sys.stderr)
        except requests.RequestException as e:
            print(f"Failed to download the regex file from default location due to error: {e}", file=sys.stderr)
            exit(1)

    # URLs
    urls_file = args.urls_file
    stdin_urls = args.stdin_urls
    max_urls = args.max_urls
    
    # Extra
    out_json_file = args.json_file
    threads = int(args.threads)
    debug = args.debug
    generic_leak_in_web = args.generic_leak_in_web
    no_exts = args.not_exts.split(",")
    avoid_sources = args.avoid_sources
    if avoid_sources:
        avoid_sources = avoid_sources.split(",")
    else:
        avoid_sources = set()
    max_secret_length = int(args.max_secret_length)
    MAX_SECRET_LENGTH = max_secret_length
    TIMEOUT = int(args.tools_timeout)
    MAX_TIMEOUT = int(args.max_timeout)


    if not is_tool("gitleaks") and not not_gitleaks:
        print("gitleaks not found (https://github.com/gitleaks/gitleaks). Please install it in PATH", file=sys.stderr)
        exit(1)
    
    if not is_tool("trufflehog") and not not_trufflehog:
        print("trufflehog not found (https://github.com/trufflesecurity/trufflehog). Please install it in PATH", file=sys.stderr)
        exit(1)
    
    if not is_tool("Rex") and not not_rex:
        print("Rex not found (https://github.com/JaimePolop/RExpository). Please install it in PATH", file=sys.stderr)
        exit(1)
    
    if not is_tool("noseyparker") and not not_noseyparker:
        print("noseyparker not found (https://github.com/praetorian-inc/noseyparker). Please install it in PATH", file=sys.stderr)
        exit(1)
    
    if not is_tool("ggshield") and not not_ggshield:
        print("ggshield not found (https://github.com/GitGuardian/ggshield). Please install it in PATH", file=sys.stderr)
        exit(1)
    
    if not is_tool("kingfisher") and not not_kingfisher:
        print("kingfisher not found (https://github.com/mongodb/kingfisher). Please install it in PATH", file=sys.stderr)
        exit(1)

    if not github_orgs and not github_users_str and not github_orgs_file and not github_users_file and not github_repos and not github_repos_file and not urls_file and not stdin_urls:
        print("Nothing to do")
        return
    
    if urls_file and not exists(urls_file):
        print(f"File {urls_file} does not exist")
        urls_file = None # Don't exit but don't use it
    
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
    
    if github_repos_file:
        if not exists(github_repos_file):
            print(f"File {github_repos_file} does not exist")
            exit(1)
        else:
            github_repos = open(github_repos_file, "r").read().splitlines()
    
    # Look in github
    if not github_token and (github_orgs or github_users_str or github_repos):
        print("To check Github repos you need to provide a github token `--github-token` even if they are public repos (create a GH token with only public access)", file=sys.stderr)
        return
    
    if github_token:
        if github_repos:
            github_repos = [r.replace("http://", "").replace("https://", "").replace("github.com/", "") for r in github_repos]

        if github_orgs or github_users_str or github_repos:
            check_github(github_token, github_users_str, github_orgs, github_repos, threads, avoid_sources, debug, from_trufflehog_only_verified, only_verified, add_org_repos_forks, add_user_repos_forks, max_repos, not_gitleaks, not_trufflehog, not_rex, rex_regex_path, rex_all_regexes, not_noseyparker, not_ggshield, not_kingfisher)
        else:
            print("No github orgs or users to check", file=sys.stderr)
            return
    
    # Look in web files
    if urls_file or stdin_urls:
        check_web(urls_file, stdin_urls, threads, avoid_sources, debug, generic_leak_in_web, no_exts, from_trufflehog_only_verified, only_verified, max_urls, not_gitleaks, not_trufflehog, not_rex, rex_regex_path, rex_all_regexes)
    

    if out_json_file:
        with open(out_json_file, "w") as f:
            json.dump(ALL_LEAKS, f)



if __name__ == "__main__":
    main()
