# Leakos

![](leakos.jpeg)

**Search with gitleaks and trufflehog in the responses of the given URLs or in all the repos of an organization and its members.**

## Quick Start

**Remember that you need to install [gitleaks](https://github.com/zricethezav/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog) and [Rex](https://github.com/JaimePolop/RExpository)**

```
pip3 install -r requirements

# Install gitleaks from https://github.com/zricethezav/gitleaks
# Install trufflehog from https://github.com/trufflesecurity/trufflehog
# Install Rex from https://github.com/JaimePolop/RExpository

python3 leakos.py --help
usage: leakos.py [-h] [--github-token GITHUB_TOKEN]
                 [--github-orgs GITHUB_ORGS]
                 [--github-orgs-file GITHUB_ORGS_FILE]
                 [--github-users GITHUB_USERS]
                 [--github-users-file GITHUB_USERS_FILE]
                 [--github-repos GITHUB_REPOS]
                 [--github-repos-file GITHUB_REPOS_FILE]
                 [--urls-file URLS_FILE]
                 [--stdin-urls STDIN_URLS]
                 [--not-exts NOT_EXTS]
                 [--json-file JSON_FILE]
                 [--threads THREADS] [--debug]
                 [--generic-leak-in-web]
                 [--from-trufflehog-only-verified]
                 [--only-verified]
                 [--avoid-sources AVOID_SOURCES]
                 [--max-secret-length MAX_SECRET_LENGTH]
                 [--add-org-repos-forks]
                 [--add-user-repos-forks]
                 [--max-urls MAX_URLS] [--not-gitleaks]
                 [--not-trufflehog] [--not-rex]
                 [--rex-regex-path REX_REGEX_PATH]

Search leaks in a github org or in the responses of urls

options:
  -h, --help            show this help message and exit
  --github-token GITHUB_TOKEN
                        Token to access github api
                        (doesn't require any permission)
  --github-orgs GITHUB_ORGS
                        Github orgs names (comma
                        separated). Users will be
                        searched also in the orgs.
  --github-orgs-file GITHUB_ORGS_FILE
                        Github orgs names from file
  --github-users GITHUB_USERS
                        Github user names (comma
                        separated)
  --github-users-file GITHUB_USERS_FILE
                        Github users names from file
  --github-repos GITHUB_REPOS
                        Github repos (comma separated)
  --github-repos-file GITHUB_REPOS_FILE
                        Github repos from file.
  --urls-file URLS_FILE
                        Search leaks in responses from
                        web urls. Path to file containing
                        URLs to search for leaks.
  --stdin-urls STDIN_URLS
                        Get URLs from stdin
  --not-exts NOT_EXTS   Do not search for leaks in urls
                        with these extensions (comma
                        separated)
  --json-file JSON_FILE
                        Store json results in the
                        indicated file
  --threads THREADS     Number of threads to use
  --debug               Debug
  --generic-leak-in-web
                        Accept generic leaks in web
                        (disabled by defult)
  --from-trufflehog-only-verified
                        From trufflehog get only verified
                        leaks
  --only-verified       Get only verified leaks (only use
                        trufflehog)
  --avoid-sources AVOID_SOURCES
                        Lower case comma separated list
                        of sources from trufflehog and
                        gitleaks to avoid
  --max-secret-length MAX_SECRET_LENGTH
                        Max length of valid secrets
  --add-org-repos-forks
                        Check an org repo even if it's a
                        fork
  --add-user-repos-forks
                        Check an user repo even if it's a
                        fork
  --max-urls MAX_URLS   Maximun number of URLs to check
  --not-gitleaks        Don't use gitleaks
  --not-trufflehog      Don't use trufflehog
  --not-rex             Don't use Rex
  --rex-regex-path REX_REGEX_PATH
                        Path to regex file for Rex (auto
                        download if nothign specified)
```

For the gihub part of this tool you need to **generate a github token** from your account (however this **token doesn't need ANY PERMISSIONS unless you need to grant access to private repos**).

If you like **Leakos** you will probably like also **[Gorks](https://github.com/carlospolop/Gorks)** and **[Pastos](https://github.com/carlospolop/Pastos)** 



