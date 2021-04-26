# GitHubScrapDorking

Scrape Github query results with credentials + 2FA.


Basic usage:

`python GitHubScrapDorking.py -c config.json -d Dorks/all_dorks.txt -q uber.com`

Save JSON output to file:

`python GitHubScrapDorking.py -c config.json -d Dorks/all_dorks.txt -q uber.com -o output.json`

Print only JSON results to stdout:

`python GitHubScrapDorking.py -c config.json -d Dorks/all_dorks.txt -q uber.com -silent`


Help:

```
usage: GitHubScrapDorking.py [-h] -c CONFIG -d DORKS [-org ORG] [-q QUERY] [-o OUTPUT] [-v] [-silent] [-f]

GithubScraper

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Configuration file with credentials
  -d DORKS, --dorks DORKS
                        Dorks file
  -org ORG, --org ORG   Github query by org
  -q QUERY, --query QUERY
                        Github query
  -o OUTPUT, --output OUTPUT
                        Output file (JSON)
  -v, --verbose         Show debug info
  -silent, --silent     Show only results in JSON format in stdout
  -f, --filter          Remove duplicate files from results

Example usage: python GitHubScrapDorking.py -c config.json -d Dorks/all_dorks.txt -org example.com
```
