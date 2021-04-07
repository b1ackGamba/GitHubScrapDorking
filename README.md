# GitHubScrapDorking

Scrape Github query results with credentials + 2FA.


Basic usage:

`python GitHubScrapDorking.py -c config.json -d Dorks/all_dorks.txt -q uber.com`

Save JSON output to file:

`python GitHubScrapDorking.py -c config.json -d Dorks/all_dorks.txt -q uber.com -o output.json`

Print only JSON results to stdout:

`python GitHubScrapDorking.py -c config.json -d Dorks/all_dorks.txt -q uber.com -silent`
