# GitHubScrap

Scrape Github query results with credentials + 2FA.


Basic usage:

`python GitHubScrap.py -c config.json -d Dorks/all_dorks.txt -org uber.com`

Save JSON output to file:
```
python GitHubScrap.py -c config.json -d Dorks/all_dorks.txt -org uber.com -o output.json
```

Print only JSON results to stdout:
```
python GitHubScrap.py -c config.json -d Dorks/all_dorks.txt -org uber.com -silent
```
