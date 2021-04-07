#!/usr/bin/env python3

# GitHubScrap is a simple Python 3 script that automates GitHub OSINT during early stages of Red Team exercises
# author - mamatb & b1ackGamba
# location - https://github.com/b1ackGamba/GitHubScrap


#TODO filter duplicate files from diferent code, por ejmplo
#https://github.com/mattfred/MediaCenter/blob/c84a520de9fccac2460ec94fec1589e06ef18cc6/lib/libUPnP/Neptune/Extras/Tools/Testing/https-urls.txt
#https://github.com/quarnster/boxeebox-xbmc/blob/7209547d3d247a4082de956f4d9a765086d96985/lib/libUPnP/Neptune/Extras/Tools/Testing/https-urls.txt

import sys, json, requests, argparse, os, colored
from colored import stylize
from re import compile
from time import sleep
from pyotp import TOTP
from os.path import exists
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlencode, quote_plus


GITHUB_HTTP_DELAY = 1.5
SLACK_HTTP_DELAY = 1.5

github_types = [
	'repositories',
	'code',
	'commits',
	'issues',
	'discussions',
	'packages',
	'marketplace',
	'topics',
	'wikis'
]


class MsgException(Exception):
	def __init__(self, message, exception, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.message = message
		self.exception = exception

def panic(msg_exception):
	"""exception handling"""
	print(
		f'[!] Error! {msg_exception.message}:\n'
		f'    {msg_exception.exception}'
	, file = sys.stderr)


def blockPrint():
    sys.stdout = open(os.devnull, 'w')

def enablePrint():
    sys.stdout = sys.__stdout__


class GithubScrapDork():
	def __init__(self, config_file, dorkfile, github_query_terms, output_file, verbosity, silent):
		self.github_query_terms = github_query_terms
		self.github_username, self.github_password, self.github_otp = self.__load_config(config_file)
		self.dorks = self.__load_dorkfile(dorkfile)
		self.output_file = output_file
		self.verbosity = verbosity
		self.silent = silent
		self.final_results = {"results":list()}

		if silent:
			blockPrint()

	def __debugInfo(self, msg):
		"""Print debug info if verbose enabled"""
		if self.verbosity:
			print(stylize("[*] DEBUG: {}".format(msg), colored.fg("wheat_1")))

	def __load_config(self, config_path):
		"""json config file reading"""
		try:
			with open(config_path, 'r') as config_file:
				config_json = json.load(config_file)
				github_username = config_json.get('github_username')
				github_password = config_json.get('github_password')
				github_otp = config_json.get('github_otp')
		except Exception as exception:
			raise MsgException('Config file could not be read', exception)
		return github_username, github_password, github_otp


	def __load_dorkfile(self, dork_path):
		"""Dork file reading"""
		try:
			dork_array = list()
			with open(dork_path) as dork_file:
				line = dork_file.readline()
				while line:
					dork_array.append(line.rstrip())
					line = dork_file.readline()
		except Exception as exception:
			raise MsgException('Dork file could not be read', exception)
		return dork_array


	def __github_login(self, github_http_session):
		"""github logging in (3 requests needed)"""
		self.__debugInfo("Logging into Github")
		try: # 1st request (grab some data needed for the login form)
			github_html_login = github_http_session.get('https://github.com/login')
			sleep(GITHUB_HTTP_DELAY)
			github_soup_login = BeautifulSoup(github_html_login.text, 'html.parser')
			form_data_login = {
				'commit': 'Sign in',
				'authenticity_token': github_soup_login.find('input', {'name': 'authenticity_token'})['value'],
				'login': self.github_username,
				'password': self.github_password,
				'webauthn-support': 'supported',
				'webauthn-iuvpaa-support': 'unsupported',
				github_soup_login.find('input', {'name': compile('required_field_')})['name']: '',
				'timestamp': github_soup_login.find('input', {'name': 'timestamp'})['value'],
				'timestamp_secret': github_soup_login.find('input', {'name': 'timestamp_secret'})['value']
			}
		except Exception as exception:
			raise MsgException('Unable to HTTP-GET GitHub login data', exception)

		try: # 2nd request (submit the login form and grab some data needed for the OTP form)
			github_http_session.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
			github_html_twofactor = github_http_session.post('https://github.com/session', data = urlencode(form_data_login))
			sleep(GITHUB_HTTP_DELAY)
			github_soup_twofactor = BeautifulSoup(github_html_twofactor.text, 'html.parser')
			form_data_otp = {'authenticity_token': github_soup_twofactor.find('input', {'name': 'authenticity_token'})['value']}
		except Exception as exception:
			raise MsgException('Unable to log in to GitHub (credentials)', exception)

		try: # 3rd request (submit the OTP form)
			form_data_otp.update({'otp': TOTP(self.github_otp).now()})
			github_http_session.post('https://github.com/sessions/two-factor', data = urlencode(form_data_otp))
			sleep(GITHUB_HTTP_DELAY)
			github_http_session.headers.pop('Content-Type')
		except Exception as exception:
			raise MsgException('Unable to log in to GitHub (OTP)', exception)


	def __github_search_count(self, github_http_session, query_term, github_type):
		"""search results count"""
		try:
			github_html_count = github_http_session.get(f'https://github.com/search/count?q={quote_plus(query_term)}&type={quote_plus(github_type)}')
			sleep(GITHUB_HTTP_DELAY)
			github_soup_count = BeautifulSoup(github_html_count.text, 'html.parser')
			github_count = github_soup_count.span.text
			if "k" in github_count.lower():
				github_count = "{}000".format(github_count[:github_count.lower().index("k")])
		except Exception as exception:
			raise MsgException('Unable to count GitHub search results', exception)
		return github_count


	def __github_search_retrieval(self, github_http_session, query_term, github_type, dork):
		"""search results retrieval"""
		try:
			github_html_pages = github_http_session.get(f'https://github.com/search?o=desc&q={quote_plus(query_term)}&type={quote_plus(github_type)}')
			sleep(GITHUB_HTTP_DELAY)
			github_soup_pages = BeautifulSoup(github_html_pages.text, 'html.parser')
			github_pages_tag = github_soup_pages.find('em', {'data-total-pages': True})
			github_pages = github_pages_tag['data-total-pages'] if github_pages_tag else 1
			github_search_result = list()

			for github_page in range(int(github_pages)):
				github_html_page = github_http_session.get(f'https://github.com/search?o=desc&p={github_page + 1}&q={quote_plus(query_term)}&type={quote_plus(github_type)}')
				sleep(GITHUB_HTTP_DELAY)
				github_soup_page = BeautifulSoup(github_html_page.text, 'html.parser')
				github_search_date = datetime.now().strftime('%F %T')
				for github_search_occurrence in github_soup_page.find_all('a', {'data-hydro-click': True}):
					github_search_result.append({
						"link": "https://github.com{}".format(github_search_occurrence['href']),
						"github_type": github_type, 
						"datetime": github_search_date,
						"dork": dork,
						"query": query_term
						})

					if not self.output_file or self.verbosity:
						print(stylize("https://github.com{}".format(github_search_occurrence['href']), colored.fg("cyan_3")))

		except Exception as exception:
			raise MsgException('Unable to retrieve GitHub search results', exception)
		return github_search_result[1:]


	def __saveGithubResults(self):
		"""json output file writing"""
		self.__debugInfo("Saving JSON results into file {}".format(self.output_file))
		try:
			with open(self.output_file, 'w') as wfile:
				json.dump(self.final_results, wfile)
		except Exception as exception:
			raise MsgException('Output file could not be written', exception)

	"""
	def __showresults(self, github_results):
		for result in github_results:
			print(stylize(result["link"], colored.fg("cyan_3")))
	"""

	def __github_logout(self, github_http_session):
		"""github logging out (2 requests needed)"""
		self.__debugInfo("Logging out from Github account")
		try: # 1st request (grab some data needed for the logout form)
			github_html_root = github_http_session.get('https://github.com')
			sleep(GITHUB_HTTP_DELAY)
			github_soup_root = BeautifulSoup(github_html_root.text, 'html.parser')
			form_data_logout = {'authenticity_token': github_soup_root.find('input', {'name': 'authenticity_token'})['value']}
		except Exception as exception:
			raise MsgException('Unable to HTTP-GET GitHub logout data', exception)

		try: # 2nd request (submit the logout form)
			github_http_session.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
			github_http_session.post('https://github.com/logout', data = urlencode(form_data_logout))
			sleep(GITHUB_HTTP_DELAY)
			github_http_session.headers.pop('Content-Type')
		except Exception as exception:
			raise MsgException('Unable to log out from GitHub', exception)


	def launchGitDorking(self):
		"""Run the query with every dork"""
		try:
			print("[+] Started Github Scraping with the query {}".format(self.github_query_terms))
			github_http_session = requests.session()
			github_http_headers = {
				'User-Agent': 'Mozilla Firefox Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0',
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
				'Accept-Encoding': 'gzip, deflate',
				'Accept-Language': 'en,es;q=0.5',
				'Connection': 'close',
				'Referer': 'https://github.com/'
			}
			github_http_session.headers.update(github_http_headers)
			self.__github_login(github_http_session)

			for dork in self.dorks:
				for github_type in github_types:
					query_term = "{} {}".format(self.github_query_terms, dork)
					github_count = self.__github_search_count(github_http_session, query_term, github_type)
					if int(github_count) >= 1:
						print(stylize("[+] {} results while looking for {} ({})".format(github_count, query_term, github_type), colored.fg("green")))
					elif self.verbosity:
						print("[+] {} results while looking for {} ({})".format(github_count, query_term, github_type))

					if github_count != '0':
						github_results = self.__github_search_retrieval(github_http_session, query_term, github_type, dork)
						if github_results:
							self.final_results["results"].extend(github_results)
							"""
							if not self.output_file or self.verbosity:
								self.__showresults(github_results)
							"""

			if self.output_file:
				unseen_urls = self.__saveGithubResults()

			if self.silent:
				enablePrint()
				print(self.final_results)
				blockPrint()

		except MsgException as msg_exception:
			panic(msg_exception)
		finally:
			try:
				self.__github_logout(github_http_session)
				github_http_session.close()
			except:
				sys.exit(-1)


def setSearchQuery(query, org):
	"""Query setup"""
	if not query and not org:
		print("[!] Query arg (-q) or org (-org) must be set. Only one of those.")
		sys.exit(0)
	elif query and org:
		print("[!] Both args query (-q) and org (-org) cannot be set. Only one of those.")
		sys.exit(0)

	if query and not org:
		return "\"{}\"".format(query)
	elif org and not query:
		return "org:{}".format(org)
	else:
		print("[!] Error setting the query")
		sys.exit(0)


def main():
	"""main"""
	parser = argparse.ArgumentParser(
		description="GithubScraper", 
		epilog="Example usage:\t python {} -c config.json -d Dorks/all_dorks.txt -org example.com".format(os.path.basename(__file__))
		)

	parser.add_argument("-c", "--config", required=True, help="Configuration file with credentials")
	parser.add_argument("-d", "--dorks", required=True, help="Dorks file")
	parser.add_argument("-org", "--org", help="Github query by org")
	parser.add_argument("-q", "--query", help="Github query")
	parser.add_argument("-o", "--output", help="Output file (JSON)")
	parser.add_argument("-v", "--verbose", action='store_true', help="Show debug info")
	parser.add_argument("-silent", "--silent", action='store_true', help="Show only results in JSON format in stdout")

	args = parser.parse_args()

	config_file = args.config
	dork_file = args.dorks
	query = args.query if args.query else False
	org = args.org if args.org else False
	output_file = args.output if args.output else False
	verbosity = True if args.verbose else False
	silent = True if args.silent else False

	query_term = setSearchQuery(query, org)

	gitdork = GithubScrapDork(config_file, dork_file, query_term, output_file, verbosity, silent)
	gitdork.launchGitDorking()

if __name__ == '__main__':
	main()
