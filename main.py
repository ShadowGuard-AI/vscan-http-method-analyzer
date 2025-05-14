import argparse
import requests
import logging
from bs4 import BeautifulSoup
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-http-method-analyzer: Analyzes allowed HTTP methods to identify potential security risks.")
    parser.add_argument("url", help="The URL to analyze (e.g., http://example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for HTTP requests in seconds (default: 5)")
    parser.add_argument("-u", "--user-agent", type=str, default="vscan-http-method-analyzer/1.0", help="Custom User-Agent string")
    return parser.parse_args()

def analyze_http_methods(url, timeout, user_agent):
    """
    Analyzes the allowed HTTP methods for a given URL.

    Args:
        url (str): The URL to analyze.
        timeout (int): The timeout for HTTP requests in seconds.
        user_agent (str): Custom User-Agent to use for requests.

    Returns:
        dict: A dictionary containing the results of the analysis.
              Keys include:
                - 'url': The URL that was analyzed.
                - 'allowed_methods': A list of allowed HTTP methods.
                - 'potentially_risky_methods': A list of potentially risky methods.
                - 'errors': A list of errors encountered during the analysis.
    """

    results = {
        'url': url,
        'allowed_methods': [],
        'potentially_risky_methods': [],
        'errors': []
    }

    risky_methods = ['PUT', 'DELETE', 'TRACE', 'TRACK', 'CONNECT']  # Methods to flag as potentially risky

    try:
        # OPTIONS request to determine allowed methods
        headers = {'User-Agent': user_agent}
        response = requests.options(url, timeout=timeout, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        allowed_methods_header = response.headers.get('Allow')
        if allowed_methods_header:
            allowed_methods = [method.strip().upper() for method in allowed_methods_header.split(',')]
            results['allowed_methods'] = allowed_methods

            for method in allowed_methods:
                if method in risky_methods:
                    results['potentially_risky_methods'].append(method)
                    logging.warning(f"Potentially risky HTTP method '{method}' is allowed for {url}")

        else:
            logging.warning(f"No 'Allow' header found in OPTIONS response for {url}")
            results['errors'].append("No 'Allow' header found in OPTIONS response.")


        # Check for methods without OPTIONS
        all_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH', 'CONNECT']  # Common HTTP methods
        for method in all_methods:
            try:
                headers = {'User-Agent': user_agent}
                if method == 'OPTIONS':
                    continue # Avoid redundant OPTIONS check
                req = requests.Request(method, url, headers=headers)
                prepared = req.prepare()
                s = requests.Session()
                response = s.send(prepared, timeout=timeout, verify=False)

                if response.status_code != 405: # 405 Method Not Allowed is the expected response if the method is not enabled
                    if response.status_code < 500: # Filter out server errors
                        logging.warning(f"Method '{method}' may be allowed for {url} (Status Code: {response.status_code})")
                        if method not in results['allowed_methods']:
                           results['allowed_methods'].append(method)
                        if method in risky_methods:
                            results['potentially_risky_methods'].append(method)

            except requests.exceptions.RequestException as e:
                logging.debug(f"Error checking method {method}: {e}")
                pass # Errors are acceptable here since we are probing various methods

    except requests.exceptions.RequestException as e:
        error_message = f"Error analyzing {url}: {e}"
        logging.error(error_message)
        results['errors'].append(error_message)


    return results


def print_results(results):
    """
    Prints the results of the analysis to the console.

    Args:
        results (dict): The results of the analysis.
    """

    print(f"Analysis for: {results['url']}")
    print("-" * 20)

    if results['errors']:
        print("Errors:")
        for error in results['errors']:
            print(f"  - {error}")
        print("-" * 20)

    if results['allowed_methods']:
        print("Allowed HTTP Methods:")
        for method in results['allowed_methods']:
            print(f"  - {method}")
        print("-" * 20)
    else:
        print("No allowed methods detected.")
        print("-" * 20)

    if results['potentially_risky_methods']:
        print("Potentially Risky Methods:")
        for method in results['potentially_risky_methods']:
            print(f"  - {method}")
        print("-" * 20)
    else:
        print("No potentially risky methods detected.")
        print("-" * 20)


def main():
    """
    Main function to execute the HTTP method analyzer.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    url = args.url
    timeout = args.timeout
    user_agent = args.user_agent

    # Input validation: Check if the URL starts with http:// or https://
    if not (url.startswith("http://") or url.startswith("https://")):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    results = analyze_http_methods(url, timeout, user_agent)
    print_results(results)

if __name__ == "__main__":
    main()