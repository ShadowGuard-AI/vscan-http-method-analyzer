import argparse
import requests
import logging
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
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for every request (default: verification on). Use only on targets you are authorized to test.")
    return parser.parse_args()

def analyze_http_methods(url, timeout, user_agent, insecure=False):
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
        'errors': [],
        'reachable': False
    }

    risky_methods = ['PUT', 'DELETE', 'TRACE', 'TRACK', 'CONNECT']  # Methods to flag as potentially risky
    verify = not insecure
    if insecure:
        logging.warning("TLS certificate verification disabled by the --insecure flag.")

    def note_allowed(method, why):
        if method not in results['allowed_methods']:
            results['allowed_methods'].append(method)
            logging.warning(f"Method '{method}' is allowed for {url} ({why})")
        if method in risky_methods and method not in results['potentially_risky_methods']:
            results['potentially_risky_methods'].append(method)

    headers = {'User-Agent': user_agent}

    # OPTIONS request to determine allowed methods. Its status never
    # gates the probing below: an error status is read, not raised.
    try:
        response = requests.options(url, timeout=timeout, headers=headers, verify=verify)
        results['reachable'] = True
        allowed_methods_header = response.headers.get('Allow')
        if allowed_methods_header:
            for method in [m.strip().upper() for m in allowed_methods_header.split(',') if m.strip()]:
                note_allowed(method, "Allow header")
        else:
            logging.info(f"No 'Allow' header found in OPTIONS response for {url}")
    except requests.exceptions.RequestException as e:
        error_message = f"OPTIONS request failed for {url}: {e}"
        logging.error(error_message)
        results['errors'].append(error_message)

    # Baseline: the status the endpoint returns for a nonsense method.
    # A probe status only counts as evidence when it differs from this.
    baseline_status = None
    try:
        req = requests.Request('ZZZNONSENSE', url, headers=headers)
        s = requests.Session()
        baseline_response = s.send(req.prepare(), timeout=timeout, verify=verify)
        results['reachable'] = True
        baseline_status = baseline_response.status_code
    except requests.exceptions.RequestException as e:
        logging.debug(f"Baseline probe failed: {e}")

    # Per method probing, independent of the OPTIONS outcome.
    all_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH', 'CONNECT']
    for method in all_methods:
        if method == 'OPTIONS':
            continue # Avoid redundant OPTIONS check
        try:
            req = requests.Request(method, url, headers=headers)
            prepared = req.prepare()
            s = requests.Session()
            response = s.send(prepared, timeout=timeout, verify=verify)
            results['reachable'] = True
            status = response.status_code
            if status == 405 or status >= 500:
                continue
            # Evidence the method itself was accepted: a 2xx response,
            # a redirect that differs from the baseline, or another
            # status that differs from a usable nonsense method baseline.
            # Resource level statuses (400, 401, 403, 404, 410) are no
            # evidence on their own, and a baseline at 5xx means the
            # server rejected the nonsense method itself, so it cannot
            # be used for comparison.
            resource_level = status in (400, 401, 403, 404, 410)
            baseline_usable = baseline_status is not None and baseline_status < 500
            if 200 <= status < 300:
                note_allowed(method, f"Status Code: {status}, baseline: {baseline_status}")
            elif not resource_level and baseline_usable and status != baseline_status:
                note_allowed(method, f"Status Code: {status}, baseline: {baseline_status}")
        except requests.exceptions.RequestException as e:
            logging.debug(f"Error checking method {method}: {e}")
            pass # Errors are acceptable here since we are probing various methods

    if not results['reachable']:
        results['errors'].append(f"Target {url} could not be reached at all; no method verdict was earned.")

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

    if not results.get('reachable', True):
        print("Analysis failed: the target could not be reached, so no method verdict is reported.")
        print("-" * 20)
        return

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

    results = analyze_http_methods(url, timeout, user_agent, insecure=args.insecure)
    print_results(results)
    if not results.get('reachable', False):
        sys.exit(1)

if __name__ == "__main__":
    main()