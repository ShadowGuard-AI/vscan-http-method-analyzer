# vscan-http-method-analyzer
Analyzes allowed HTTP methods (e.g., OPTIONS) to identify potential security risks. Checks for methods that should not be enabled in a production environment (e.g., PUT, DELETE) and reports any inconsistencies. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-http-method-analyzer`

## Usage
`./vscan-http-method-analyzer [params]`

The per method probes run even when the OPTIONS request returns an error status. A method counts as allowed only on evidence: its presence in the Allow header, a 2xx response to that method, or a non resource level response status that differs from the status the endpoint returns for a nonsense method used as a baseline. Resource level statuses such as 404 never count as evidence on their own. A uniform error status for every method, such as 404 everywhere, reports no allowed methods. If the target cannot be reached at all, the tool prints no method verdict and exits 1. All requests verify TLS certificates by default; `--insecure` turns verification off for every request and logs a warning when used.

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-t`: No description provided
- `-u`: Custom User-Agent string
- `--insecure`: Disable TLS certificate verification for every request

## License
Copyright (c) ShadowStrikeHQ
