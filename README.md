## TLS/SSL certificates used in Adafruit software

[CircuitPython](https://github.com/adafruit/circuitpython),
[NINA-FW](https://github.com/adafruit/nina-fw),
Adafruit IO Arduino libraries, and other Adafruit software need a current set of TLS
root certificates for secure web access.
Microsoft, Mozilla, Android, curl, and other projects maintain lists of root and related certificates.
Those lists are quite complete, and too large for some embedded firmware.

This repo includes a tool to combine local or fetched root certificate lists and filter them
to the most commonly needed roots.
There is also a testing tool.
Projects can then use this repo as a submodule to have access to an updated list of root
certificates.

Currently the certificates are filtered from the [`curl` root
list](https://curl.se/docs/caextract.html), which is based on the
Mozilla root list, and from a local file.

- `tools/extra.pem` is a list of certificates needed but not present in the Mozilla root list.
- `tools/filter_certs.py` does the filtering to the most common root cert providers.
- `tools/filters.txt` contains regexps to match those providers or the cert names
- `tools/test_site_coverage.py` tests a given `roots.pem` against a long list of URL's.
- `tools/urls.txt` is that list of URLs. Add to it as necessary. Some are commented out, for reasons noted.

The resulting filtered root certificate bundle is in `data/`.
- `data/roots.pem` contains the filtered list, with comments describing each certificate.
