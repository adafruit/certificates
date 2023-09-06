## TLS/SSL certificates used in Adafruit software

[CircuitPython](https://github.com/adafruit/circuitpython),
[NINA-FW](https://github.com/adafruit/nina-fw),
Adafruit IO Arduino libraries, and other Adafruit software need a current set of TLS
root certificates for secure web access.
Microsoft, Mozilla, Android, curl, and other projects maintain lists of root and related certificates.
Those lists are quite complete, and too large for some embedded firmware.

This repo includes tools to download a list of root certificates and
subset it to the most commonly needed roots. Projects can then use
this repo as a submodule to have access to an updated list of root
certificates.

Currently the certificates are filtered from the [`curl` root
list](https://curl.se/docs/caextract.html), which is based on the
Mozilla root list.

- `tools/filter_certs.py` does the filtering to the most common root cert providers.
- `tools/issuers.txt` contains regexps to match those providers.
- `tools/test_site_coverage.py` tests a given `roots.pem` against a long list of URL's.
- `tools/urls.txt` is that list of URLs. Add to it as necessary. Some are commented out, for reasons noted.

The resulting files are in `data/`.
- `data/roots.pem` is just a certificate bundle.
- `data/roots-commented.pem` is the same bundle with a comment line describing the certificate.
