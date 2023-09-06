#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Dan Halbert for Adafruit Industries LLC
#
# SPDX-License-Identifier: MIT

import click
import requests
from requests.exceptions import SSLError, RequestException

@click.command()
@click.option(
    "--certs",
    help="certificate bundle (.pem file)",
    default="roots.pem",
    type=click.Path(exists=True, dir_okay=False),
    show_default=True,
)
@click.option(
    "--urls",
    help="file of URLs to test against the supplied certificate bundle",
    default="urls.txt",
    type=click.File("r"),
    show_default=True,
)
def run(certs, urls):
    for url in urls.readlines():
        url = url.strip()
        if not url or url.startswith("#"):
            continue

        try:
            requests.request("GET", url, verify=certs, allow_redirects=True, timeout=20)
            print("PASS", url)
        except SSLError:
            # Could not connect with given certs.
            print("FAIL", url)
        except RequestException as exc:
            # Some other problem, unrelated to SSL issues.
            print("SKIP", url, exc)

if __name__ == "__main__":
    run()
