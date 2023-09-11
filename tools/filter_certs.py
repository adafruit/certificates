#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Dan Halbert for Adafruit Industries LLC
#
# SPDX-License-Identifier: MIT

import click
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
import cryptography.x509
import requests
import re


@click.command()
@click.option(
    "--sources",
    multiple=True,
    help=".pem filenames or URLs to filter",
    default=("https://curl.se/ca/cacert.pem", "extra.pem"),
    show_default=True,
)
@click.option(
    "--out",
    default="roots.pem",
    help="filtered combined .pem file",
    type=click.File("wb"),
    show_default=True,
)
@click.option(
    "--filters",
    help="file of cert O and CN names to select; one regexp per line; substring match; case-insensitive; # comments OK",
    default="filters.txt",
    type=click.File("r"),
    show_default=True,
)
def run(sources, out, filters):
    concatenated_pem = b""
    for source in sources:
        if source.startswith("http"):
            concatenated_pem += requests.get(source).content
        else:
            with open(source, "rb") as input:
                concatenated_pem += input.read()

    # Read a list of regexps to substr-match against Issuer O and CN names.

    filter_patterns = []
    for line in filters.readlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        filter_patterns.append(re.compile(line, flags=re.IGNORECASE))

    # Read in all the certs at once.
    input_certs = cryptography.x509.load_pem_x509_certificates(concatenated_pem)

    # For each cert, see if its O or CN name matches against the list of filter patterns.

    for cert in input_certs:
        issuer = cert.issuer
        print(issuer)
        org_name_attributes = issuer.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        org_name = org_name_attributes[0].value if org_name_attributes else ""

        common_name_attributes = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = (
            common_name_attributes[0].value if common_name_attributes else ""
        )

        if not any((org_name, common_name)):
            raise ValueError(f"no O or CN available for {issuer}")

        passes_filters = False
        for pattern in filter_patterns:
            if pattern.search(org_name) or pattern.search(common_name):
                passes_filters = True
                break

        if passes_filters:
            # Add a comment with the O and CN names.
            out.write(f"# O={org_name}, CN={common_name}\n".encode("ascii"))
            out.write(cert.public_bytes(Encoding.PEM))


if __name__ == "__main__":
    run()
