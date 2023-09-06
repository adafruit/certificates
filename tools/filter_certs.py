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
    "--in",
    "in_",
    help=".pem filename or URL to filter",
    default="https://curl.se/ca/cacert.pem",
    show_default=True,
)
@click.option(
    "--out",
    "out_",
    default="roots.pem",
    help="filtered .pem file",
    type=click.File("wb"),
    show_default=True,
)
@click.option(
    "--comment",
    is_flag=True,
    default=False,
    help="Comment certs in output",
    show_default=True,
)
@click.option(
    "--issuers",
    "issuers_",
    help="file of issuers to select; one regexp per line; substring match; case-insensitive; # comments OK",
    default="issuers.txt",
    type=click.File("r"),
    show_default=True,
)
def run(in_, out_, comment, issuers_):
    if in_.startswith("http"):
        input_text = requests.get(in_).content
    else:
        with open(in_, "rb") as input:
            input_text = input.read()

    # Read a list of regexps to substr-match against Issue names.

    issuer_patterns = []
    for line in issuers_.readlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        issuer_patterns.append(re.compile(line, flags=re.IGNORECASE))

    # Read in all the certs at once.
    input_certs = cryptography.x509.load_pem_x509_certificates(input_text)

    # For each cert, see if its O or CN name matches against the list of filter patterns.

    for cert in input_certs:
        input_issuer = cert.issuer
        org_name_attributes = input_issuer.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        org_name = org_name_attributes[0].value if org_name_attributes else ""

        common_name_attributes = input_issuer.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
        common_name = common_name_attributes[0].value if common_name_attributes else ""

        match_name = org_name or common_name
        if not match_name:
            raise ValueError(f"no OU or CN available for {input_issuer}")

        for pattern in issuer_patterns:
            if pattern.search(match_name):
                # Add a comment with the O and CN names if requested.
                if comment:
                    out_.write(f"# O={org_name}, CN={common_name}\n".encode("ascii"))
                out_.write(cert.public_bytes(Encoding.PEM))


if __name__ == "__main__":
    run()
