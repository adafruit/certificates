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
    "--include",
    help="file of cert O and CN names to select; one regexp per line; substring match; case-insensitive; # comments OK",
    default="include.txt",
    type=click.File("r"),
    show_default=True,
)
@click.option(
    "--exclude",
    help="file of cert O and CN names to exclude (after --include); one regexp per line; substring match; case-insensitive; # comments OK",
    default="exclude.txt",
    type=click.File("r"),
    show_default=True,
)
def run(sources, out, include, exclude):
    concatenated_pem = b""
    for source in sources:
        if source.startswith("http"):
            concatenated_pem += requests.get(source).content
        else:
            with open(source, "rb") as input:
                concatenated_pem += input.read()

    # Read a list of regexps to substr-match against Issuer O and CN names.

    def read_patterns(f):
        patterns = []
        for line in f.readlines():
            line = line.strip()
            if line.startswith("#"):
                continue

            patterns.append(re.compile(line, flags=re.IGNORECASE))
        return patterns

    include_patterns = read_patterns(include)
    exclude_patterns = read_patterns(exclude)

    # Read in all the certs at once.
    input_certs = cryptography.x509.load_pem_x509_certificates(concatenated_pem)

    # For each cert, see if its O or CN name matches against the list of include and exclude patterns.

    for cert in input_certs:
        issuer = cert.issuer
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

        include_cert = False
        for pattern in include_patterns:
            if pattern.search(org_name) or pattern.search(common_name):
                include_cert = True
                break

        if include_cert:
            for pattern in exclude_patterns:
                print(pattern, org_name, common_name)
                if pattern.search(org_name) or pattern.search(common_name):
                    print("EXCLUDED", cert)
                    include_cert = False
                    break

        if include_cert:
            # Add a comment with the O and CN names.
            out.write(f"# O={org_name}, CN={common_name}\n".encode("ascii"))
            out.write(cert.public_bytes(Encoding.PEM))


if __name__ == "__main__":
    run()
