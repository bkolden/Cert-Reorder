#!/usr/bin/env python
"""Sorts PEM certificates in a particular order."""

import argparse
from typing import Optional

import OpenSSL


def build_parser() -> argparse.ArgumentParser:
    """Define argParser arguments and variables.

    Returns argument parser object.
    """
    parser = argparse.ArgumentParser(
        description='Manipulate the order of certificates in a pem style file',
    )
    parser.add_argument('file', type=argparse.FileType('r'), default='-', nargs='?')
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        '-r',
        '--reverse',
        dest='action',
        action='store_const',
        const=reverse,
        default=interactive,
        help='Reverse the order of certificates.',
    )
    action.add_argument(
        '-p',
        '--print',
        dest='action',
        action='store_const',
        const=print_cert_name,
        help='',
    )
    action.add_argument(
        '-a',
        '--auto',
        dest='action',
        action='store_const',
        const=auto,
        help='',
    )
    return parser


class CertParser:
    """Certificate Parser class for sorting certificates."""

    def __init__(self) -> None:
        """Static variables for parsing PEM certificates."""
        self._begin = '-----BEGIN CERTIFICATE-----'
        self._end = '-----END CERTIFICATE-----'

    def _get_lines(self, file: argparse.FileType) -> list:
        """Add Docs here.

        Args:
          file: File object.

        Returns lines from certificate file without leading/training whitespace.
        """
        return [line.strip() for line in file.readlines()]

    def _get_certificates(self, lines: list) -> list:
        """Add Docs here.

        Args:
          lines: List of lines from a certificate file.

        Returns: List of certificates found from the file lines.
        """
        start = None
        end = None
        certs = []
        for i in range(len(lines)):
            if start is None:
                if lines[i] == self._begin:
                    start = i
                    continue
            elif end is None:
                if lines[i] != self._end:
                    continue
                end = i
                certs.append(lines[start : end + 1])
                start, end = None, None
        return certs

    def parse(self, file: argparse.FileType) -> list:
        """Parse certificates from file into list of PEM certificates.

        Args:
          file: File object.
          certs: List of PEM certificates.

        Returns: List of PEM certificates.
        """
        content = self._get_lines(file)
        return ['\n'.join(x) for x in self._get_certificates(content)]

    def get_common_name(self, cert: str) -> str:
        """Parse given cert for Common Name.

        Args:
          cert: PEM certificate.

        Returns given certificate's Common Name as a string.
        """
        return (
            OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            .get_subject()
            .commonName
        )


def reverse(certs: list) -> None:
    """Print certificates to standard output in reverse order.

    Args:
      certs: List of PEM certificates.

    Returns: Nothing.
    """
    certs.reverse()
    print(as_chain(certs))


def print_cert_name(certs: list) -> None:
    """Print the Common Names from the list of PEM certificates.

    Args:
      certs: List of PEM certificates.

    Returns: Nothing.
    """
    p = CertParser()
    for cert in certs:
        print(p.get_common_name(cert))


def as_chain(certs: list) -> str:
    """Concatenate certificates and print as a string to standard out.

    Args:
      certs: List of PEM certificates.

    Returns string containing all of the certificates.
    """
    return '\n'.join(certs)


def find_root(certs: list) -> Optional[str]:
    """Find the root cert from the list of certificates.

    Args:
      certs: List of PEM certificates.

    Returns cert dictionary.
    """
    for i, cert in enumerate(certs):
        if (
            cert['cert'].get_issuer().commonName
            == cert['cert'].get_subject().commonName
        ):
            del certs[i]
            return cert
    return None


def parse(certs: list) -> list:
    """Parses list of certificates and returns list of dicts.

    Args:
      certs: List of PEM certificates.

    Returns: Nothing.
    """
    x = []
    for cert in certs:
        x.append(
            {
                'text': cert,
                'cert': OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    cert,
                ),
            },
        )
    return x


def add_next(pcerts: dict, certs: list) -> Optional[str]:
    """Return child certificate of given issuer, if present.

    Args:
      pcerts: Not sure what this is.
      certs: List of PEM certificates.

    Returns certificate as a string.
    """
    parent = pcerts['cert'].get_subject().commonName
    for i, cert in enumerate(certs):
        if cert['cert'].get_issuer().commonName == parent:
            del certs[i]
            return cert
    return None


def auto(certs: list) -> None:
    """Prints certs in 'Automatic' order.

    Args:
      certs: list of certs.

    Returns nothing.
    """
    certs = parse(certs)
    chain = []
    chain.insert(0, find_root(certs))
    while True:
        next = add_next(chain[0], certs)
        if next is None:
            break
        chain.insert(0, next)
    chain = [c['text'] for c in chain]
    print(as_chain(chain))


def interactive(certs: list) -> None:
    """Not yet implemented.

    Args:
      certs: list of certs.

    Returns nothing.
    """
    print('Not yet implemented')


if __name__ == '__main__':
    args = build_parser().parse_args()
    args.action(CertParser().parse(args.file))
