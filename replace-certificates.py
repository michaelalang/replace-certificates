#!/usr/bin/python

import openshift as oc
from base64 import b64decode, b64encode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization

import logging
import os
import sys
import optparse

logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def get_cert_object(data):
    logging.debug(f"loading certificate")
    cert = x509.load_pem_x509_certificate(b64decode(data), default_backend())
    return cert


def replace(secret, new_cert, new_key):
    logging.info(
        f"replacing {secret.namespace()} {secret.qname()} {cert.subject.rfc4514_string()}"
        + f" (expire {cert.not_valid_after}) with {new_cert.subject.rfc4514_string()} "
        + f"({new_cert.not_valid_before}-{new_cert.not_valid_after})"
    )
    if not options.dryrun:
        secret.model["data"]["tls.key"] = b64encode(
            new_key.private_bytes(
                Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode("utf8")
        secret.model["data"]["tls.crt"] = b64encode(
            new_cert.public_bytes(Encoding.PEM)
        ).decode("utf8")
        oc.replace(secret)
    else:
        logging.debug("skipping replace due to dry-run mode")


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="usage: %prog [options] ignore_ns1 ignore_ns2_startingwith- ignore_ns3 ignore_ns4_startingwith-"
    )
    parser.add_option("-c", "--cert", action="store", default=None)
    parser.add_option("-k", "--key", action="store", default=None)
    parser.add_option("-i", "--ignore", action="append", default=[])
    parser.add_option("-s", "--subject", action="store", default=None)
    parser.add_option("--context", action="store", default=None)
    parser.add_option("-n", "--namespace", action="store", default="default")
    parser.add_option(
        "-A", "--all-namespaces", dest="all", action="store_true", default=False
    )
    parser.add_option("--dry-run", dest="dryrun", action="store_true", default=False)
    parser.add_option("-d", "--debug", action="store_true", default=False)
    options, remainings = parser.parse_args()

    options.ignore.extend(remainings)
    options.ignore = list(set(options.ignore))
    if options.ignore == []:
        options.ignore = ["-"]

    if options.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    NEWCERT = options.cert
    NEWKEY = options.key
    if any([NEWCERT is None, NEWKEY is None]):
        logging.error("you need to specify --cert and --key")
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(NEWCERT):
        logging.error(f"unable to open Certificate {NEWCERT}, no such file")
        sys.exit(1)
    try:
        new_cert = x509.load_pem_x509_certificate(open(NEWCERT).read().encode("utf8"))
    except Exception as certerr:
        logging.error(f"unable to load Certificate {NEWCERT} {certerr}")
        sys.exit(1)
    if not os.path.isfile(NEWKEY):
        logging.error(f"unable to open private key {NEWKEY}, no such file")
        sys.exit(1)
    try:
        new_key = serialization.load_pem_private_key(
            open(NEWKEY).read().encode("utf8"), password=None
        )
    except Exception as certerr:
        logging.error(f"unable to load private key {NEWKEY} {certerr}")
        sys.exit(1)

    if not options.context is None:
        logging.debug(f"using context {options.context}")
        oc.use_config_context(options.context)
    if not options.all:
        logging.debug(f"using namespace {options.namespace}")
        oc.project(options.namespace)
    else:
        logging.debug(f"using all namespaces")

    logging.debug("API query for secrets, type 'kubernetes.io/tls'")
    secrets = list(
        filter(
            lambda x: x.model["type"] == "kubernetes.io/tls",
            oc.selector("secret", all_namespaces=options.all).objects(),
        )
    )

    for secret in secrets:
        if any(
            [
                secret.namespace() in options.ignore,
                secret.get_annotation("cert-manager.io/certificate-name"),
                any(map(lambda x: secret.namespace().startswith(x), options.ignore)),
            ]
        ):
            logging.debug(f"ignoring secret {secret.namespace()}/{secret.qname()}")
            continue
        try:
            logging.debug(f"decoding Certificate {secret.namespace()}/{secret.qname()}")
            cert = get_cert_object(secret.model["data"]["tls.crt"])
        except ValueError:
            logging.error(
                f"cannot load cert for {secret.namespace()} {secret.qname()} skipping"
            )
            continue
        if options.subject == "*":
            logging.debug("matching Certificate subject '*'")
            replace(secret, new_cert, new_key)
        elif options.subject is None:
            altnames = list(
                map(
                    lambda x: f"CN={x}",
                    new_cert.extensions.get_extension_for_oid(
                        x509.OID_SUBJECT_ALTERNATIVE_NAME
                    ).value.get_values_for_type(x509.GeneralName),
                )
            )
            altnames.append(f"CN={new_cert.subject.rfc4514_string()}")
            if cert.subject.rfc4514_string() in altnames:
                logging.debug(
                    f"matching Certificate due to subject or subjectAlternativeNames {cert.subject.rfc4514_string()}"
                )
                replace(secret, new_cert, new_key)
        elif f"CN={options.subject}" == cert.subject.rfc4514_string():
            logging.debug(f"matching exact subject CN={options.subject}")
            replace(secret, new_cert, new_key)
