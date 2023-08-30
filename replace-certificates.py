#!/usr/bin/python

import openshift as oc
from base64 import b64decode, b64encode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization
from datetime import datetime

import logging
import os
import sys
import optparse

now = datetime.now()


def get_cert_object(data):
    logging.debug(f"loading certificate")
    cert = x509.load_pem_x509_certificate(b64decode(data), default_backend())
    return cert


def replace_secret(secret, cert, new_cert, new_key):
    if any([new_cert == None, new_key == None]):
        logging.debug("skipping due to no new cert specified")
        return
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


def replace_route(route, cert, new_cert, new_key):
    if any([new_cert == None, new_key == None]):
        logging.debug("skipping due to no new cert specified")
        return
    logging.info(
        f"replacing {route.namespace()} {route.qname()} {cert.subject.rfc4514_string()}"
        + f" (expire {cert.not_valid_after}) with {new_cert.subject.rfc4514_string()} "
        + f"({new_cert.not_valid_before}-{new_cert.not_valid_after})"
    )
    if not options.dryrun:
        route.model.spec.tls.key = b64encode(
            new_key.private_bytes(
                Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode("utf8")
        route.model.spec.tls.certificate = b64encode(
            new_cert.public_bytes(Encoding.PEM)
        ).decode("utf8")
        oc.replace(route)
    else:
        logging.debug("skipping replace due to dry-run mode")


def replace_configmap(configmap, cmkey, cert, new_cert, new_key):
    if any([new_cert == None, new_key == None]):
        logging.debug("skipping due to no new cert specified")
        return
    logging.debug(
        f"replacing {configmap.namespace()} {configmap.qname()} {cert.subject.rfc4514_string()}"
        + f" (expire {cert.not_valid_after}) with {new_cert.subject.rfc4514_string()} "
        + f"({new_cert.not_valid_before}-{new_cert.not_valid_after})"
    )
    if not options.dryrun:
        try:
            configmap.model.data[cmkey] = b64encode(
                new_key.private_bytes(
                    Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ).decode("utf8")
        except Exception:
            logging.error(f"configMap key {cmkey} not existing, cannot replace")
            return
        oc.replace(configmap)
    else:
        logging.debug("skipping replace due to dry-run mode")


def do_secrets():
    logging.debug("API query for secrets, type 'kubernetes.io/tls'")
    secrets = list(
        filter(
            lambda x: x.model.type == "kubernetes.io/tls",
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
            if options.warn > 0:
                if (cert.not_valid_after - now).days <= options.warn:
                    logging.info(
                        f"{secret.namespace()}/{secret.qname()} {cert.subject} expires in {cert.not_valid_after - now}"
                    )
        except ValueError:
            logging.error(
                f"cannot load cert for {secret.namespace()} {secret.qname()} skipping"
            )
            continue
        if options.subject == "*":
            logging.debug("matching Certificate subject '*'")
            replace_secret(secret, cert, new_cert, new_key)
        elif options.subject is None:
            try:
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
                    replace_secret(secret, cert, new_cert, new_key)
            except Exception:
                pass
        elif f"CN={options.subject}" == cert.subject.rfc4514_string():
            logging.debug(f"matching exact subject CN={options.subject}")
            replace_secret(secret, cert, new_cert, new_key)


def do_routes():
    logging.debug("API query for routes, for tls 'certificats'")
    try:
        routes = list(
            filter(
                lambda x: x.model.spec.tls.certificate,
                oc.selector("route", all_namespaces=options.all).objects(),
            )
        )
    except Exception:
        logging.info("no route objects, most likely vanilla k8s")
        return

    for route in routes:
        if any(
            [
                route.namespace() in options.ignore,
                route.get_annotation("cert-manager.io/certificate-name"),
                route.get_annotation("sealedsecrets.bitnami.com/sealed-secrets-key"),
                any(map(lambda x: route.namespace().startswith(x), options.ignore)),
            ]
        ):
            logging.debug(f"ignoring secret {route.namespace()}/{route.qname()}")
            continue
        try:
            logging.debug(f"decoding Certificate {route.namespace()}/{route.qname()}")
            if isinstance(route.model.spec.tls.certificate, oc.MissingModel):
                logging.info(
                    f"skipping route {route.namespace()}/{route.qname()} no certificate in spec"
                )
                continue
            cert = get_cert_object(
                b64encode(route.model.spec.tls.certificate.encode("utf8"))
            )
            if options.warn > 0:
                if (cert.not_valid_after - now).days <= options.warn:
                    logging.info(
                        f"{route.namespace()}/{route.qname()} {cert.subject} expires in {cert.not_valid_after - now}"
                    )
        except ValueError:
            logging.error(
                f"cannot load cert for {route.namespace()} {route.qname()} skipping"
            )
            continue
        if options.subject == "*":
            logging.debug("matching Certificate subject '*'")
            replace_route(route, cert, new_cert, new_key)
        elif options.subject is None:
            try:
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
                    replace_route(route, cert, new_cert, new_key)
            except Exception:
                pass
        elif f"CN={options.subject}" == cert.subject.rfc4514_string():
            logging.debug(f"matching exact subject CN={options.subject}")
            replace_route(route, cert, new_cert, new_key)


def do_configMaps():
    logging.debug("API query for configMaps, with 'certificats'")
    configmaps = list(
        filter(
            lambda y: len(
                set(map(lambda x: x.split(".")[-1], y.model.data.keys())).intersection(
                    set(["crt", "pem", "key", "cert"])
                )
            ),
            oc.selector("configMaps", all_namespaces=options.all).objects(),
        )
    )

    for configmap in configmaps:
        if any(
            [
                configmap.namespace() in options.ignore,
                configmap.get_annotation("cert-manager.io/certificate-name"),
                configmap.get_annotation(
                    "sealedsecrets.bitnami.com/sealed-secrets-key"
                ),
                any(map(lambda x: configmap.namespace().startswith(x), options.ignore)),
            ]
        ):
            logging.debug(
                f"ignoring secret {configmap.namespace()}/{configmap.qname()}"
            )
            continue
        try:
            logging.debug(
                f"decoding Certificate {configmap.namespace()}/{configmap.qname()}"
            )
            for cmkey in configmap.model.data.keys():
                try:
                    cert = get_cert_object(
                        b64encode(configmap.model.data[cmkey].encode("utf8"))
                    )
                except Exception as certerr:
                    # ignore none parseable certificates
                    pass
                if options.warn > 0:
                    if (cert.not_valid_after - now).days <= options.warn:
                        logging.info(
                            f"{configmap.namespace()}/{configmap.qname()} {cert.subject} expires in {cert.not_valid_after - now}"
                        )
                if options.subject == "*":
                    logging.debug("matching Certificate subject '*'")
                    replace_configmap(configmap, cmkey, cert, new_cert, new_key)
                elif options.subject is None:
                    try:
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
                            replace_configmap(configmap, cmkey, cert, new_cert, new_key)
                    except Exception:
                        pass
                elif f"CN={options.subject}" == cert.subject.rfc4514_string():
                    logging.debug(f"matching exact subject CN={options.subject}")
                    replace_configmap(configmap, cmkey, cert, new_cert, new_key)
        except ValueError:
            logging.error(
                f"cannot load cert for {configmap.namespace()} {configmap.qname()} skipping"
            )
            continue


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
    parser.add_option("-w", "--warn", type=int, default=0)
    parser.add_option(
        "--yes-I-really-really-mean-it",
        dest="safety",
        action="store_true",
        default=False,
    )
    parser.add_option(
        "--no-secrets", dest="nosecrets", action="store_true", default=False
    )
    parser.add_option(
        "--no-routes", dest="noroutes", action="store_true", default=False
    )
    parser.add_option(
        "--no-configmaps", dest="noconfigmaps", action="store_true", default=False
    )
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
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    if all(
        [options.all, options.subject == "*", not options.safety, options.warn == 0]
    ):
        print(f"you specified to replace all subjects in all namespaces")
        print(f"this would render your cluster useless")
        print(f"please privde --yes-I-really-really-mean-it accordingly")
        sys.exit(1)
    if all([options.all, options.subject == "*", options.safety, options.warn == 0]):
        print(f"still I cannot fulfill your request")
        sys.exit(1)

    NEWCERT = options.cert
    NEWKEY = options.key
    if options.warn == 0:
        if any([NEWCERT is None, NEWKEY is None]):
            logging.error("you need to specify --cert and --key")
            parser.print_help()
            sys.exit(1)

        if not os.path.isfile(NEWCERT):
            logging.error(f"unable to open Certificate {NEWCERT}, no such file")
            sys.exit(1)
        try:
            new_cert = x509.load_pem_x509_certificate(
                open(NEWCERT).read().encode("utf8")
            )
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
    else:
        new_cert = None
        new_key = None

    if not options.context is None:
        logging.debug(f"using context {options.context}")
        oc.use_config_context(options.context)
    if not options.all:
        logging.debug(f"using namespace {options.namespace}")
        oc.project(options.namespace)
    else:
        logging.debug(f"using all namespaces")

    if not options.nosecrets:
        do_secrets()
    if not options.noroutes:
        do_routes()
    if not options.noconfigmaps:
        do_configMaps()
