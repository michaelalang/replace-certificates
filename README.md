# Kubernetes/Openshift Certificate replacement automation helper

This little script is intended to support you replacing SSL Certificate secrets that are not handled yet by cert-manager or another Gitops Controller.
Due to many possibilties on how a tls secret is referenced and utilized by some workload, I did not choose to include a automated `rollout restart` of the deployment referencing the secret.
(like traefik uses TLSStore objects, projected secrets ... the chance to hit the wrong one is too high)

## Plans, ToDo's

* create git repository out of what would be changed to integrate the changes into a Gitops controller
* maybe integrate manual authentication to avoid the need to call `oc login` on switching context without certificates

## installing the requirements for the script

It should be fairly simple to use a s2i image to not taint the system you want the script to run at. Still, with being multi context and namespace aware, the amount of additional maps for the certificates and keys 
one might need, was just not worth the effort writing a default Dockerfile.

### prerequisits 

* a valid `.kube/config` with the context and certificates/tokens for authentication

### install python's requirements openshift-client and cryptography

on RHEL bases system cryptography comes as RPM and does not need to be installed/updated.

```
# pip install --user -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: openshift-client in /home/milang/.local/lib/python3.9/site-packages (from -r requirements.txt (line 1)) (1.0.19)
Requirement already satisfied: cryptography in /usr/lib64/python3.9/site-packages (from -r requirements.txt (line 2)) (36.0.1)
Requirement already satisfied: pyyaml in /usr/lib64/python3.9/site-packages (from openshift-client->-r requirements.txt (line 1)) (5.4.1)
Requirement already satisfied: six in /home/milang/.local/lib/python3.9/site-packages (from openshift-client->-r requirements.txt (line 1)) (1.16.0)
Requirement already satisfied: paramiko in /home/milang/.local/lib/python3.9/site-packages (from openshift-client->-r requirements.txt (line 1)) (2.12.0)
Requirement already satisfied: cffi>=1.12 in /usr/lib64/python3.9/site-packages (from cryptography->-r requirements.txt (line 2)) (1.14.5)
Requirement already satisfied: pycparser in /usr/lib/python3.9/site-packages (from cffi>=1.12->cryptography->-r requirements.txt (line 2)) (2.20)
Requirement already satisfied: pynacl>=1.0.1 in /home/milang/.local/lib/python3.9/site-packages (from paramiko->openshift-client->-r requirements.txt (line 1)) (1.5.0)
Requirement already satisfied: bcrypt>=3.1.3 in /home/milang/.local/lib/python3.9/site-packages (from paramiko->openshift-client->-r requirements.txt (line 1)) (4.0.1)
Requirement already satisfied: ply==3.11 in /usr/lib/python3.9/site-packages (from pycparser->cffi>=1.12->cryptography->-r requirements.txt (line 2)) (3.11)
user = True
home = None
root = None
prefix = None
```

## replacing certificates in your Cluster

**NOTE** always run with `--dry-run` first to ensure, you are not replacing kube-system or openshift-\* namespace certificates you do not want to touch

### using ignore to remove namespaces we do not want to touch

the script takes options and additional parameters which are used for `ignoring` namespaces it should not touch
for example if we want to exclude particular namespaces, we can execute the script with 

```
$ ./replace-certificates -c ... -k ... --dry-run -A openshift-ingress openshift-kube-apiserver openshift-apiserver
```

the same mechanism works for namespaces starting with the ignore string. To ignore all openshift namespaces use

```
$ ./replace-certificates -c ... -k ... --dry-run -A openshift- 
```

## changing context or limiting namespaces to act on

the script takes the same options like `kubectl` or `oc` for working in a particular context or limit it to a certain namespace

```
# working in context cluster1 on all namespaces
$ ./replace-certificates --context cluster1 -A

# working in context cluster2 limited to namespace default
$ ./replace-certificates --context cluster2 -n default
```

**NOTE** as with `kubectl` and `oc` the namespace and context options do not support wildcards 

### operator handled certificates 

with `cert-bot` handling Certificates in the future, all secrets with the annotation `cert-manager.io/certificate-name` are ignored as well no matter if the namespace is included or not.
Mixing `cert-bot` handled and self handled certificates is expected to work with the script.

So far, no other Operator create certificates are handled right now.

### replacing a renewed certificate

this scenario handles certificates in a renewal, meaning, the subject and subjectAlternativeNames do not change 

```
# assuming your new certificates are in `./certificates/*` 
# as example we use the let's Encrypt naming for certificates fullchain.pem and privatekey.pem
$ ./replace-certificates.py -c ./certificates/fullchain.pem -k ./certificates/privkey.pem --dry-run -A 
INFO:root:replacing istio-system secret/istio-ingressgateway-certs CN=*.apps.cluster1.example.com (expire 2023-07-01 14:38:16) with CN=*.apps.cluster1.example.com (2023-07-01 14:38:16-2023-09-29 14:38:15)
INFO:root:replacing openshift-gitops secret/openshift-gitops-tls CN=*.apps.cluster1.example.com (expire 2023-07-01 14:38:16) with CN=*.apps.cluster1.example.com (2023-07-01 14:38:16-2023-09-29 14:38:15)
INFO:root:replacing openshift-ingress secret/tls-home CN=*.apps.cluster1.example.com (expire 2023-07-01 14:38:16) with CN=*.apps.cluster1.example.com (2023-07-01 14:38:16-2023-09-29 14:38:15)
INFO:root:replacing production secret/istio-ingressgateway-certs CN=*.apps.cluster1.example.com (expire 2023-07-01 14:38:16) with CN=*.apps.cluster1.example.com (2023-07-01 14:38:16-2023-09-29 14:38:15)
```

### replacing certificates matching a specific subject

this scenario handles certificate replacement matching a specific subject like `*` all or `*.example.com` to replace those with `*.cluster3.example.com` 

```
$ ./replace-certificates.py -c ./certificates/fullchain.pem -k ./certificates/privkey.pem --dry-run -A  -s '*'
INFO:root:replacing cnpg-system secret/cnpg-webhook-cert CN=cnpg-webhook-service.cnpg-system.svc (expire 2023-09-26 15:29:05) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing default secret/traefik-ingress-ssl CN=*.example.com (expire 2023-07-17 06:14:03) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing istio-system secret/frontend-gateway CN=*.example.com (expire 2023-09-29 14:37:13) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing istio-system secret/frontend-gateway-cluster3 CN=*.cluster3.example.com (expire 2023-09-29 14:38:37) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing istio-system secret/istio-ingressgateway-certs CN=*.cluster3.example.com (expire 2023-09-29 14:38:37) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing kube-system secret/sealed-secrets-keyn4ht2  (expire 2032-12-26 14:11:04) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing kube-system secret/traefik-ingress-ssl CN=*.cluster3.example.com (expire 2023-09-29 14:38:37) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing postgres secret/cluster-sso-cluster3-replication CN=streaming_replica (expire 2023-09-26 15:29:29) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing postgres secret/cluster-sso-cluster3-server CN=cluster-sso-cluster3-rw (expire 2023-09-26 15:29:29) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing quay secret/cluster-cluster3-replication CN=streaming_replica (expire 2023-09-26 19:09:44) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing quay secret/cluster-cluster3-server CN=cluster-cluster3-rw (expire 2023-09-26 19:09:44) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
INFO:root:replacing quay secret/quay-ssl-postgres CN=quay (expire 2023-10-12 12:37:47) with CN=*.cluster3.example.com (2023-07-01 14:41:20-2023-09-29 14:41:19)
```

### Reporting on expire date only

without specifying `cert` and `key` and instead setting `--warn` to a value in days (eq `--warn 30` for 30 days from today) the script will report Certificates which have less valid days left than set in the warn option.

```
$ ./replace-certificates.py -A --warn 30
INFO:root:istio-system/secret/istio-ingressgateway-certs <Name(CN=*.apps.example.com)> expires in 30 days, 7:23:47.992904
INFO:root:openshift-config-managed/secret/kube-controller-manager-client-cert-key <Name(CN=system:kube-controller-manager)> expires in 17 days, 20:48:32.992904
INFO:root:openshift-config-managed/secret/kube-scheduler-client-cert-key <Name(CN=system:kube-scheduler)> expires in 17 days, 20:48:36.992904
INFO:root:openshift-gitops/secret/openshift-gitops-tls <Name(CN=gitops.apps.example.com)> expires in 30 days, 7:23:47.992904
...
```

