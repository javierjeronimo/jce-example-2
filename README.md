# jce-example-2

This repo includes some examples of how to perform programmatically in JAVA the following tasks:
* Create a JAVA keystore
* Create a V1 certificate
* Create a V3 certificate
* Create a Certificate Revocation List (CRL)
* Create a Certificate Signing Request
* Import a certificates to a specific JKS file
* Import a certificate to system's default JKS file
* Sign a JAR with a certificate present in a JKS file

It uses JAVA 8 JCE and Bouncy Castle and each point form the previous list has been implemented as a method in a class and a unit test to check its correct behaviour.

# Usage

```bash
mvn clean package
```
