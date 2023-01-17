# InstallCert
Allows to download a certificate from a specified site and import it in your keystore.

Old name: jksExportKey (version 1)

Compile & Build:
=================
mvn clean package

Run:
================
cd target

java -jar InstallCert-2.jar

Usage:
============
Start jar file with no arguments to get a summary:

java -jar InstallCert-2.jar

Usage:   java -jar <jar> [host[:port]] [passphrase] [outputFile] [inputFile]

Example: java -jar <jar> google.com changeit jssecacerts-fixed
