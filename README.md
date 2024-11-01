# InstallCert
Java tool which allows to download a certificate from a specified site and import it in your keystore. It could be executed on Linux and on Windows / DOS.

# Help:
Start jar file with no arguments to get a summary:

> java -jar InstallCert-2.jar

# Usage
> java -jar <jar> [host[:port]] [passphrase] [outputFile] [inputFile]

# Example usage: 
> java -jar InstallCert-2.jar google.com changeit jssecacerts-fixed

# Compile & Build:
> mvn clean package

# More information
[https://dev.miteff.com/](https://dev.miteff.com/)

