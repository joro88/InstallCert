package com.miteff.util;

/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Please take into account that Oracle Corporation bought Sun Microsystems, so 
 * currently Oracle has rights over this code.
 */
import java.io.*;
import java.net.URL;

import java.security.*;
import java.security.cert.*;

import javax.net.ssl.*;

public class InstallCert {

public static void main(String[] args) throws Exception {

    String httpsUrl = null;
    String host;
    int port;
    char[] passphrase;
    String outputFileName = "jssecacerts";
    String inputFileName = "jssecacerts";
    
    if ((0< args.length ) && (args.length <=4)) {
        String[] splittedUri = args[0].split(":");
        host = splittedUri[0];
        port = (splittedUri.length == 1) ? 443 : Integer.parseInt(splittedUri[1]);
        String p = (args.length == 1) ? "changeit" : args[1];
        passphrase = p.toCharArray();
        httpsUrl = "https://" + host + ":" + port + "/";
        if (args.length >= 3) {
            outputFileName = args[2];
        }
    } else {
        System.out.println("Usage:   java -jar <jar> [host[:port]] [passphrase] [outputFile] [inputFile]");
        System.out.println("Example: java -jar <jar> google.com changeit jssecacerts-fixed");
        return;
    }

    File file = new File(inputFileName);
    if (file.isFile() == false) {
		System.out.println("Cannot open file '" + inputFileName + "'.");
        char SEP = File.separatorChar;
        File dir = new File(System.getProperty("java.home") + SEP + "lib"
                + SEP + "security");
        file = new File(dir, "jssecacerts");
		System.out.println("Fallback... trying to load file: " + file.getCanonicalPath());
        if (file.isFile() == false) {
            file = new File(dir, "cacerts");
            System.out.println("Fallback... trying to load file: " + file.getCanonicalPath());
        }
    }
    System.out.println("Loading KeyStore: " + file.getCanonicalPath());
    InputStream in = new FileInputStream(file);
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    ks.load(in, passphrase);
    in.close();

    SSLContext context = SSLContext.getInstance("TLS");
    TrustManagerFactory tmf = TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ks);
    X509TrustManager defaultTrustManager = (X509TrustManager) tmf
            .getTrustManagers()[0];
    SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
    context.init(null, new TrustManager[] { tm }, null);
    SSLSocketFactory factory = context.getSocketFactory();

    System.out.println("Opening connection to " + host + ":" + port + "...");

    URL url = new URL(httpsUrl);
//    Proxy p = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("176.9.240.109", 1080));
    HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
    conn.setSSLSocketFactory(factory);
    conn.setConnectTimeout(3000); // 3 seconds.
    conn.setReadTimeout(3000); // 3 seconds
    conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.0; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0");
    try {
        System.out.println("Starting SSL handshake...");
        conn.connect();
        System.out.println();
        System.out.println("No errors, certificate is already trusted");
    } catch (SSLException e) {
        System.out.println();
        e.printStackTrace(System.out);
    } finally {
        conn.disconnect();
    }

    X509Certificate[] chain = tm.chain;
    if (chain == null) {
        System.out.println("Could not obtain server certificate chain");
        return;
    }

    BufferedReader reader = new BufferedReader(new InputStreamReader(
            System.in));

    System.out.println();
    System.out.println("Server sent " + chain.length + " certificate(s):");
    System.out.println();
    MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    MessageDigest md5 = MessageDigest.getInstance("MD5");
    for (int i = 0; i < chain.length; i++) {
        X509Certificate cert = chain[i];
        System.out.println(" " + (i + 1) + " Subject "
                + cert.getSubjectDN());
        System.out.println("   Issuer  " + cert.getIssuerDN());
        sha1.update(cert.getEncoded());
        System.out.println("   sha1    " + toHexString(sha1.digest()));
        md5.update(cert.getEncoded());
        System.out.println("   md5     " + toHexString(md5.digest()));
        System.out.println();
    }

    System.out
    .println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
    String line = reader.readLine().trim();
    int k;
    try {
        k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
    } catch (NumberFormatException e) {
        System.out.println("KeyStore not changed");
        return;
    }

    X509Certificate cert = chain[k];
    String alias = host + "-" + (k + 1);
    ks.setCertificateEntry(alias, cert);

    
    OutputStream out = new FileOutputStream(outputFileName);
    ks.store(out, passphrase);
    out.close();
    
    System.out.println();
    System.out.println(cert);
    System.out.println();
    System.out.println("Added certificate to keystore '" + outputFileName + 
            "' using alias '" + alias + "'");
}

private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

private static String toHexString(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 3);
    for (int b : bytes) {
        b &= 0xff;
        sb.append(HEXDIGITS[b >> 4]);
        sb.append(HEXDIGITS[b & 15]);
        sb.append(' ');
    }
    return sb.toString();
}

private static class SavingTrustManager implements X509TrustManager {

    private final X509TrustManager tm;
    private X509Certificate[] chain;

    SavingTrustManager(X509TrustManager tm) {
        this.tm = tm;
    }

    public X509Certificate[] getAcceptedIssuers() {
//        throw new UnsupportedOperationException();
        return new X509Certificate[0];
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        throw new UnsupportedOperationException();
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        this.chain = chain;
        tm.checkServerTrusted(chain, authType);
    }
}
}