This module interfaces with the TLS implementation of Oracle JDK8 to
provide an implementation of ALPN.

# How Grizzly Uses This Module

Grizzly has the concept of an
[`AddOn`](https://github.com/javaee/grizzly/blob/e0e9200479851078d9cf2bad1cf29fa72f525437/modules/http-server/src/main/java/org/glassfish/grizzly/http/server/AddOn.java).
This facility allows Grizzly to be extended using an implementation of
the Chain of Responsibility design pattern.  In general, an `AddOn`
implementation will insert one or more `Filter` implementations into the
`FilterChain` which is used to process HTTP requests and cause HTTP
responses to be sent.

Grizzly itself uses this `AddOn` concept to provide HTTP/2 support, in
the form of
[`Http2AddOn`](https://github.com/javaee/grizzly/blob/e0e9200479851078d9cf2bad1cf29fa72f525437/modules/http2/src/main/java/org/glassfish/grizzly/http2/Http2AddOn.java)
This `AddOn` implementation inserts some filters in the chain using the
proper order to ensure that ALPN concerns are handled first, and then
the HTTP/2 protocol is handled.  The former is of interest here.  The
`setup` override in the `Http2AddOn` takes the following actions if the
current connection is secure (that is, it is supposed to be using ALPN).

* Use the `addHandshakeListener` method of the existing
  [`SSLBaseFilter`](https://github.com/javaee/grizzly/blob/e0e9200479851078d9cf2bad1cf29fa72f525437/modules/grizzly/src/main/java/org/glassfish/grizzly/ssl/SSLBaseFilter.java)
  to cause an ALPN specific SSL handshake listener to be added to the
  existing list of listeners that are invoked when an
  [SSL Handshake](https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.1.0/com.ibm.mq.doc/sy10660_.htm)
  happens.

    Grizzly's handshake listener has several methods, but the only one
    used is `onStart`.  This obtains the JDK `SSLEngine` and takes
    different action depending on the return from
    [`getUseClientMode()`](https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/SSLEngine.html#getUseClientMode--).
    The `grizzly-npn` module provides
    [`AlpnClientNegotiator`](https://github.com/javaee/grizzly-npn/blob/bfa03914bf4222fd22f7710d1deb352b55de0b82/api/src/main/java/org/glassfish/grizzly/npn/AlpnClientNegotiator.java)
    and
    [`AlpnServerNegotiator`](https://github.com/javaee/grizzly-npn/blob/bfa03914bf4222fd22f7710d1deb352b55de0b82/api/src/main/java/org/glassfish/grizzly/npn/AlpnServerNegotiator.java)
    for these two cases.

    By the time `onStart` is invoked, the handshake listener will have been initialized with 
