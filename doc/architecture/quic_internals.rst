QUIC Internals
==============

Overview
~~~~~~~~

We are planning to support :term:`QUIC` endpoints in CCF in the same way that we already have 'TCP' ones. HTTP over QUIC is also known as 'HTTP/3': An evolution of 'HTTP/2', using 'QUIC' instead of 'TCP'.

As 'QUIC' is implemented over 'UDP' packets and has its own internal implementation of :term:`TLS`, we cannot reuse most of the existing infrastructure for endpoint communication and encryption (see :ref:`architecture/tls_internals:TLS Internals`).

This project will require changes in three sections of CCF:

- The host side will need a UDP connection to receive packages and send them to the ring buffer, to registered QUIC REST nodes.
- The ring buffer will need to understand about 'quic_*' package types (similar to 'tls_*' ones).
- The enclave side will need an HTTP/3 / QUIC endpoint stack, which cannot use the existing ``tls::Context`` for reading and writing.

Host Side
~~~~~~~~~

On the host side, we'll need an implementation of QUIC in the same structure as the existing 'TCP' one (``src/host/tcp.h``). That will be responsible for opening connections, sending and receiving UDP packets over the network sockets.

We'll also have to modify the main logic (``src/host/main.cpp``) to choose between TCP and QUIC appropriately, and create the right type of enclave. It's not yet clear if we need to have both TCP and QUIC endpoints in the same enclave or if one or the other would be enough.

If both, then the main doesn't change much and we need to multiplex the incoming TCP and UDP packets through the same ring buffer to the enclave. If one of the other, then main decides which one to create and communicated via a single protocol.

Ring Buffer Side
~~~~~~~~~~~~~~~~

This is the simplest change, as it just needs to "know" about QUIC message types. This is basically the same as TLS messages, for example: 'quic_inbound', 'quic_outbound', etc.

Both host and enclave will send ring buffer messages using those types (via the ``RINGBUFFER_TRY_WRITE_MESSAGE`` macro) and the data should pass unaltered.

Enclave Side
~~~~~~~~~~~~

This is the biggest change. We'll need to create a new 'HTTP3Session' that will listen for 'quic_inbound' messages and communicate with the 'QUICSession' layer (likely a super-class) that will perform the same job as 'TLSSession'. However, this is where the similarities end.

While TLS is a layer over TCP, QUIC's encryption is entangled with data transmission in a much closer way.

First, with QUIC, every connection begins with a TLS handshake, and during the handshake there can be different keys to exchange data as well (0-RTT vs 1-RTT). So, not only a QUIC implementation must keep buffers of incomplete data messages, but it can potentially also have to keep different keys to decrypt different parts of those messages. Once the connection is established, all UDP packets are encrypted.

Second, all of the connection control that TCP provides, UDP doesn't. So QUIC has to implement that on its own, which leads to a complex state machine (when compared to the TLS part only in TCP). An attempt at putting all parts of the state machine can be seen in figure 1, but a complete picture can be seen on both `QUIC <https://www.rfc-editor.org/rfc/rfc9000.html>`_ and `QUIC+TLS <https://www.rfc-editor.org/rfc/rfc9001.html>`_ RFCs.

.. image:: QUIC.png
   :alt: figure 1

Finally, because of the differences (and the need for special support), QUIC can't just use the OpenSSL calls as we do in TCP. It implements a number of special callbacks that need to be registered at the connection creation, that will know which keys have been exchanged, which stage of the handshake it is, etc.

Those callbacks are implemented in `ngtcp2 <https://nghttp2.org/ngtcp2/programmers-guide.html>`_ for example, but even that level is still too low level for us to map to our current endpoint structure.

Luckily, there's an HTTP/3 implementation on top of QUIC from `nghttp3 <https://nghttp2.org/nghttp3/programmers-guide.html>`_ which has a more high level API. It uses QUIC's callbacks and also add a few of it own.

However, upon closer inspection, both libraries assume that the connection is established by the same part that reads and writes, which is not true in our separated world on each side of the ring-buffer.
