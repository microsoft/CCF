Node State
==========

.. mermaid::

    graph TB;
        Uninitialized-- config -->Initialized;
        Initialized-- start -->PartOfNetwork;
        Initialized-- join from snapshot -->VerifyingSnapshot;
        VerifyingSnapshot-->Pending;
        Initialized-- join -->Pending;
        Pending-- poll status -->Pending;
        Pending-- trusted -->PartOfNetwork;
        Initialized-- recovery -->ReadingPublicLedger;
        ReadingPublicLedger-->PartOfPublicNetwork;
        PartOfPublicNetwork-- member recovery shares reassembly -->ReadingPrivateLedger;
        ReadingPrivateLedger-->PartOfNetwork;