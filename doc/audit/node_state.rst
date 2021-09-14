Node State
==========

.. mermaid::

    graph TB;
        Uninitialized-->Initialized;
        Initialized-->PartOfNetwork;
        Initialized-->VerifyingSnapshot;
        Initialized-->Pending;
        Pending-->Pending;
        Initialized-->ReadingPublicLedger;
        ReadingPublicLedger-->PartOfPublicNetwork;
        PartOfPublicNetwork-->ReadingPrivateLedger;
        ReadingPrivateLedger-->PartOfNetwork;