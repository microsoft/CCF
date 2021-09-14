Node State
==========

.. mermaid::

    graph TB;
        Uninitialized-->Initialized;
        Initialized-->PartOfNetwork;
        Initialized-->VerifyingSnapshot;
        VerifyingSnapshot-->Pending;
        Initialized-->Pending;
        Pending-->Pending;
        Pending-->PartOfNetwork;
        Initialized-->ReadingPublicLedger;
        ReadingPublicLedger-->PartOfPublicNetwork;
        PartOfPublicNetwork-->ReadingPrivateLedger;
        ReadingPrivateLedger-->PartOfNetwork;