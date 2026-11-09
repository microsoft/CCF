Nodes need less memory to install a startup snapshot when joining a service or during [disaster recovery](doc/operations/recovery.rst): its private domain is decrypted in place, and private recovery reuses the public tables already installed from it.
`ccf::crypto::KeyAesGcm::decrypt()` has a new overload which decrypts into caller-owned memory, including in place.
