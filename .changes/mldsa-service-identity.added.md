With OpenSSL 3.5 or newer, services issue ML-DSA service certificates on start or recovery, selected by `service_mldsa_parameter_set` and renewed through `set_pq_service_certificate_validity`.
Such services only accept nodes with ML-DSA support; see the [7.x to 8.x migration guide](doc/releases/migration_7_x_to_8_x.rst).
