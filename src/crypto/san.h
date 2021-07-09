// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#include <string>

// TODO: Rename file?
namespace crypto
{
  struct SubjectAltName
  {
    std::string san;
    bool is_ip;
  };
  DECLARE_JSON_TYPE(SubjectAltName);
  DECLARE_JSON_REQUIRED_FIELDS(SubjectAltName, san, is_ip);

  struct CertificateSubjectIdentity
  {
    std::vector<SubjectAltName> sans;
    std::string name;

    CertificateSubjectIdentity() = default;
    CertificateSubjectIdentity(const std::string& name) : name(name) {}
  };
  DECLARE_JSON_TYPE(CertificateSubjectIdentity);
  DECLARE_JSON_REQUIRED_FIELDS(CertificateSubjectIdentity, sans, name);
}
