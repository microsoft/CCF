// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

/* Status Codes */
#define HTTP_STATUS_MAP(XX) \
  XX(100, CONTINUE, "Continue") \
  XX(101, SWITCHING_PROTOCOLS, "Switching Protocols") \
  XX(102, PROCESSING, "Processing") \
  XX(200, OK, "OK") \
  XX(201, CREATED, "Created") \
  XX(202, ACCEPTED, "Accepted") \
  XX(203, NON_AUTHORITATIVE_INFORMATION, "Non-Authoritative Information") \
  XX(204, NO_CONTENT, "No Content") \
  XX(205, RESET_CONTENT, "Reset Content") \
  XX(206, PARTIAL_CONTENT, "Partial Content") \
  XX(207, MULTI_STATUS, "Multi-Status") \
  XX(208, ALREADY_REPORTED, "Already Reported") \
  XX(226, IM_USED, "IM Used") \
  XX(300, MULTIPLE_CHOICES, "Multiple Choices") \
  XX(301, MOVED_PERMANENTLY, "Moved Permanently") \
  XX(302, FOUND, "Found") \
  XX(303, SEE_OTHER, "See Other") \
  XX(304, NOT_MODIFIED, "Not Modified") \
  XX(305, USE_PROXY, "Use Proxy") \
  XX(307, TEMPORARY_REDIRECT, "Temporary Redirect") \
  XX(308, PERMANENT_REDIRECT, "Permanent Redirect") \
  XX(400, BAD_REQUEST, "Bad Request") \
  XX(401, UNAUTHORIZED, "Unauthorized") \
  XX(402, PAYMENT_REQUIRED, "Payment Required") \
  XX(403, FORBIDDEN, "Forbidden") \
  XX(404, NOT_FOUND, "Not Found") \
  XX(405, METHOD_NOT_ALLOWED, "Method Not Allowed") \
  XX(406, NOT_ACCEPTABLE, "Not Acceptable") \
  XX(407, PROXY_AUTHENTICATION_REQUIRED, "Proxy Authentication Required") \
  XX(408, REQUEST_TIMEOUT, "Request Timeout") \
  XX(409, CONFLICT, "Conflict") \
  XX(410, GONE, "Gone") \
  XX(411, LENGTH_REQUIRED, "Length Required") \
  XX(412, PRECONDITION_FAILED, "Precondition Failed") \
  XX(413, PAYLOAD_TOO_LARGE, "Payload Too Large") \
  XX(414, URI_TOO_LONG, "URI Too Long") \
  XX(415, UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type") \
  XX(416, RANGE_NOT_SATISFIABLE, "Range Not Satisfiable") \
  XX(417, EXPECTATION_FAILED, "Expectation Failed") \
  XX(421, MISDIRECTED_REQUEST, "Misdirected Request") \
  XX(422, UNPROCESSABLE_ENTITY, "Unprocessable Entity") \
  XX(423, LOCKED, "Locked") \
  XX(424, FAILED_DEPENDENCY, "Failed Dependency") \
  XX(426, UPGRADE_REQUIRED, "Upgrade Required") \
  XX(428, PRECONDITION_REQUIRED, "Precondition Required") \
  XX(429, TOO_MANY_REQUESTS, "Too Many Requests") \
  XX(431, REQUEST_HEADER_FIELDS_TOO_LARGE, "Request Header Fields Too Large") \
  XX(451, UNAVAILABLE_FOR_LEGAL_REASONS, "Unavailable For Legal Reasons") \
  XX(500, INTERNAL_SERVER_ERROR, "Internal Server Error") \
  XX(501, NOT_IMPLEMENTED, "Not Implemented") \
  XX(502, BAD_GATEWAY, "Bad Gateway") \
  XX(503, SERVICE_UNAVAILABLE, "Service Unavailable") \
  XX(504, GATEWAY_TIMEOUT, "Gateway Timeout") \
  XX(505, HTTP_VERSION_NOT_SUPPORTED, "HTTP Version Not Supported") \
  XX(506, VARIANT_ALSO_NEGOTIATES, "Variant Also Negotiates") \
  XX(507, INSUFFICIENT_STORAGE, "Insufficient Storage") \
  XX(508, LOOP_DETECTED, "Loop Detected") \
  XX(510, NOT_EXTENDED, "Not Extended") \
  XX(511, NETWORK_AUTHENTICATION_REQUIRED, "Network Authentication Required")

enum http_status
{
#define XX(num, name, string) HTTP_STATUS_##name = num,
  HTTP_STATUS_MAP(XX)
#undef XX
};

/* Returns a string version of the HTTP status code. */
static inline const char* http_status_str(enum http_status s)
{
  switch (s)
  {
#define XX(num, name, string) \
  case HTTP_STATUS_##name: \
    return string;
    HTTP_STATUS_MAP(XX)
#undef XX
    default:
      return "<unknown>";
  }
}
