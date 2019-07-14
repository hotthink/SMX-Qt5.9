#ifndef _BASE64_H_WSQ
#define _BASE64_H_WSQ

#include <string>

std::string base64_encode(unsigned char const*, unsigned int len);
std::string base64_decode(std::string const& s);
std::string base64_encode_pic(const char *bytes_to_encode, unsigned int in_len);

#endif /* _BASE64_H_WSQ */
