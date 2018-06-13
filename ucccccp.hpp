/*
 * utfccp.hpp
 *
 *  Created on: Jul 1, 2017
 *      Author: nullifiedcat
 */

#pragma once

#include <string>
#include <ctime>
#include <cmath>
#include "base64.h"

/*
 *  Usage:
 *  	To send message, call ucccccp::encrypt on text of the message and send the result to chat
 *  	When receiving a message, call ucccccp::validate, and if it succeeds, call ucccccp::decrypt and show the result
 *
 *		To include this to your project, add this file and base64.h to your source and include this file.
 *
 *		Feel free to suggest improvements! Use the github repo (https://github.com/nullifiedcat/ucccccp) to submit issues.
 *
 *  General structure of message:
 *  	!![version][data]
 *  		version: char from base64 alphabet
 *  		data: depends on version
 *
 * 	Versions:
 * 	A:
 * 		!!A[data][checksum]
 * 			data = base64(crappy_xorstring(input))
 *			checksum = crappy_checksum(input)
 *		Not time based, useful for normal daily use
 *
 *	B:
 *		!!B[data][checksum]
 *			data = base64(crappy_xorstringb(input))
 *			checksum = crappy_checksum(input)
 *		Uses time based encryption, useful for fast and more secure exchanges
 */

namespace ucccccp
{

inline std::string crappy_checksum(const std::string &in)
{
    int s = 0, ss = 0;
    for (int i = 0; i < in.length(); i += 2)
    {
        s += (int) in[i];
        if (i < in.length() - 1)
            ss += (int) in[i + 1] * (int) in[i + 1];
    }
    return { kBase64Alphabet[s % 64], kBase64Alphabet[ss % 64] };
}

inline std::string crappy_xorstring(const std::string &in)
{
    std::string out;
    for (int i = 0; i < in.length(); i++)
    {
        // 696969th prime, 13371337th prime
        out.push_back(in[i] ^ ((10522103 * in.length()) + i * 244053389 % 256));
    }
    return out;
}

inline std::string crappy_xorstringb(const std::string &in,
                                     unsigned int timeBlocks)
{
    std::string out;
    for (int i = 0; i < in.length(); i++)
    {
        // 323969th prime (CA7 + 69), 829289th (CA71337) prime
        out.push_back(in[i] ^ ((4623413 * in.length()) + i * 12673579 % 256 +
                               timeBlocks));
    }
    return out;
}

/*
 * validate
 * A
 * B
 */
inline bool validate(const std::string &in)
{
    if (in.length() < 4)
        return false;
    if (in[0] != '!' || in[1] != '!')
        return false;
    switch (in[2])
    {
    case 'A':
    case 'B':
        return crappy_checksum(in.substr(3, in.length() - 5)) ==
               in.substr(in.length() - 2);
    default:
        return false;
    }
}

/*
 * 	decrypt
 * 	A
 * 	B
 */
inline std::string decrypt(const std::string &in)
{
    switch (in[2])
    {
    case 'A':
    {
        std::string b64;
        Base64::Decode(in.substr(3, in.length() - 5), &b64);
        return crappy_xorstring(b64);
    }
    case 'B':
    {
        std::time_t time                       = std::time(nullptr);
        unsigned int twoMinuteBlocksSinceEpoch = ceil(time / 30);
        std::string b64;
        for (int i = -1; i < 2; i++)
        {
            Base64::Decode(in.substr(3, in.length() - 5), &b64);
            std::string output =
                crappy_xorstringb(b64, twoMinuteBlocksSinceEpoch + i);
            if (output.substr(0, 3) == "ucp")
                return output.substr(3);
        }
        return "Attempt at ucccccping and failing";
    }
    default:
        return "Unsupported version";
    }
}

/*
 * 	encrypt
 * 		falls back to A if version is invalid
 * 	A
 * 	B
 */
inline std::string encrypt(const std::string &in, char version = 'A')
{
    switch (version)
    {
    default:
    case 'A':
    {
        std::string b64;
        Base64::Encode(crappy_xorstring(in), &b64);
        return "!!A" + b64 + crappy_checksum(b64);
    }
    case 'B':
    {
        std::time_t time                       = std::time(nullptr);
        unsigned int twoMinuteBlocksSinceEpoch = ceil(time / 30);
        std::string b64;
        Base64::Encode(crappy_xorstringb("ucp" + in, twoMinuteBlocksSinceEpoch),
                       &b64);
        return "!!B" + b64 + crappy_checksum(b64);
    }
    }
}
}
