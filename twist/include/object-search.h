#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

#include <ldap.h>

namespace ObjectSearch
{
    //
    // [SECTION] Types
    //

    enum class AttributeType
    {
        STRING,
        BINARY_SID,
        FILETIME,
        MULTI_VALUE,
        ENUMERATION,
        BINARY_SECURITY_DESCRIPTOR
    };

    struct Attribute
    {
        const char *name;
        AttributeType type;
    };

    struct Entry
    {
        const char *objectClass;
        std::vector<Attribute> attributes;
    };

    using Map = std::unordered_map<std::string, Entry>;

    //
    // [SECTION] Functions
    //

    std::string parseFiletime(const struct berval *value)
    {
        if (value == nullptr)
            return "Invalid";

        uint64_t filetime{std::stoull(value->bv_val)};

        if (filetime == 0 || filetime == 0x7FFFFFFFFFFFFFFF)
            return "Never";

        const uint64_t FILETIME_TO_UNIX_OFFSET{11644473600ULL};
        uint64_t seconds{(filetime / 10000000ULL) - FILETIME_TO_UNIX_OFFSET};

        std::time_t time{static_cast<std::time_t>(seconds)};
        std::tm *tm{std::gmtime(&time)};

        std::ostringstream oss;
        oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    }

    std::string parseSid(const struct berval *value)
    {
        if (value == nullptr || value->bv_len < 8)
            return "Invalid";

        const uint8_t *sid{reinterpret_cast<uint8_t *>(value->bv_val)};

        if (sid[0] != 1)
            return "Invalid";

        uint8_t subauth_count{sid[1]};

        uint64_t authority = 0;
        for (int i = 0; i < 6; i++)
            authority = (authority << 8) | sid[2 + i];

        std::ostringstream oss;
        oss << "S-" << static_cast<int>(sid[0]) << "-" << authority;

        for (int i = 0; i < subauth_count; i++)
        {
            uint32_t subauth{};
            int offset{8 + (i * 4)};

            subauth = sid[offset] |
                      (sid[offset + 1] << 8) |
                      (sid[offset + 2] << 16) |
                      (sid[offset + 3] << 24);

            oss << "-" << subauth;
        }

        return oss.str();
    }

    std::string parseSecurityDescriptor(const struct berval *value)
    {
        std::cout << value->bv_val << "\n";
        return "";
    }
};