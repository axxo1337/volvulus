#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

#include <ldap.h>

#include "windows-types.h"

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
        SecurityDescriptorRelative *p_security_descript_relative{reinterpret_cast<SecurityDescriptorRelative *>(value->bv_val)};
        SID *p_owner{reinterpret_cast<SID *>(value->bv_val + p_security_descript_relative->owner_offset)};
        SID *p_group{reinterpret_cast<SID *>(value->bv_val + p_security_descript_relative->group_offset)};

        if (p_security_descript_relative->dacl_offset != 0)
        {
            ACL *p_dacl{reinterpret_cast<ACL *>(value->bv_val + p_security_descript_relative->dacl_offset)};

            if (reinterpret_cast<uint64_t>(p_dacl) < reinterpret_cast<uint64_t>(value->bv_val + value->bv_len))
            {
                ACE_Header *p_ace_header{reinterpret_cast<ACE_Header *>(
                    reinterpret_cast<uint8_t *>(p_dacl) + sizeof(ACL))};

                for (int i{}; i < p_dacl->ace_count; i++)
                {
                    switch (p_ace_header->type)
                    {
                    case ACE_Type::ACCESS_ALLOWED_ACE_TYPE:
                        std::cout << "ACCESS_ALLOWED_ACE\n";
                        break;
                    case ACE_Type::ACCESS_DENIED_ACE_TYPE:
                        std::cout << "ACCESS_DENIED_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_AUDIT_ACE_TYPE:
                        std::cout << "SYSTEM_AUDIT_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_ALARM_ACE_TYPE:
                        std::cout << "SYSTEM_ALARM_ACE (Reserved)\n";
                        break;
                    case ACE_Type::ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
                        std::cout << "ACCESS_ALLOWED_COMPOUND_ACE (Reserved)\n";
                        break;
                    case ACE_Type::ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                        std::cout << "ACCESS_ALLOWED_OBJECT_ACE\n";
                        break;
                    case ACE_Type::ACCESS_DENIED_OBJECT_ACE_TYPE:
                        std::cout << "ACCESS_DENIED_OBJECT_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                        std::cout << "SYSTEM_AUDIT_OBJECT_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_ALARM_OBJECT_ACE_TYPE:
                        std::cout << "SYSTEM_ALARM_OBJECT_ACE (Reserved)\n";
                        break;
                    case ACE_Type::ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
                        std::cout << "ACCESS_ALLOWED_CALLBACK_ACE\n";
                        break;
                    case ACE_Type::ACCESS_DENIED_CALLBACK_ACE_TYPE:
                        std::cout << "ACCESS_DENIED_CALLBACK_ACE\n";
                        break;
                    case ACE_Type::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
                        std::cout << "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE\n";
                        break;
                    case ACE_Type::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                        std::cout << "ACCESS_DENIED_CALLBACK_OBJECT_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
                        std::cout << "SYSTEM_AUDIT_CALLBACK_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_ALARM_CALLBACK_ACE_TYPE:
                        std::cout << "SYSTEM_ALARM_CALLBACK_ACE (Reserved)\n";
                        break;
                    case ACE_Type::SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
                        std::cout << "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
                        std::cout << "SYSTEM_ALARM_CALLBACK_OBJECT_ACE (Reserved)\n";
                        break;
                    case ACE_Type::SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                        std::cout << "SYSTEM_MANDATORY_LABEL_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                        std::cout << "SYSTEM_RESOURCE_ATTRIBUTE_ACE\n";
                        break;
                    case ACE_Type::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                        std::cout << "SYSTEM_SCOPED_POLICY_ID_ACE\n";
                        break;
                    default:
                        std::cout << "UNKNOWN_ACE_TYPE\n";
                        break;
                    }

                    p_ace_header = reinterpret_cast<ACE_Header *>(
                        reinterpret_cast<uint8_t *>(p_ace_header) + p_ace_header->size);
                }
            }
        }

        ACL *p_sacl{reinterpret_cast<ACL *>(value->bv_val + p_security_descript_relative->sacl_offset)};

        return "";
    }
};