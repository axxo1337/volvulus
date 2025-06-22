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
        if (value == nullptr || value->bv_len < sizeof(SecurityDescriptorRelative))
            return "null";

        SecurityDescriptorRelative *p_security_descriptor = reinterpret_cast<SecurityDescriptorRelative *>(value->bv_val);

        std::ostringstream oss;
        oss << "{\n";
        oss << "        \"revision\": " << static_cast<int>(p_security_descriptor->revision) << ",\n";
        oss << "        \"control\": " << p_security_descriptor->control << ",\n";

        if (p_security_descriptor->owner_offset != 0)
        {
            berval owner_berval;
            owner_berval.bv_val = value->bv_val + p_security_descriptor->owner_offset;
            owner_berval.bv_len = value->bv_len - p_security_descriptor->owner_offset;
            oss << "        \"owner\": \"" << parseSid(&owner_berval) << "\",\n";
        }

        if (p_security_descriptor->group_offset != 0)
        {
            berval group_berval;
            group_berval.bv_val = value->bv_val + p_security_descriptor->group_offset;
            group_berval.bv_len = value->bv_len - p_security_descriptor->group_offset;
            oss << "        \"group\": \"" << parseSid(&group_berval) << "\",\n";
        }

        if (p_security_descriptor->dacl_offset != 0)
        {
            ACL *p_dacl = reinterpret_cast<ACL *>(value->bv_val + p_security_descriptor->dacl_offset);

            if (reinterpret_cast<uint64_t>(p_dacl) < reinterpret_cast<uint64_t>(value->bv_val + value->bv_len))
            {
                oss << "        \"dacl\": {\n";
                oss << "          \"revision\": " << static_cast<int>(p_dacl->revision) << ",\n";
                oss << "          \"size\": " << p_dacl->acl_size << ",\n";
                oss << "          \"ace_count\": " << p_dacl->ace_count << ",\n";
                oss << "          \"aces\": [\n";

                ACE_Header *p_ace_header = reinterpret_cast<ACE_Header *>(
                    reinterpret_cast<uint8_t *>(p_dacl) + sizeof(ACL));

                for (int i = 0; i < p_dacl->ace_count; i++)
                {
                    if (i > 0)
                        oss << ",\n";

                    oss << "            {\n";
                    oss << "              \"type\": " << static_cast<int>(p_ace_header->type) << ",\n";
                    oss << "              \"flags\": " << static_cast<int>(p_ace_header->flags) << ",\n";
                    oss << "              \"size\": " << p_ace_header->size << ",\n";

                    if (p_ace_header->type == ACE_Type::ACCESS_ALLOWED_ACE_TYPE ||
                        p_ace_header->type == ACE_Type::ACCESS_DENIED_ACE_TYPE)
                    {
                        uint32_t *mask_ptr = reinterpret_cast<uint32_t *>(
                            reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header));
                        oss << "              \"access_mask\": " << *mask_ptr << ",\n";

                        uint8_t *sid_data = reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header) + sizeof(uint32_t);
                        berval sid_berval;
                        sid_berval.bv_val = reinterpret_cast<char *>(sid_data);
                        sid_berval.bv_len = p_ace_header->size - sizeof(ACE_Header) - sizeof(uint32_t);
                        oss << "              \"trustee\": \"" << parseSid(&sid_berval) << "\"\n";
                    }
                    else if (p_ace_header->type == ACE_Type::ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                             p_ace_header->type == ACE_Type::ACCESS_DENIED_OBJECT_ACE_TYPE)
                    {
                        uint32_t *mask_ptr = reinterpret_cast<uint32_t *>(
                            reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header));
                        uint32_t *flags_ptr = reinterpret_cast<uint32_t *>(
                            reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header) + sizeof(uint32_t));

                        oss << "              \"access_mask\": " << *mask_ptr << ",\n";
                        oss << "              \"object_flags\": " << *flags_ptr << ",\n";

                        size_t sid_offset = sizeof(ACE_Header) + sizeof(uint32_t) + sizeof(uint32_t);

                        if (*flags_ptr & 0x1)
                        {
                            uint8_t *guid_data = reinterpret_cast<uint8_t *>(p_ace_header) + sid_offset;

                            uint32_t data1 = *reinterpret_cast<uint32_t *>(guid_data);
                            uint16_t data2 = *reinterpret_cast<uint16_t *>(guid_data + 4);
                            uint16_t data3 = *reinterpret_cast<uint16_t *>(guid_data + 6);

                            oss << "              \"object_type_guid\": \"";
                            oss << std::hex << std::setfill('0')
                                << std::setw(8) << data1 << "-"
                                << std::setw(4) << data2 << "-"
                                << std::setw(4) << data3 << "-";

                            for (int j = 8; j < 10; j++)
                            {
                                oss << std::setw(2) << static_cast<int>(guid_data[j]);
                            }
                            oss << "-";
                            for (int j = 10; j < 16; j++)
                            {
                                oss << std::setw(2) << static_cast<int>(guid_data[j]);
                            }
                            oss << std::dec << "\",\n";

                            sid_offset += 16;
                        }

                        if (*flags_ptr & 0x2)
                        {
                            uint8_t *guid_data = reinterpret_cast<uint8_t *>(p_ace_header) + sid_offset;

                            uint32_t data1 = *reinterpret_cast<uint32_t *>(guid_data);
                            uint16_t data2 = *reinterpret_cast<uint16_t *>(guid_data + 4);
                            uint16_t data3 = *reinterpret_cast<uint16_t *>(guid_data + 6);

                            oss << "              \"inherited_object_type_guid\": \"";
                            oss << std::hex << std::setfill('0')
                                << std::setw(8) << data1 << "-"
                                << std::setw(4) << data2 << "-"
                                << std::setw(4) << data3 << "-";

                            for (int j = 8; j < 10; j++)
                            {
                                oss << std::setw(2) << static_cast<int>(guid_data[j]);
                            }
                            oss << "-";
                            for (int j = 10; j < 16; j++)
                            {
                                oss << std::setw(2) << static_cast<int>(guid_data[j]);
                            }
                            oss << std::dec << "\",\n";

                            sid_offset += 16;
                        }

                        uint8_t *sid_data = reinterpret_cast<uint8_t *>(p_ace_header) + sid_offset;
                        berval sid_berval;
                        sid_berval.bv_val = reinterpret_cast<char *>(sid_data);
                        sid_berval.bv_len = p_ace_header->size - sid_offset;
                        oss << "              \"trustee\": \"" << parseSid(&sid_berval) << "\"\n";
                    }
                    else
                        oss << "              \"raw_data\": true\n";

                    oss << "            }";

                    if (p_ace_header->size == 0)
                        break;

                    p_ace_header = reinterpret_cast<ACE_Header *>(
                        reinterpret_cast<uint8_t *>(p_ace_header) + p_ace_header->size);
                }

                oss << "\n          ]\n";
                oss << "        }\n";
            }
        }

        oss << "      }";
        return oss.str();
    }
};