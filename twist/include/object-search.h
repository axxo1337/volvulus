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
#include "json.h"

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

    std::unique_ptr<JSON::Object> parseSecurityDescriptor(const struct berval *value)
    {
        std::unique_ptr<JSON::Object> result{std::make_unique<JSON::Object>()};

        if (value == nullptr || value->bv_len < sizeof(SecurityDescriptorRelative))
            return std::move(result);

        SecurityDescriptorRelative *p_security_descriptor = reinterpret_cast<SecurityDescriptorRelative *>(value->bv_val);

        result->setValue("revision", static_cast<int>(p_security_descriptor->revision));
        result->setValue("control", static_cast<int>(p_security_descriptor->control));

        if (p_security_descriptor->owner_offset != 0)
        {
            berval owner_berval;
            owner_berval.bv_val = value->bv_val + p_security_descriptor->owner_offset;
            owner_berval.bv_len = value->bv_len - p_security_descriptor->owner_offset;
            result->setValue("owner", parseSid(&owner_berval));
        }

        if (p_security_descriptor->group_offset != 0)
        {
            berval group_berval;
            group_berval.bv_val = value->bv_val + p_security_descriptor->group_offset;
            group_berval.bv_len = value->bv_len - p_security_descriptor->group_offset;
            result->setValue("group", parseSid(&group_berval));
        }

        if (p_security_descriptor->dacl_offset != 0)
        {
            ACL *p_dacl = reinterpret_cast<ACL *>(value->bv_val + p_security_descriptor->dacl_offset);

            if (reinterpret_cast<uint64_t>(p_dacl) < reinterpret_cast<uint64_t>(value->bv_val + value->bv_len))
            {
                std::unique_ptr<JSON::Object> dacl_obj{std::make_unique<JSON::Object>()};
                dacl_obj->setValue("revision", static_cast<int>(p_dacl->revision));
                dacl_obj->setValue("size", static_cast<int>(p_dacl->acl_size));
                dacl_obj->setValue("ace_count", static_cast<int>(p_dacl->ace_count));

                std::vector<JSON::Value> aces;
                ACE_Header *p_ace_header{reinterpret_cast<ACE_Header *>(
                    reinterpret_cast<uint8_t *>(p_dacl) + sizeof(ACL))};

                for (int i = 0; i < p_dacl->ace_count; i++)
                {
                    std::unique_ptr<JSON::Object> ace_obj = std::make_unique<JSON::Object>();
                    ace_obj->setValue("type", static_cast<int>(p_ace_header->type));
                    ace_obj->setValue("flags", static_cast<int>(p_ace_header->flags));
                    ace_obj->setValue("size", static_cast<int>(p_ace_header->size));

                    if (p_ace_header->type == ACE_Type::ACCESS_ALLOWED_ACE_TYPE ||
                        p_ace_header->type == ACE_Type::ACCESS_DENIED_ACE_TYPE)
                    {
                        uint32_t *mask_ptr = reinterpret_cast<uint32_t *>(
                            reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header));
                        ace_obj->setValue("access_mask", static_cast<int>(*mask_ptr));

                        uint8_t *sid_data{reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header) + sizeof(uint32_t)};
                        berval sid_berval;
                        sid_berval.bv_val = reinterpret_cast<char *>(sid_data);
                        sid_berval.bv_len = p_ace_header->size - sizeof(ACE_Header) - sizeof(uint32_t);
                        ace_obj->setValue("trustee", parseSid(&sid_berval));
                    }
                    else if (p_ace_header->type == ACE_Type::ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                             p_ace_header->type == ACE_Type::ACCESS_DENIED_OBJECT_ACE_TYPE)
                    {
                        uint32_t *mask_ptr = reinterpret_cast<uint32_t *>(
                            reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header));
                        uint32_t *flags_ptr = reinterpret_cast<uint32_t *>(
                            reinterpret_cast<uint8_t *>(p_ace_header) + sizeof(ACE_Header) + sizeof(uint32_t));

                        ace_obj->setValue("access_mask", static_cast<int>(*mask_ptr));
                        ace_obj->setValue("object_flags", static_cast<int>(*flags_ptr));

                        size_t sid_offset{sizeof(ACE_Header) + sizeof(uint32_t) + sizeof(uint32_t)};

                        if (*flags_ptr & 0x1)
                        {
                            uint8_t *guid_data{reinterpret_cast<uint8_t *>(p_ace_header) + sid_offset};

                            uint32_t data1{*reinterpret_cast<uint32_t *>(guid_data)};
                            uint16_t data2{*reinterpret_cast<uint16_t *>(guid_data + 4)};
                            uint16_t data3{*reinterpret_cast<uint16_t *>(guid_data + 6)};

                            std::ostringstream guid_oss;
                            guid_oss << std::hex << std::setfill('0')
                                     << std::setw(8) << data1 << "-"
                                     << std::setw(4) << data2 << "-"
                                     << std::setw(4) << data3 << "-";

                            for (int j = 8; j < 10; j++)
                                guid_oss << std::setw(2) << static_cast<int>(guid_data[j]);

                            guid_oss << "-";

                            for (int j = 10; j < 16; j++)
                                guid_oss << std::setw(2) << static_cast<int>(guid_data[j]);

                            ace_obj->setValue("object_type_guid", guid_oss.str());
                            sid_offset += 16;
                        }

                        if (*flags_ptr & 0x2)
                        {
                            uint8_t *guid_data = reinterpret_cast<uint8_t *>(p_ace_header) + sid_offset;

                            uint32_t data1{*reinterpret_cast<uint32_t *>(guid_data)};
                            uint16_t data2{*reinterpret_cast<uint16_t *>(guid_data + 4)};
                            uint16_t data3{*reinterpret_cast<uint16_t *>(guid_data + 6)};

                            std::ostringstream guid_oss;
                            guid_oss << std::hex << std::setfill('0')
                                     << std::setw(8) << data1 << "-"
                                     << std::setw(4) << data2 << "-"
                                     << std::setw(4) << data3 << "-";

                            for (int j = 8; j < 10; j++)
                                guid_oss << std::setw(2) << static_cast<int>(guid_data[j]);

                            guid_oss << "-";

                            for (int j = 10; j < 16; j++)
                                guid_oss << std::setw(2) << static_cast<int>(guid_data[j]);

                            ace_obj->setValue("inherited_object_type_guid", guid_oss.str());
                            sid_offset += 16;
                        }

                        uint8_t *sid_data{reinterpret_cast<uint8_t *>(p_ace_header) + sid_offset};
                        berval sid_berval;
                        sid_berval.bv_val = reinterpret_cast<char *>(sid_data);
                        sid_berval.bv_len = p_ace_header->size - sid_offset;
                        ace_obj->setValue("trustee", parseSid(&sid_berval));
                    }
                    else
                        ace_obj->setValue("raw_data", 1);

                    aces.push_back(JSON::Value(JSON::ValueType::OBJECT, std::move(ace_obj)));

                    if (p_ace_header->size == 0)
                        break;

                    p_ace_header = reinterpret_cast<ACE_Header *>(
                        reinterpret_cast<uint8_t *>(p_ace_header) + p_ace_header->size);
                }

                dacl_obj->setValue("aces", aces);
                result->setValue("dacl", std::move(dacl_obj));
            }
        }

        return result;
    }
};