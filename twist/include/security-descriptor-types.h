#pragma once

#include <cstdint>

struct SecurityDescriptorRelative
{
    uint8_t revision;
    uint8_t reserved1;
    uint16_t control;
    uint32_t owner_offset;
    uint32_t group_offset;
    uint32_t sacl_offset;
    uint32_t dacl_offset;
};

struct SID
{
    uint8_t revision;
    uint8_t sub_authority_count;
    uint8_t identifier_authority[6];
};

struct GUID
{
    unsigned long data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
};

struct ACL
{
    uint8_t revision;
    uint8_t reserved1;
    uint16_t acl_size;
    uint16_t ace_count;
    uint16_t reserved2;
};

enum class ACE_Type : uint8_t
{
    ACCESS_ALLOWED_ACE_TYPE = 0x00,
    ACCESS_DENIED_ACE_TYPE = 0x01,
    SYSTEM_AUDIT_ACE_TYPE = 0x02,
    SYSTEM_ALARM_ACE_TYPE = 0x03,
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05,
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06,
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07,
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09,
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C,
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12,
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13,
};

struct ACE_Header
{
    ACE_Type type;
    uint8_t flags;
    uint16_t size;
};

struct ACCESS_ALLOWED_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct ACCESS_DENIED_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct SYSTEM_AUDIT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct SYSTEM_ALARM_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct ACCESS_ALLOWED_COMPOUND_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint16_t compound_ace_type;
    uint16_t reserved;
    uint32_t sid_start;
};

struct ACCESS_ALLOWED_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct ACCESS_DENIED_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct SYSTEM_AUDIT_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct SYSTEM_ALARM_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct ACCESS_ALLOWED_CALLBACK_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct ACCESS_DENIED_CALLBACK_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct ACCESS_DENIED_CALLBACK_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct SYSTEM_AUDIT_CALLBACK_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct SYSTEM_ALARM_CALLBACK_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct SYSTEM_ALARM_CALLBACK_OBJECT_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t flags;
    GUID object_type;
    GUID inherited_object_type;
    uint32_t sid_start;
};

struct SYSTEM_MANDATORY_LABEL_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct SYSTEM_RESOURCE_ATTRIBUTE_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};

struct SYSTEM_SCOPED_POLICY_ID_ACE
{
    ACE_Header header;
    uint32_t mask;
    uint32_t sid_start;
};