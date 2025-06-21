#pragma once

#include <unordered_map>
#include <vector>
#include <string>

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
        MULTI_VALUE
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
};