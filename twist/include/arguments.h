#pragma once

#include <optional>
#include <variant>
#include <string>
#include <iostream>
#include <unordered_map>

namespace Arguments
{
    //
    // [SECTION] Types
    //

    enum class Type
    {
        STRING = 0,
        INT,
        BOOLEAN
    };

    struct Argument
    {
        Type type;
        bool is_required;
        std::optional<std::variant<std::string, int>> value;
        bool was_specified;
    };

    using Map = std::unordered_map<std::string, Argument>;

    //
    // [SECTION] Functions
    //

    int parse(int argc, char **argv, Map &arguments)
    {
        if (argc > 0)
        {
            Map::iterator last_it = arguments.end();

            for (int i{1}; i < argc; i++)
            {
                if (last_it == arguments.end())
                {
                    last_it = arguments.find(argv[i]);

                    if (last_it == arguments.end())
                    {
                        std::cerr << "[x] Argument \"" << argv[i] << "\" not found" << std::endl;
                        return 1;
                    }

                    /* Handle special case of boolean values */
                    if (last_it->second.type == Type::BOOLEAN)
                    {
                        last_it->second.value = true;
                        last_it = arguments.end();
                    }
                }
                else
                {
                    if (last_it->second.value != std::nullopt && last_it->second.is_required)
                    {
                        std::cerr << "[x] Argument's value was already provided" << std::endl;
                        return 2;
                    }

                    switch (last_it->second.type)
                    {
                    case Type::STRING:
                        last_it->second.value = argv[i];
                        break;
                    case Type::INT:
                        last_it->second.value = atoi(argv[i]);
                        break;
                    default:
                        std::cerr << "[x] Unhandled argument type" << std::endl;
                        return 3;
                    }

                    last_it->second.was_specified = true;

                    last_it = arguments.end();
                }
            }
        }

        for (auto &it : arguments)
        {
            if (it.second.is_required && it.second.value == std::nullopt)
            {
                std::cerr << "[x] Required argument \"" << it.first << "\"'s value is missing" << std::endl;
                return 4;
            }
        }

        return 0;
    }

    template <typename T>
    std::optional<T> getValue(const Map &arguments, const std::string &key)
    {
        auto it = arguments.find(key);
        if (it == arguments.end())
            return std::nullopt;

        const Argument &arg = it->second;
        if (!arg.value.has_value())
            return std::nullopt;

        try
        {
            return std::get<T>(*arg.value);
        }
        catch (const std::bad_variant_access &)
        {
            std::cerr << "[x] Type mismatch for argument \"" << key << "\"" << std::endl;
            return std::nullopt;
        }
    }
}