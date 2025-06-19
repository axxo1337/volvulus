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
        INT
    };

    struct Argument
    {
        Type type;
        bool is_required;
        std::optional<std::variant<std::string, int>> value;
    };

    using Map = std::unordered_map<std::string, Argument>;

    //
    // [SECTION] Functions
    //

    bool parse(int argc, char **argv, Map &arguments)
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
                        return true;
                    }
                }
                else
                {
                    if (last_it->second.value != std::nullopt && last_it->second.is_required)
                    {
                        std::cerr << "[x] Argument's value was already provided" << std::endl;
                        return true;
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
                        return true;
                    }

                    last_it = arguments.end();
                }
            }
        }

        for (auto &it : arguments)
        {
            if (it.second.is_required && it.second.value == std::nullopt)
            {
                std::cerr << "[x] Required argument \"" << it.first << "\"'s value is missing" << std::endl;
                return true;
            }
        }

        return false;
    }
}