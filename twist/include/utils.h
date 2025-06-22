#pragma once

#include <string>

namespace Utils
{
    std::string escapeJson(const std::string &input)
    {
        std::string output;
        for (char c : input)
        {
            switch (c)
            {
            case '"':
                output += "\\\"";
                break;
            case '\\':
                output += "\\\\";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                output += c;
                break;
            }
        }
        return output;
    }
}