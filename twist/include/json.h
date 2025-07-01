#pragma once

#include <map>
#include <string>
#include <sstream>
#include <variant>
#include <memory>

namespace JSON
{
    class Object;

    enum class ValueType
    {
        STRING,
        INT,
        OBJECT,
        ARRAY
    };

    struct Value
    {
        ValueType type;
        std::variant<std::string, int, std::unique_ptr<Object>, std::vector<Value>> value;

        Value(ValueType t, std::string s) : type(t), value(std::move(s)) {}
        Value(ValueType t, int i) : type(t), value(i) {}
        Value(ValueType t, std::unique_ptr<Object> obj) : type(t), value(std::move(obj)) {}
        Value(ValueType t, std::vector<Value> arr) : type(t), value(std::move(arr)) {}
        Value() : type(ValueType::STRING), value(std::string{}) {}
        Value(Value &&other) noexcept : type(other.type), value(std::move(other.value)) {}
    };

    class Object
    {
    public:
        std::string arrayToString(std::vector<Value> &value, int indent_level = 0)
        {
            std::ostringstream oss;
            std::string base_indent{generateIndent(indent_level)};

            oss << "[\n";

            bool first_entry{true};

            for (auto &entry : value)
            {
                if (!first_entry)
                    oss << ",\n";

                oss << base_indent << "    ";

                switch (entry.type)
                {
                case ValueType::STRING:
                    oss << "\"" << escape(std::get<std::string>(entry.value)) << "\"";
                    break;
                case ValueType::INT:
                    oss << std::to_string(std::get<int>(entry.value));
                    break;
                case ValueType::OBJECT:
                    oss << std::get<std::unique_ptr<Object>>(entry.value)->toString(indent_level + 1);
                    break;
                case ValueType::ARRAY:
                    oss << arrayToString(std::get<std::vector<Value>>(entry.value), indent_level + 1);
                    break;
                }

                first_entry = false;
            }

            oss << "\n"
                << base_indent << "]";

            return oss.str();
        }

        std::string toString(int indent_level = 0)
        {
            std::ostringstream oss;
            std::string base_indent{generateIndent(indent_level)};

            oss << "{\n";

            bool first_entry{true};

            for (auto &entry : map)
            {
                if (!first_entry)
                    oss << ",\n";

                oss << base_indent << "    \"" << entry.first << "\": ";

                switch (entry.second.type)
                {
                case ValueType::STRING:
                    oss << "\"" << escape(std::get<std::string>(entry.second.value)) << "\"";
                    break;
                case ValueType::INT:
                    oss << std::to_string(std::get<int>(entry.second.value));
                    break;
                case ValueType::OBJECT:
                    oss << std::get<std::unique_ptr<Object>>(entry.second.value)->toString(indent_level + 1);
                    break;
                case ValueType::ARRAY:
                    oss << arrayToString(std::get<std::vector<Value>>(entry.second.value), indent_level + 1);
                    break;
                }

                first_entry = false;
            }

            oss << "\n"
                << base_indent << "}";

            return oss.str();
        }

        std::string getStringValue(std::string &key)
        {
            return std::get<std::string>(map[key].value);
        }

        int getIntValue(std::string &key)
        {
            return std::get<int>(map[key].value);
        }

        Object &getObjectValue(std::string &key)
        {
            return *std::get<std::unique_ptr<Object>>(map[key].value);
        }

        void setValue(const std::string &key, const std::string &value)
        {
            map[key].type = ValueType::STRING;
            map[key].value = value;
        }

        void setValue(const std::string &key, int value)
        {
            map[key].type = ValueType::INT;
            map[key].value = value;
        }

        void setValue(const std::string &key, std::unique_ptr<Object> value)
        {
            map[key].type = ValueType::OBJECT;
            map[key].value = std::move(value);
        }

        void setValue(const std::string &key, std::vector<Value> &value)
        {
            map[key].type = ValueType::ARRAY;
            map[key].value = std::move(value);
        }

    private:
        std::map<std::string, Value> map;

        std::string escape(const std::string &input)
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

        std::string generateIndent(int level)
        {
            std::ostringstream oss;

            for (int i{}; i < level; i++)
                oss << "    ";

            return oss.str();
        }
    };
}