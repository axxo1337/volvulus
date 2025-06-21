#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>

#include <ldap.h>

#include "arguments.h"
#include "object-search.h"

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

int main(int argc, char **argv)
{
    Arguments::Map arguments = {
        {"-u", {Arguments::Type::STRING, true, std::nullopt}},
        {"-p", {Arguments::Type::STRING, true, std::nullopt}},
        {"-d", {Arguments::Type::STRING, true, std::nullopt}},
        {"-h", {Arguments::Type::STRING, true, std::nullopt}},
        {"-sp", {Arguments::Type::INT, false, 389}},
    };

    if (Arguments::parse(argc, argv, arguments))
    {
        std::cerr << "[x] Failed to parse arguments" << std::endl;
        return -1;
    }

    auto username = Arguments::getValue<std::string>(arguments, "-u");
    auto password = Arguments::getValue<std::string>(arguments, "-p");
    auto domain = Arguments::getValue<std::string>(arguments, "-d");
    auto host = Arguments::getValue<std::string>(arguments, "-h");
    auto port = Arguments::getValue<int>(arguments, "-sp");

    LDAP *p_ldap;
    std::string uri("ldap://" + *host + ":" + std::to_string(*port));
    int code{ldap_initialize(&p_ldap, uri.c_str())};

    if (code != LDAP_SUCCESS)
    {
        std::cerr << "[x] Failed to initialize LDAP: " << ldap_err2string(code) << std::endl;
        return -1;
    }

    int version = LDAP_VERSION3;

    code = ldap_set_option(p_ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (code != LDAP_OPT_SUCCESS)
    {
        std::cerr << "[x] Failed to set LDAP version: " << ldap_err2string(code) << std::endl;
        ldap_unbind_ext_s(p_ldap, nullptr, nullptr);
        return -1;
    }

    code = ldap_set_option(p_ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (code != LDAP_OPT_SUCCESS)
        std::cout << "[!] Could not disable referrals" << std::endl;

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    code = ldap_set_option(p_ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    if (code != LDAP_OPT_SUCCESS)
        std::cout << "[!] Could not set network timeout" << std::endl;

    int tls_reqcert = LDAP_OPT_X_TLS_NEVER;
    code = ldap_set_option(p_ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_reqcert);
    if (code != LDAP_OPT_SUCCESS)
        std::cout << "[!] Could not set TLS certificate requirements" << std::endl;

    size_t domain_short_end{domain->find('.')};
    std::string domain_short{domain->substr(0, domain_short_end)};
    std::string domain_ext{domain->substr(domain_short_end + 1, domain->length() - domain_short_end - 1)};
    std::string bind_dn{domain_short + "\\" + *username};

    code = ldap_simple_bind_s(p_ldap, bind_dn.c_str(), password->c_str());

    if (code != LDAP_SUCCESS)
    {
        std::cerr << "[x] Failed to bind LDAP: " << ldap_err2string(code) << std::endl;
        return -1;
    }

    std::string base_dn("DC=" + domain_short + ",DC=" + domain_ext);

    ObjectSearch::Map objectSearchMap = {
        {"USERS",
         {"user", {{"sAMAccountName", ObjectSearch::AttributeType::STRING}, {"displayName", ObjectSearch::AttributeType::STRING}, {"objectSid", ObjectSearch::AttributeType::BINARY_SID}, {"lastLogon", ObjectSearch::AttributeType::FILETIME}, {"memberOf", ObjectSearch::AttributeType::MULTI_VALUE}, {"rid", ObjectSearch::AttributeType::ENUMERATION}}}}};

    std::ostringstream oss;
    oss << "{\n";

    bool first_search_type = true;
    for (auto &entry : objectSearchMap)
    {
        if (!first_search_type)
        {
            oss << ",\n";
        }

        LDAPMessage *search_result;
        std::string filter{"(objectClass=" + std::string(entry.second.objectClass) + ")"};

        oss << "  \"" << entry.first << "\": [\n";

        std::vector<const char *> attributes;
        for (const auto &attribute : entry.second.attributes)
            attributes.push_back(attribute.name);
        attributes.push_back(nullptr);

        int search_result_code{ldap_search_s(p_ldap, base_dn.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), (char **)attributes.data(), 0, &search_result)};

        if (search_result_code != LDAP_SUCCESS)
        {
            std::cerr << "[x] Search failed for \"" << entry.first << "\": " << ldap_err2string(search_result_code) << std::endl;
            return -1;
        }

        LDAPMessage *message_entry{ldap_first_entry(p_ldap, search_result)};

        bool first_entry{true};
        while (message_entry != nullptr)
        {
            if (!first_entry)
                oss << ",\n";

            oss << "    {\n";

            bool first_attribute = true;
            for (const auto &attribute : entry.second.attributes)
            {
                berval **values{ldap_get_values_len(p_ldap, message_entry, attribute.name)};

                if (values == nullptr)
                    continue;

                if (!first_attribute)
                {
                    oss << ",\n";
                }

                oss << "      \"" << attribute.name << "\": ";

                switch (attribute.type)
                {
                case ObjectSearch::AttributeType::STRING:
                    if (values[0] != nullptr)
                        oss << "\"" << escapeJson(values[0]->bv_val) << "\"";
                    else
                        oss << "null";
                    break;

                case ObjectSearch::AttributeType::MULTI_VALUE:
                    oss << "[\n";
                    for (int i = 0; values[i] != nullptr; i++)
                    {
                        if (i > 0)
                            oss << ",\n";
                        oss << "        \"" << escapeJson(values[i]->bv_val) << "\"";
                    }
                    oss << "\n      ]";
                    break;

                case ObjectSearch::AttributeType::FILETIME:
                    if (values[0] != nullptr)
                        oss << "\"" << escapeJson(ObjectSearch::parseFiletime(values[0])) << "\"";
                    else
                        oss << "null";
                    break;

                case ObjectSearch::AttributeType::BINARY_SID:
                    if (values[0] != nullptr)
                        oss << "\"" << escapeJson(ObjectSearch::parseSid(values[0])) << "\"";
                    else
                        oss << "null";
                    break;

                case ObjectSearch::AttributeType::ENUMERATION:
                    if (values[0] != nullptr && values[0]->bv_len == 4)
                    {
                        uint32_t value{*reinterpret_cast<uint32_t *>(values[0]->bv_val)};
                        oss << value;
                    }
                    else
                        oss << "null";
                    break;
                }

                ldap_value_free_len(values);
                first_attribute = false;
            }

            oss << "\n    }";

            message_entry = ldap_next_entry(p_ldap, message_entry);
            first_entry = false;
        }

        oss << "\n  ]";
        ldap_msgfree(search_result);
        first_search_type = false;
    }

    oss << "\n}\n";

    std::ofstream output("output.json", std::ios::trunc | std::ios::binary);
    output.write(oss.str().c_str(), oss.str().size());
    output.close();

    ldap_unbind_ext_s(p_ldap, nullptr, nullptr);
    return 0;
}