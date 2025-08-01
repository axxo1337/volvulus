#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>

#include <ldap.h>

#include "arguments.h"
#include "object-search.h"
#include "utils.h"
#include "json.h"

LDAPControl *createSDFlagsControl()
{
    BerElement *ber{ber_alloc_t(LBER_USE_DER)};
    if (!ber)
        return nullptr;

    if (ber_printf(ber, "{i}", 7) == -1)
    {
        ber_free(ber, 1);
        return nullptr;
    }

    berval *encodedValue{};
    if (ber_flatten(ber, &encodedValue) == -1)
    {
        ber_free(ber, 1);
        return nullptr;
    }

    LDAPControl *control{new LDAPControl};
    control->ldctl_oid = const_cast<char *>("1.2.840.113556.1.4.801");
    control->ldctl_iscritical = 0;
    control->ldctl_value.bv_len = encodedValue->bv_len;
    control->ldctl_value.bv_val = new char[encodedValue->bv_len];
    memcpy(control->ldctl_value.bv_val, encodedValue->bv_val, encodedValue->bv_len);

    ber_bvfree(encodedValue);
    ber_free(ber, 1);
    return control;
}

int main(int argc, char **argv)
{
    Arguments::Map arguments = {
        {"-u", {Arguments::Type::STRING, true, std::nullopt}},
        {"-p", {Arguments::Type::STRING, true, std::nullopt}},
        {"-d", {Arguments::Type::STRING, true, std::nullopt}},
        {"-h", {Arguments::Type::STRING, true, std::nullopt}},
        {"-s", {Arguments::Type::BOOLEAN, false, false}},
        {"-sp", {Arguments::Type::INT, false, 389}},
    };

    int return_code{Arguments::parse(argc, argv, arguments)};

    if (return_code != 0)
    {
        std::cerr << "[x] Failed to parse arguments with error code " << return_code << std::endl;
        return 1;
    }

    auto username{Arguments::getValue<std::string>(arguments, "-u")};
    auto password{Arguments::getValue<std::string>(arguments, "-p")};
    auto domain{Arguments::getValue<std::string>(arguments, "-d")};
    auto host{Arguments::getValue<std::string>(arguments, "-h")};
    auto use_secure{Arguments::getValue<int>(arguments, "-s") != 0};

    int port{};
    auto &port_argument{arguments["-sp"]};
    if (port_argument.was_specified)
        port = std::get<int>(*port_argument.value);
    else
        port = use_secure ? 636 : 389;

    LDAP *p_ldap;
    std::string uri((use_secure ? "ldaps://" : "ldap://") + *host + ":" + std::to_string(port));
    return_code = ldap_initialize(&p_ldap, uri.c_str());

    if (return_code != LDAP_SUCCESS)
    {
        std::cerr << "[x] Failed to initialize LDAP: " << ldap_err2string(return_code) << std::endl;
        return 1;
    }

    int version = LDAP_VERSION3;

    return_code = ldap_set_option(p_ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (return_code != LDAP_OPT_SUCCESS)
    {
        std::cerr << "[x] Failed to set LDAP version: " << ldap_err2string(return_code) << std::endl;
        ldap_unbind_ext_s(p_ldap, nullptr, nullptr);
        return 1;
    }

    return_code = ldap_set_option(p_ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (return_code != LDAP_OPT_SUCCESS)
        std::cout << "[!] Could not disable referrals" << std::endl;

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    return_code = ldap_set_option(p_ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    if (return_code != LDAP_OPT_SUCCESS)
        std::cout << "[!] Could not set network timeout" << std::endl;

    if (use_secure)
    {
        int tls_req = LDAP_OPT_X_TLS_NEVER;
        ldap_set_option(p_ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_req);

        int tls_protocol = LDAP_OPT_X_TLS_PROTOCOL_TLS1_2;
        ldap_set_option(p_ldap, LDAP_OPT_X_TLS_PROTOCOL_MIN, &tls_protocol);
    }

    size_t domain_short_end{domain->find('.')};
    std::string domain_short{domain->substr(0, domain_short_end)};
    std::string domain_ext{domain->substr(domain_short_end + 1, domain->length() - domain_short_end - 1)};
    std::string bind_dn{domain_short + "\\" + *username};

    return_code = ldap_simple_bind_s(p_ldap, bind_dn.c_str(), password->c_str());

    if (return_code != LDAP_SUCCESS)
    {
        std::cerr << "[x] Failed to bind LDAP: " << ldap_err2string(return_code) << std::endl;
        return 1;
    }

    std::string base_dn("DC=" + domain_short + ",DC=" + domain_ext);

    ObjectSearch::Map objectSearchMap = {
        {
            "USERS",
            {
                "user",
                {
                    {"sAMAccountName", ObjectSearch::AttributeType::STRING},
                    {"displayName", ObjectSearch::AttributeType::STRING},
                    {"distinguishedName", ObjectSearch::AttributeType::STRING},
                    {"objectSid", ObjectSearch::AttributeType::BINARY_SID},
                    {"lastLogon", ObjectSearch::AttributeType::FILETIME},
                    {"memberOf", ObjectSearch::AttributeType::MULTI_VALUE},
                    {"userAccountControl", ObjectSearch::AttributeType::ENUMERATION},
                    {"description", ObjectSearch::AttributeType::STRING},
                    {"nTSecurityDescriptor", ObjectSearch::AttributeType::BINARY_SECURITY_DESCRIPTOR},
                    {"objectClass", ObjectSearch::AttributeType::MULTI_VALUE},
                },
            },
        },
        {
            "GROUPS",
            {
                "group",
                {
                    {"sAMAccountName", ObjectSearch::AttributeType::STRING},
                    {"displayName", ObjectSearch::AttributeType::STRING},
                    {"objectSid", ObjectSearch::AttributeType::BINARY_SID},
                    {"description", ObjectSearch::AttributeType::STRING},
                    {"member", ObjectSearch::AttributeType::MULTI_VALUE},
                    {"memberOf", ObjectSearch::AttributeType::MULTI_VALUE},
                    {"nTSecurityDescriptor", ObjectSearch::AttributeType::BINARY_SECURITY_DESCRIPTOR},
                    {"distinguishedName", ObjectSearch::AttributeType::STRING},
                },
            },
        },
        {
            "ORGANIZATIONAL_UNITS",
            {
                "organizationalUnit",
                {
                    {"name", ObjectSearch::AttributeType::STRING},
                    {"distinguishedName", ObjectSearch::AttributeType::STRING},
                    {"nTSecurityDescriptor", ObjectSearch::AttributeType::BINARY_SECURITY_DESCRIPTOR},
                    {"gPLink", ObjectSearch::AttributeType::STRING},
                    {"managedBy", ObjectSearch::AttributeType::STRING},
                },
            },
        },
    };

    std::unique_ptr<JSON::Object> root_json_object{std::make_unique<JSON::Object>()};

    for (auto &entry : objectSearchMap)
    {
        LDAPMessage *search_result;
        std::string filter{"(objectClass=" + std::string(entry.second.objectClass) + ")"};

        std::vector<JSON::Value> objects_array;

        std::vector<const char *> attributes;
        for (const auto &attribute : entry.second.attributes)
            attributes.push_back(attribute.name);
        attributes.push_back(nullptr);

        LDAPControl *sdControl = createSDFlagsControl();
        LDAPControl *serverControls[] = {sdControl, nullptr};
        int search_result_code = ldap_search_ext_s(p_ldap, base_dn.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), (char **)attributes.data(), 0, serverControls, nullptr, nullptr, 0, &search_result);
        if (sdControl)
        {
            delete[] sdControl->ldctl_value.bv_val;
            delete sdControl;
        }

        if (search_result_code != LDAP_SUCCESS)
        {
            std::cerr << "[x] Search failed for \"" << entry.first << "\": " << ldap_err2string(search_result_code) << std::endl;
            return -1;
        }

        LDAPMessage *message_entry{ldap_first_entry(p_ldap, search_result)};

        while (message_entry != nullptr)
        {
            std::unique_ptr<JSON::Object> sub_json_object{std::make_unique<JSON::Object>()};

            for (const auto &attribute : entry.second.attributes)
            {
                berval **values{ldap_get_values_len(p_ldap, message_entry, attribute.name)};

                if (values == nullptr)
                    continue;

                switch (attribute.type)
                {
                case ObjectSearch::AttributeType::STRING:
                    if (values[0] != nullptr)
                        sub_json_object->setValue(attribute.name, values[0]->bv_val);
                    break;

                case ObjectSearch::AttributeType::MULTI_VALUE:
                {
                    std::vector<JSON::Value> json_values;
                    for (int i{}; values[i] != nullptr; i++)
                        json_values.push_back(JSON::Value(JSON::ValueType::STRING, values[i]->bv_val));
                    sub_json_object->setValue(attribute.name, json_values);
                }
                break;

                case ObjectSearch::AttributeType::FILETIME:
                    if (values[0] != nullptr)
                        sub_json_object->setValue(attribute.name, ObjectSearch::parseFiletime(values[0]));
                    break;

                case ObjectSearch::AttributeType::BINARY_SID:
                    if (values[0] != nullptr)
                        sub_json_object->setValue(attribute.name, ObjectSearch::parseSid(values[0]));
                    break;

                case ObjectSearch::AttributeType::ENUMERATION:
                    if (values[0] != nullptr)
                        sub_json_object->setValue(attribute.name, std::stoul(values[0]->bv_val));
                    break;

                case ObjectSearch::AttributeType::BINARY_SECURITY_DESCRIPTOR:
                    if (values[0] != nullptr)
                        sub_json_object->setValue(attribute.name, ObjectSearch::parseSecurityDescriptor(values[0]));
                    break;
                }

                ldap_value_free_len(values);
            }

            objects_array.push_back(JSON::Value(JSON::ValueType::OBJECT, std::move(sub_json_object)));
            message_entry = ldap_next_entry(p_ldap, message_entry);
        }

        ldap_msgfree(search_result);

        root_json_object->setValue(entry.first, objects_array);
    }

    std::string stringified_json{root_json_object->toString()};
    std::ofstream output("output.json", std::ios::trunc | std::ios::binary);
    output.write(stringified_json.c_str(), stringified_json.size());
    output.close();

    ldap_unbind_ext_s(p_ldap, nullptr, nullptr);
    return 0;
}