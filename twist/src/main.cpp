#include <iostream>
#include <string>

#include <ldap.h>

#include "arguments.h"
#include "object-search.h"

ObjectSearch::Map objectSearchMap = {
    {"USERS",
     {"user", {{"sAMAccountName", ObjectSearch::AttributeType::STRING}}}}};

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

    LDAPMessage *search_result;
    const char *filter{"(objectClass=user)"};
    const char *attributes[]{"sAMAccountName", "displayName", "objectSid", nullptr};
    int search_result_code{ldap_search_s(p_ldap, base_dn.c_str(), LDAP_SCOPE_SUBTREE, filter, (char **)attributes, 0, &search_result)};

    if (search_result_code != LDAP_SUCCESS)
    {
        std::cerr << "[x] Search failed: " << ldap_err2string(search_result_code) << std::endl;
        return -1;
    }

    int entry_count = ldap_count_entries(p_ldap, search_result);

    ldap_msgfree(search_result);

    ldap_unbind_ext_s(p_ldap, nullptr, nullptr);
    return 0;
}