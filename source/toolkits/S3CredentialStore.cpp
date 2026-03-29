// SPDX-FileCopyrightText: 2020-2025 Sven Breuner and elbencho contributors
// SPDX-License-Identifier: GPL-3.0-only

#ifdef S3_SUPPORT

#include <boost/algorithm/string.hpp>
#include <fstream>
#include <sstream>
#include "Common.h"
#include "Logger.h"
#include "ProgException.h"
#include "toolkits/S3CredentialStore.h"
#include "toolkits/StringTk.h"

/**
 * Load credentials from a file where each line contains a credential in format:
 * access_key:secret_key[:session_token]
 */
void S3CredentialStore::loadCredentialsFromFile(const std::string& filePath)
{
    std::ifstream file(filePath);
    if(!file)
        throw ProgException("Unable to open S3 credentials file: " + filePath);

    std::string line;
    while(std::getline(file, line))
    {
        if(line.empty() || line[0] == '#') // skip empty lines and comments
            continue;

        try
        {
            parseAndAddCredential(line);
        }
        catch(const ProgException& e)
        {
            LOGGER(Log_NORMAL, "Warning: Skipping invalid credential in file. "
                    << e.what() << std::endl);
        }
    }

    if(credentials.empty())
        throw ProgException("No valid credentials found in file: " + filePath);
}

/**
 * Load credentials from a comma-separated list in format:
 * access_key1:secret_key1[:token1],access_key2:secret_key2[:token2],...
 */
void S3CredentialStore::loadCredentialsFromList(const std::string& credList)
{
    StringVec credVec;
    boost::split(credVec, credList, boost::is_any_of(","));

    if(credVec.empty())
        throw ProgException("Empty credentials list provided");

    for(const std::string& credStr : credVec)
    {
        try
        {
            parseAndAddCredential(credStr);
        }
        catch(const ProgException& e)
        {
            LOGGER(Log_NORMAL, "Warning: Skipping invalid credential in list. "
                    << e.what() << std::endl);
        }
    }

    if(credentials.empty())
        throw ProgException("No valid credentials found in provided list");
}

/**
 * Add a single credential.
 */
void S3CredentialStore::addCredential(const std::string& accessKey, const std::string& secretKey,
    const std::string& sessionToken)
{
    validateCredential(accessKey, secretKey);

    std::lock_guard<std::mutex> lock(mutex);
    credentials.emplace_back(accessKey, secretKey, sessionToken);
}

/**
 * Get AWS credentials for a given worker rank. Uses round-robin distribution.
 */
std::shared_ptr<Aws::Auth::AWSCredentialsProvider> S3CredentialStore::getCredential(size_t workerRank)
{
    std::lock_guard<std::mutex> lock(mutex);

    if(credentials.empty())
        throw ProgException("No S3 credentials available");

    size_t index = workerRank % credentials.size();
    const S3Credential& cred = credentials[index];

    return std::make_shared<Aws::Auth::SimpleAWSCredentialsProvider>(
        cred.accessKey, cred.secretKey, cred.sessionToken);
}

/**
 * Get raw credential entry for a given worker rank. Uses round-robin distribution.
 */
const S3CredentialStore::S3Credential& S3CredentialStore::getCredentialEntry(size_t workerRank)
{
    std::lock_guard<std::mutex> lock(mutex);

    if(credentials.empty())
        throw ProgException("No S3 credentials available");

    size_t index = workerRank % credentials.size();
    return credentials[index];
}

/**
 * Parse a credential string in format "access_key:secret_key[:session_token]" and add it to the
 * store. The session token field is optional and used for STS temporary credentials.
 */
void S3CredentialStore::parseAndAddCredential(const std::string& credStr)
{
    // split into at most 3 parts (access_key, secret_key, optional session_token)
    size_t firstColon = credStr.find(':');
    if(firstColon == std::string::npos)
        throw ProgException(
            "Invalid credential format. Expected 'access_key:secret_key[:session_token]', got: " +
            credStr);

    size_t secondColon = credStr.find(':', firstColon + 1);

    std::string accessKey;
    std::string secretKey;
    std::string sessionToken;

    if(secondColon == std::string::npos)
    {
        // two fields: access_key:secret_key
        accessKey = credStr.substr(0, firstColon);
        secretKey = credStr.substr(firstColon + 1);
    }
    else
    {
        // three fields: access_key:secret_key:session_token
        accessKey = credStr.substr(0, firstColon);
        secretKey = credStr.substr(firstColon + 1, secondColon - firstColon - 1);
        sessionToken = credStr.substr(secondColon + 1);
        boost::trim(sessionToken);
    }

    boost::trim(accessKey);
    boost::trim(secretKey);

    validateCredential(accessKey, secretKey);

    std::lock_guard<std::mutex> lock(mutex);
    credentials.emplace_back(accessKey, secretKey, sessionToken);
}

/**
 * Validate that the provided credentials are not empty.
 */
void S3CredentialStore::validateCredential(const std::string& accessKey, const std::string& secretKey)
{
    if(accessKey.empty())
        throw ProgException("S3 access key cannot be empty");

    if(secretKey.empty())
        throw ProgException("S3 secret key cannot be empty");
}

#endif /* S3_SUPPORT */ 