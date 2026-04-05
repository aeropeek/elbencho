// SPDX-FileCopyrightText: 2020-2025 Sven Breuner and elbencho contributors
// SPDX-License-Identifier: GPL-3.0-only

#ifndef TOOLKITS_S3CREDENTIALSTORE_H_
#define TOOLKITS_S3CREDENTIALSTORE_H_

#ifdef S3_SUPPORT

#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>


class ProgArgs; // forward declaration

/**
 * Stores and manages multiple S3 credentials for multi-user benchmarking.
 * Thread-safe singleton class.
 */
class S3CredentialStore
{
    public:
        struct S3Credential 
        {
            std::string accessKey;
            std::string secretKey;
            std::string sessionToken; // optional STS session token; empty if not an STS credential
            
            S3Credential(const std::string& accessKey, const std::string& secretKey,
                const std::string& sessionToken = "") :
                accessKey(accessKey), secretKey(secretKey), sessionToken(sessionToken) {}
        };

        /**
         * Get the singleton instance of the credential store.
         * 
         * @return Reference to the singleton instance
         */
        static S3CredentialStore& getInstance()
        {
            static S3CredentialStore instance;
            return instance;
        }

        /**
         * Load credentials from a file.
         * Each line in the file should be in format: access_key:secret_key[:session_token]
         * Session token is optional and used for STS temporary credentials.
         * Lines starting with # are treated as comments.
         * 
         * @param filePath Path to the credentials file
         * @throw ProgException if file cannot be read or has invalid format
         */
        void loadCredentialsFromFile(const std::string& filePath);

        /**
         * Load credentials from a comma-separated list.
         * List format: "access_key1:secret_key1[:token1],access_key2:secret_key2[:token2],..."
         * 
         * @param credList Comma-separated list of credentials
         * @throw ProgException if list has invalid format
         */
        void loadCredentialsFromList(const std::string& credList);

        /**
         * Add a single credential to the store.
         * 
         * @param accessKey S3 access key
         * @param secretKey S3 secret key
         * @param sessionToken optional STS session token
         */
        void addCredential(const std::string& accessKey, const std::string& secretKey,
            const std::string& sessionToken = "");

        /**
         * Get a credential based on worker rank.
         * Credentials are assigned in round-robin fashion based on the worker rank.
         * 
         * @param workerRank Rank of the worker requesting credentials
         * @return AWS credentials provider (includes session token if present)
         * @throw ProgException if no credentials are available
         */
        std::shared_ptr<Aws::Auth::AWSCredentialsProvider> getCredential(size_t workerRank);

        /**
         * Get raw credential entry based on worker rank (round-robin).
         * 
         * @param workerRank Rank of the worker requesting credentials
         * @return const reference to S3Credential struct
         * @throw ProgException if no credentials are available
         */
        const S3Credential& getCredentialEntry(size_t workerRank);

        void openCredCmdPipe(const std::string& cmd);
        std::shared_ptr<Aws::Auth::AWSCredentialsProvider> readCredFromPipe();
        void closeCredCmdPipe();
        bool hasCredCmdPipe() const { return credCmdPipe != nullptr; }

        size_t getNumCredentials() const { return credentials.size(); }
        uint64_t claimNextCredIdx();
        void clear()
        {
            credentials.clear();
            nextCredIdx.store(0, std::memory_order_relaxed);
            closeCredCmdPipe();
        }

    private:
        S3CredentialStore() {} // private constructor for singleton

        // Prevent copying and assignment
        S3CredentialStore(const S3CredentialStore&) = delete;
        S3CredentialStore& operator=(const S3CredentialStore&) = delete;

        std::vector<S3Credential> credentials; // Store for all loaded credentials
        mutable std::mutex mutex; // Mutex for thread-safe access
        std::atomic<uint64_t> nextCredIdx{0}; // global counter for credential rotation

        FILE* credCmdPipe{nullptr}; // long-lived credential provider subprocess pipe
        std::mutex pipeMutex; // serializes reads from the credential pipe

        void parseAndAddCredential(const std::string& credStr);
        void validateCredential(const std::string& accessKey, const std::string& secretKey);
};

#endif /* S3_SUPPORT */
#endif /* TOOLKITS_S3CREDENTIALSTORE_H_ */ 