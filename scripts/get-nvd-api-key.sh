#!/bin/bash

# Script to help users get an NVD API key for OWASP Dependency Check
# This improves performance and reduces rate limiting issues

set -e

echo "🔑 NVD API Key Setup for OWASP Dependency Check"
echo "================================================"
echo ""
echo "The National Vulnerability Database (NVD) provides free API keys that"
echo "significantly improve the performance of security scans and reduce"
echo "rate limiting issues."
echo ""

# Check if API key already exists
if [ -f ".nvd-api-key" ]; then
    echo "✅ NVD API key already exists in .nvd-api-key"
    echo "Current key: $(head -c 10 .nvd-api-key)..."
    echo ""
    read -p "Do you want to generate a new key? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing API key."
        exit 0
    fi
fi

echo "📋 Steps to get your free NVD API key:"
echo ""
echo "1. Visit: https://nvd.nist.gov/developers/request-an-api-key"
echo "2. Fill out the form with your information"
echo "3. Check your email for the API key"
echo "4. Copy the key and paste it below"
echo ""

read -p "Enter your NVD API key: " -r api_key

if [ -z "$api_key" ]; then
    echo "❌ No API key provided. Exiting."
    exit 1
fi

# Validate API key format (should be a UUID)
if [[ ! $api_key =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "⚠️  Warning: The API key doesn't look like a valid UUID format."
    echo "   NVD API keys are typically in UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting without saving API key."
        exit 1
    fi
fi

# Save the API key
echo "$api_key" > .nvd-api-key
chmod 600 .nvd-api-key

echo ""
echo "✅ NVD API key saved to .nvd-api-key"
echo ""
echo "🔧 To use this API key with Gradle, you can:"
echo ""
echo "Option 1: Set environment variable:"
echo "   export NVD_API_KEY=$(cat .nvd-api-key)"
echo ""
echo "Option 2: Add to gradle.properties:"
echo "   systemProp.dependencycheck.nvd.api.key=$(cat .nvd-api-key)"
echo ""
echo "Option 3: Use with task:"
echo "   NVD_API_KEY=$(cat .nvd-api-key) ./gradlew dependencyCheckAnalyze"
echo ""

# Add to .gitignore if not already there
if ! grep -q ".nvd-api-key" .gitignore 2>/dev/null; then
    echo ".nvd-api-key" >> .gitignore
    echo "✅ Added .nvd-api-key to .gitignore"
fi

echo "🎉 Setup complete! Your security scans should now be faster and more reliable." 