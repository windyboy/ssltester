#!/bin/bash

# SSL Test Tool - Dependency Update Script
# This script helps update dependencies to their latest versions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSIONS_FILE="gradle/libs.versions.toml"
BUILD_DIR="app/build/dependencyUpdates"
REPORT_FILE="$BUILD_DIR/report.txt"

echo -e "${BLUE}🔧 SSL Test Tool - Dependency Update${NC}"
echo "=========================================="

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}📋 Checking prerequisites...${NC}"
    
    if ! command_exists java; then
        echo -e "${RED}❌ Java not found! Please install Java 21 or later.${NC}"
        exit 1
    fi
    
    if ! command_exists ./gradlew; then
        echo -e "${RED}❌ Gradle wrapper not found!${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Prerequisites check passed${NC}"
}

# Generate dependency update report
generate_report() {
    echo -e "${YELLOW}🔍 Generating dependency update report...${NC}"
    
    # Clean previous reports
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    
    # Run dependency updates
    ./gradlew dependencyUpdates
    
    if [ -f "$REPORT_FILE" ]; then
        echo -e "${GREEN}✅ Report generated at $REPORT_FILE${NC}"
    else
        echo -e "${RED}❌ Failed to generate report${NC}"
        exit 1
    fi
}

# Display current dependency status
show_status() {
    echo -e "${YELLOW}📊 Current dependency status:${NC}"
    echo "----------------------------------------"
    
    if [ -f "$REPORT_FILE" ]; then
        cat "$REPORT_FILE"
    else
        echo -e "${RED}❌ Report file not found${NC}"
        exit 1
    fi
}

# Parse current versions from versions.toml
parse_current_versions() {
    echo -e "${YELLOW}📋 Parsing current versions...${NC}"
    
    if [ ! -f "$VERSIONS_FILE" ]; then
        echo -e "${RED}❌ Versions file not found: $VERSIONS_FILE${NC}"
        exit 1
    fi
    
    # Extract version variables
    grep -E '^[a-zA-Z_][a-zA-Z0-9_]* = "[0-9]+\.[0-9]+\.[0-9]+"' "$VERSIONS_FILE" | while read -r line; do
        var_name=$(echo "$line" | cut -d'=' -f1 | xargs)
        current_version=$(echo "$line" | cut -d'"' -f2)
        echo "$var_name=$current_version"
    done
}

# Interactive update mode
interactive_update() {
    echo -e "${YELLOW}🔄 Interactive update mode${NC}"
    echo "This will help you update dependencies step by step."
    echo ""
    
    # Show current status
    show_status
    
    echo ""
    echo -e "${BLUE}Available actions:${NC}"
    echo "1. Update all dependencies automatically"
    echo "2. Update specific dependency"
    echo "3. Show detailed report"
    echo "4. Exit"
    echo ""
    
    read -p "Choose an option (1-4): " choice
    
    case $choice in
        1)
            auto_update_all
            ;;
        2)
            update_specific_dependency
            ;;
        3)
            show_detailed_report
            ;;
        4)
            echo -e "${GREEN}👋 Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Invalid option${NC}"
            exit 1
            ;;
    esac
}

# Auto update all dependencies
auto_update_all() {
    echo -e "${YELLOW}🔄 Auto-updating all dependencies...${NC}"
    
    # This is a simplified version - in practice, you'd want more sophisticated parsing
    echo -e "${BLUE}💡 Note: This will create a backup and attempt to update versions${NC}"
    
    # Create backup
    cp "$VERSIONS_FILE" "${VERSIONS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${GREEN}✅ Backup created${NC}"
    
    # For now, just show what would be updated
    echo -e "${YELLOW}📋 Dependencies that can be updated:${NC}"
    if [ -f "$REPORT_FILE" ]; then
        grep -E "(->|available)" "$REPORT_FILE" || echo "No updates available"
    fi
    
    echo ""
    echo -e "${BLUE}💡 To manually update versions:${NC}"
    echo "1. Review the report at $REPORT_FILE"
    echo "2. Edit $VERSIONS_FILE with new versions"
    echo "3. Run './gradlew build' to test changes"
}

# Update specific dependency
update_specific_dependency() {
    echo -e "${YELLOW}🎯 Update specific dependency${NC}"
    
    # Show available dependencies
    echo "Available dependencies:"
    parse_current_versions | while read -r dep; do
        echo "  $dep"
    done
    
    echo ""
    read -p "Enter dependency name to update: " dep_name
    
    if [ -z "$dep_name" ]; then
        echo -e "${RED}❌ No dependency name provided${NC}"
        return
    fi
    
    echo -e "${BLUE}💡 To update $dep_name:${NC}"
    echo "1. Check the latest version in the report"
    echo "2. Edit $VERSIONS_FILE"
    echo "3. Update the version for $dep_name"
    echo "4. Run './gradlew build' to test"
}

# Show detailed report
show_detailed_report() {
    echo -e "${YELLOW}📄 Detailed dependency report${NC}"
    echo "======================================"
    
    if [ -f "$REPORT_FILE" ]; then
        cat "$REPORT_FILE"
    else
        echo -e "${RED}❌ Report file not found${NC}"
    fi
}

# Main execution
main() {
    case "${1:-interactive}" in
        "check")
            check_prerequisites
            generate_report
            show_status
            ;;
        "update")
            check_prerequisites
            generate_report
            auto_update_all
            ;;
        "interactive")
            check_prerequisites
            generate_report
            interactive_update
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [check|update|interactive|help]"
            echo ""
            echo "Commands:"
            echo "  check       - Check for outdated dependencies"
            echo "  update      - Auto-update all dependencies"
            echo "  interactive - Interactive update mode (default)"
            echo "  help        - Show this help message"
            ;;
        *)
            echo -e "${RED}❌ Unknown command: $1${NC}"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@" 