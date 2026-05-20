#include "rule.h"
#include <regex>

/*
 * File destruction: basic destructive operations (Warning).
 * Redirect checking moved to sensitive-paths.cpp.
 * This module handles: find -delete, dd (with of=), shred (with path arg).
 */

std::vector<Violation> checkFileDestruction(const std::string& command) {
    std::vector<Violation> violations;

    // Use blankQuoted so commands inside quotes are invisible.
    // This prevents false positives like: bash -c 'dd if=/dev/zero of=/dev/sda'
    std::string processed = blankQuoted(command);

    // find ... -delete
    static const std::regex find_delete_re("\\bfind\\b.*-delete\\b");
    if (std::regex_search(processed, find_delete_re)) {
        violations.push_back({"file-destruction", Severity::WARNING,
            "find -delete detected: can recursively delete files matching a pattern"});
    }

    // dd — only flag when there's an of= arg (actual write target)
    static const std::regex dd_re("\\bdd\\b.*\\bof=");
    if (std::regex_search(processed, dd_re)) {
        violations.push_back({"file-destruction", Severity::WARNING,
            "dd detected: low-level block copy can overwrite disks or files"});
    }

    // shred — only flag when there's a path arg (not --help, --version, etc.)
    // Allow single-dash flags like -zvf before the path: shred -zvf secret.txt
    // Exclude double-dash flags like --help, --version (those are info-only).
    static const std::regex shred_re("\\bshred\\b(\\s+-[a-zA-Z]+)*\\s+[^-]\\S*");
    if (std::regex_search(processed, shred_re)) {
        violations.push_back({"file-destruction", Severity::WARNING,
            "shred detected: securely overwrites files, making recovery impossible"});
    }

    return violations;
}
