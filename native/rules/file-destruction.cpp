#include "rule.h"
#include <regex>

/*
 * File destruction: basic destructive operations (Warning).
 * Redirect checking moved to sensitive-paths.cpp.
 * This module handles: find -delete, dd, shred.
 */

std::vector<Violation> checkFileDestruction(const std::string& command) {
    std::vector<Violation> violations;

    // find ... -delete
    static const std::regex find_delete_re("\\bfind\\b.*-delete\\b");
    if (std::regex_search(command, find_delete_re)) {
        violations.push_back({"file-destruction", Severity::WARNING,
            "find -delete detected: can recursively delete files matching a pattern"});
    }

    // dd
    static const std::regex dd_re("\\bdd\\b");
    if (std::regex_search(command, dd_re)) {
        violations.push_back({"file-destruction", Severity::WARNING,
            "dd detected: low-level block copy can overwrite disks or files"});
    }

    // shred
    static const std::regex shred_re("\\bshred\\b");
    if (std::regex_search(command, shred_re)) {
        violations.push_back({"file-destruction", Severity::WARNING,
            "shred detected: securely overwrites files, making recovery impossible"});
    }

    return violations;
}
