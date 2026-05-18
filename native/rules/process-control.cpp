#include "rule.h"
#include <regex>

/*
 * Process control: detect commands that manage or background processes.
 *
 * Patterns:
 *   kill, killall, pkill  — signal/terminate other processes
 *   nohup                 — run immune to hangups
 *   disown                — remove from shell's job table
 *   trailing &            — background a process (but not && or &>)
 */

std::vector<Violation> checkProcessControl(const std::string& command) {
    std::vector<Violation> violations;

    // kill / killall / pkill
    static const std::regex kill_re("\\b(kill|killall|pkill)\\b");
    if (std::regex_search(command, kill_re)) {
        violations.push_back({
            "process-control",
            Severity::WARNING,
            "Process control detected: kill/killall/pkill can terminate system processes"
        });
    }

    // nohup
    static const std::regex nohup_re("\\bnohup\\b");
    if (std::regex_search(command, nohup_re)) {
        violations.push_back({
            "process-control",
            Severity::WARNING,
            "nohup detected: process will survive session termination"
        });
    }

    // disown
    static const std::regex disown_re("\\bdisown\\b");
    if (std::regex_search(command, disown_re)) {
        violations.push_back({
            "process-control",
            Severity::WARNING,
            "disown detected: process removed from shell job table"
        });
    }

    // Background with & — but NOT && (chained), &> (redirect), or >& (fd redirect)
    // Strategy: scan for & not preceded/followed by &, >, or <
    for (size_t i = 0; i < command.size(); ++i) {
        if (command[i] == '&') {
            bool prev_amp = (i > 0 && command[i - 1] == '&');
            bool next_amp = (i + 1 < command.size() && command[i + 1] == '&');
            bool next_gt  = (i + 1 < command.size() && command[i + 1] == '>');
            bool prev_gt  = (i > 0 && command[i - 1] == '>');
            bool prev_lt  = (i > 0 && command[i - 1] == '<');

            if (!prev_amp && !next_amp && !next_gt && !prev_gt && !prev_lt) {
                violations.push_back({
                    "process-control",
                    Severity::WARNING,
                    "Background process (&) detected: process will run independently of the shell"
                });
                break; // one violation is enough for this category
            }
        }
    }

    return violations;
}
