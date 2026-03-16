#pragma once
// Luckyware Cleaner - Built-in YARA Engine (no libyara dependency)
// Supports: literal strings, hex patterns, regex strings, nocase modifier,
// and conditions: any/all of ($prefix*), $mz at 0, #mz > 1, and/or/not, parentheses.
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <fstream>
#include <algorithm>
#include <functional>

namespace YaraEngine {

struct YaraString {
    std::string id;        // e.g. $s1, $hex_blob
    std::string value;     // literal value (after unescape)
    bool nocase = false;
    bool is_hex = false;   // pattern defined as { D0 CF ... }
    bool is_regex = false; // pattern defined as /regex/
    std::vector<uint8_t> hex_bytes;
    std::string regex_pattern;
};

struct YaraRule {
    std::string name;
    std::string description;
    std::vector<YaraString> strings;
    std::string condition_raw;

    // Pre-compiled regexes for nocase and regex-type strings (built lazily).
    mutable std::vector<std::pair<int, std::regex>> compiled_regexes;
    mutable bool compiled = false;

    void compile() const {
        if (compiled) return;
        for (int i = 0; i < (int)strings.size(); ++i) {
            const auto& s = strings[i];
            if (s.is_regex) {
                try {
                    auto flags = std::regex::ECMAScript;
                    if (s.nocase) flags |= std::regex::icase;
                    compiled_regexes.push_back({i, std::regex(s.regex_pattern, flags)});
                } catch (...) {}
            } else if (s.nocase && !s.is_hex) {
                try {
                    // Escape regex metacharacters in the literal before compiling
                    std::string escaped;
                    for (char c : s.value) {
                        if (c == '.' || c == '*' || c == '+' || c == '?' ||
                            c == '[' || c == ']' || c == '(' || c == ')' ||
                            c == '{' || c == '}' || c == '\\' || c == '^' || c == '$')
                            escaped += '\\';
                        escaped += c;
                    }
                    compiled_regexes.push_back({i, std::regex(escaped, std::regex::icase)});
                } catch (...) {}
            }
        }
        compiled = true;
    }
};

// Parses a hex pattern string like "{ D0 CF 11 E0 }" into a byte vector.
inline std::vector<uint8_t> parse_hex_pattern(const std::string& hex_str) {
    std::vector<uint8_t> bytes;
    std::string s = hex_str;
    s.erase(std::remove_if(s.begin(), s.end(), [](char c) {
        return c == '{' || c == '}' || c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }), s.end());
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        std::string byte_str = s.substr(i, 2);
        try {
            bytes.push_back(static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16)));
        } catch (...) { break; }
    }
    return bytes;
}

inline std::vector<YaraRule> load_rules(const std::string& filepath) {
    std::vector<YaraRule> rules;
    std::ifstream f(filepath);
    if (!f.is_open()) return rules;

    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    f.close();

    // Strip C-style and C++-style comments before parsing
    std::regex comment_re(R"(//[^\n]*)");
    content = std::regex_replace(content, comment_re, "");
    std::regex block_comment_re(R"(/\*(?:[\s\S]*?)\*/)");
    content = std::regex_replace(content, block_comment_re, "");

    std::regex rule_re(R"(rule\s+(\w+)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\})");
    std::sregex_iterator it(content.begin(), content.end(), rule_re);
    std::sregex_iterator end_it;

    while (it != end_it) {
        std::smatch m = *it;
        YaraRule rule;
        rule.name = m[1].str();
        std::string body = m[2].str();

        std::regex desc_re("description\\s*=\\s*\"([^\"]*)\"");
        std::smatch dm;
        if (std::regex_search(body, dm, desc_re))
            rule.description = dm[1].str();

        std::regex strings_section_re(R"(strings\s*:([\s\S]*?)(?=condition\s*:))");
        std::smatch sm;
        if (std::regex_search(body, sm, strings_section_re)) {
            std::string strings_body = sm[1].str();
            // Matches: $name = "literal" [nocase]
            //          $name = { hex bytes }
            //          $name = /regex/
            std::regex str_re("\\$(\\w+)\\s*=\\s*(?:\"([^\"]*)\"|(\\{[^}]*\\})|/([^/]*)/)(?:\\s+(nocase))?");
            auto sit = std::sregex_iterator(strings_body.begin(), strings_body.end(), str_re);
            auto send = std::sregex_iterator();
            while (sit != send) {
                std::smatch sm2 = *sit;
                YaraString ys;
                ys.id = "$" + sm2[1].str();
                if (sm2[2].matched) {
                    ys.value = sm2[2].str();
                    // Unescape \xHH sequences in the literal
                    std::string unescaped;
                    for (size_t i = 0; i < ys.value.size(); ++i) {
                        if (ys.value[i] == '\\' && i + 1 < ys.value.size()) {
                            if (ys.value[i+1] == 'x' && i + 3 < ys.value.size()) {
                                std::string hex = ys.value.substr(i+2, 2);
                                try { unescaped += (char)std::stoi(hex, nullptr, 16); } catch(...) {}
                                i += 3; continue;
                            }
                            ++i; unescaped += ys.value[i]; continue;
                        }
                        unescaped += ys.value[i];
                    }
                    ys.value = unescaped;
                } else if (sm2[3].matched) {
                    ys.is_hex = true;
                    ys.hex_bytes = parse_hex_pattern(sm2[3].str());
                } else if (sm2[4].matched) {
                    ys.is_regex = true;
                    ys.regex_pattern = sm2[4].str();
                }
                ys.nocase = sm2[5].matched;
                rule.strings.push_back(ys);
                ++sit;
            }
        }

        std::regex cond_re(R"(condition\s*:\s*([\s\S]*?)(?=\}|$))");
        std::smatch cm;
        if (std::regex_search(body, cm, cond_re)) {
            rule.condition_raw = cm[1].str();
            auto& cr = rule.condition_raw;
            cr.erase(0, cr.find_first_not_of(" \t\n\r"));
            cr.erase(cr.find_last_not_of(" \t\n\r") + 1);
        }

        rule.compile();
        rules.push_back(std::move(rule));
        ++it;
    }
    return rules;
}

inline bool find_string_in_data(const std::vector<uint8_t>& data,
                                 const YaraString& ys,
                                 int idx,
                                 const YaraRule& rule) {
    if (ys.is_hex) {
        if (ys.hex_bytes.empty()) return false;
        auto it = std::search(data.cbegin(), data.cend(),
                              ys.hex_bytes.cbegin(), ys.hex_bytes.cend());
        return it != data.cend();
    } else if (ys.is_regex || ys.nocase) {
        rule.compile();
        for (const auto& cr : rule.compiled_regexes) {
            if (cr.first == idx) {
                std::string text(data.begin(), data.end());
                return std::regex_search(text, cr.second);
            }
        }
        return false;
    } else {
        auto it = std::search(data.cbegin(), data.cend(),
                              ys.value.cbegin(), ys.value.cend());
        return it != data.cend();
    }
}

// Evaluates a YARA condition string against a set of per-string match results.
// Supported constructs: any/all of ($prefix*), $mz at 0, #mz > 1, and, or, not, ().
// Uses a simple recursive-descent boolean parser after substituting all variables.
inline bool evaluate_condition(const std::string& condition,
                                const std::vector<bool>& matched,
                                const std::vector<YaraString>& strings,
                                const std::vector<uint8_t>& data) {
    std::map<std::string, bool> m;
    for (size_t i = 0; i < strings.size(); ++i)
        m[strings[i].id] = (i < matched.size()) ? matched[i] : false;

    auto eval_any_of = [&](const std::string& prefix) -> bool {
        for (auto& [id, val] : m) {
            if (id.size() > prefix.size() + 1 &&
                id.substr(1, prefix.size()) == prefix && val)
                return true;
        }
        return false;
    };
    auto eval_all_of = [&](const std::string& prefix) -> bool {
        bool found_any = false;
        for (auto& [id, val] : m) {
            if (id.size() > prefix.size() + 1 &&
                id.substr(1, prefix.size()) == prefix) {
                found_any = true;
                if (!val) return false;
            }
        }
        return found_any;
    };

    bool mz_at_0 = (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z');
    int mz_count = 0;
    for (size_t i = 0; i + 1 < data.size(); ++i)
        if (data[i] == 'M' && data[i+1] == 'Z') ++mz_count;

    std::string eval_cond = condition;

    auto re_any_star = std::regex(R"(any\s+of\s+\(\s*\$([a-zA-Z]+)\*\s*\))");
    {
        std::smatch sm;
        std::string temp;
        while (std::regex_search(eval_cond, sm, re_any_star)) {
            std::string prefix = sm[1].str();
            bool result = eval_any_of(prefix);
            temp = sm.prefix().str() + (result ? "TRUE" : "FALSE") + sm.suffix().str();
            eval_cond = temp;
        }
    }

    auto re_all_star = std::regex(R"(all\s+of\s+\(\s*\$([a-zA-Z]+)\*\s*\))");
    {
        std::smatch sm;
        std::string temp;
        while (std::regex_search(eval_cond, sm, re_all_star)) {
            std::string prefix = sm[1].str();
            bool result = eval_all_of(prefix);
            temp = sm.prefix().str() + (result ? "TRUE" : "FALSE") + sm.suffix().str();
            eval_cond = temp;
        }
    }

    {
        std::regex r(R"(\$mz\s+at\s+0)");
        eval_cond = std::regex_replace(eval_cond, r, mz_at_0 ? "TRUE" : "FALSE");
    }

    {
        std::regex r(R"(#mz\s*>\s*1)");
        eval_cond = std::regex_replace(eval_cond, r, (mz_count > 1) ? "TRUE" : "FALSE");
    }

    for (auto& [id, val] : m) {
        std::string escaped_id = "\\$" + id.substr(1) + "(?![a-zA-Z0-9_])";
        try {
            std::regex r(escaped_id);
            eval_cond = std::regex_replace(eval_cond, r, val ? "TRUE" : "FALSE");
        } catch (...) {}
    }

    // Minimal recursive-descent boolean evaluator for the substituted expression
    struct BoolEval {
        std::string expr;
        size_t pos;

        void skip_ws() {
            while (pos < expr.size() && std::isspace(expr[pos])) ++pos;
        }
        bool parse_atom() {
            skip_ws();
            if (pos + 4 <= expr.size() && expr.substr(pos, 4) == "TRUE") {
                pos += 4; return true;
            }
            if (pos + 5 <= expr.size() && expr.substr(pos, 5) == "FALSE") {
                pos += 5; return false;
            }
            if (pos < expr.size() && expr[pos] == '(') {
                ++pos;
                bool v = parse_or();
                skip_ws();
                if (pos < expr.size() && expr[pos] == ')') ++pos;
                return v;
            }
            while (pos < expr.size() && expr[pos] != ')' && expr[pos] != '\n') ++pos;
            return false;
        }
        bool parse_and() {
            bool v = parse_atom();
            while (true) {
                skip_ws();
                if (pos + 3 <= expr.size() && expr.substr(pos, 3) == "and") {
                    pos += 3;
                    bool v2 = parse_atom();
                    v = v && v2;
                } else break;
            }
            return v;
        }
        bool parse_or() {
            bool v = parse_and();
            while (true) {
                skip_ws();
                if (pos + 2 <= expr.size() && expr.substr(pos, 2) == "or") {
                    pos += 2;
                    bool v2 = parse_and();
                    v = v || v2;
                } else break;
            }
            return v;
        }
        bool eval(const std::string& e) {
            expr = e; pos = 0;
            return parse_or();
        }
    };

    BoolEval be;
    return be.eval(eval_cond);
}

struct MatchResult {
    std::string rule_name;
    std::string description;
    std::vector<std::string> matched_strings;
};

// Reads up to max_size bytes from the file (default 64 MB) to keep memory usage bounded.
inline std::vector<MatchResult> match_file(const std::string& filepath,
                                            const std::vector<YaraRule>& rules,
                                            size_t max_size = 64 * 1024 * 1024) {
    std::vector<MatchResult> results;

    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return results;
    f.seekg(0, std::ios::end);
    size_t file_size = static_cast<size_t>(f.tellg());
    f.seekg(0, std::ios::beg);

    size_t read_size = std::min(file_size, max_size);
    std::vector<uint8_t> data(read_size);
    f.read(reinterpret_cast<char*>(data.data()), read_size);
    f.close();

    for (const auto& rule : rules) {
        std::vector<bool> matched(rule.strings.size(), false);
        for (size_t i = 0; i < rule.strings.size(); ++i) {
            matched[i] = find_string_in_data(data, rule.strings[i], (int)i, rule);
        }

        bool rule_matched = evaluate_condition(rule.condition_raw, matched, rule.strings, data);
        if (rule_matched) {
            MatchResult mr;
            mr.rule_name = rule.name;
            mr.description = rule.description;
            for (size_t i = 0; i < rule.strings.size(); ++i) {
                if (matched[i]) mr.matched_strings.push_back(rule.strings[i].id);
            }
            results.push_back(mr);
        }
    }
    return results;
}

// Extracts domain values from strings whose ID starts with '$d' in the
// Luckyware_C2_Indicators rule.
inline std::vector<std::string> extract_domains(const std::vector<YaraRule>& rules) {
    std::vector<std::string> domains;
    for (size_t ri = 0; ri < rules.size(); ++ri) {
        const YaraRule& rule = rules[ri];
        if (rule.name == "Luckyware_C2_Indicators") {
            for (size_t si = 0; si < rule.strings.size(); ++si) {
                const YaraString& s = rule.strings[si];
                if (!s.id.empty() && s.id[1] == 'd' && !s.value.empty()) {
                    domains.push_back(s.value);
                }
            }
        }
    }
    return domains;
}

} // namespace YaraEngine
