#include "sensitive_data_detector.h"
#include <spdlog/spdlog.h>
#include <tbb/parallel_for.h>
#include <algorithm>

// 正则规则实现
RegexRule::RegexRule(SensitiveType type, const std::string& pattern, double confidence)
    : type_(type), pattern_(pattern), confidence_(confidence) {
    regex_ = std::make_unique<re2::RE2>(pattern);
    if (!regex_->ok()) {
        throw std::invalid_argument("无效的正则表达式: " + pattern + " 错误: " + regex_->error());
    }
}

std::vector<SensitiveMatch> RegexRule::detect(const std::string& text) const {
    std::vector<SensitiveMatch> matches;
    re2::StringPiece input(text);
    re2::StringPiece match;
    
    while (RE2::FindAndConsume(&input, *regex_, &match)) {
        SensitiveMatch m;
        m.type = type_;
        m.value = match.as_string();
        m.start_pos = text.size() - input.size() - match.size();
        m.length = match.size();
        m.confidence = confidence_;
        matches.push_back(m);
    }
    
    return matches;
}

// 敏感数据识别器实现
SensitiveDataDetector::SensitiveDataDetector(const ConfigManager& config) 
    : config_(config), file_handler_(config) {
    init_default_rules();
    load_custom_rules();
    spdlog::info("初始化敏感数据识别器，加载了 {} 条规则", rules_.size());
}

void SensitiveDataDetector::init_default_rules() {
    // 身份证号规则 (18位，最后一位可能是X)
    rules_.emplace_back(std::make_unique<RegexRule>(
        SensitiveType::ID_CARD,
        R"(\b\d{17}[\dXx]\b)",
        0.99
    ));
    
    // 手机号规则 (11位数字，以1开头)
    rules_.emplace_back(std::make_unique<RegexRule>(
        SensitiveType::PHONE_NUMBER,
        R"(\b1[3-9]\d{9}\b)",
        0.99
    ));
    
    // 邮箱地址规则
    rules_.emplace_back(std::make_unique<RegexRule>(
        SensitiveType::EMAIL,
        R"(\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b)",
        0.95
    ));
    
    // 银行卡号规则 (16-19位数字，可能有空格分隔)
    rules_.emplace_back(std::make_unique<RegexRule>(
        SensitiveType::BANK_CARD,
        R"(\b(?:\d{4}[-\s]?){3}\d{4,7}\b)",
        0.90
    ));
    
    // IP地址规则
    rules_.emplace_back(std::make_unique<RegexRule>(
        SensitiveType::IP_ADDRESS,
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)",
        0.99
    ));
    
    // MAC地址规则
    rules_.emplace_back(std::make_unique<RegexRule>(
        SensitiveType::MAC_ADDRESS,
        R"(\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b)",
        0.99
    ));
    
    // API密钥规则 (32位或64位字母数字)
    rules_.emplace_back(std::make_unique<RegexRule>(
        SensitiveType::API_KEY,
        R"(\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{64})\b)",
        0.85
    ));
}

void SensitiveDataDetector::load_custom_rules() {
    // 从配置加载自定义规则
    auto custom_rules = config_.get_custom_detection_rules();
    for (const auto& rule : custom_rules) {
        try {
            SensitiveType type = string_to_type(rule.type);
            rules_.emplace_back(std::make_unique<RegexRule>(
                type,
                rule.pattern,
                rule.confidence
            ));
            spdlog::info("加载自定义规则: {}", rule.name);
        } catch (const std::exception& e) {
            spdlog::error("加载自定义规则失败: {}", e.what());
        }
    }
}

std::vector<SensitiveMatch> SensitiveDataDetector::detect(const std::string& text) {
    std::vector<SensitiveMatch> all_matches;
    
    // 应用所有规则进行匹配
    for (const auto& rule : rules_) {
        auto matches = rule->detect(text);
        all_matches.insert(all_matches.end(), matches.begin(), matches.end());
    }
    
    // 按位置排序
    std::sort(all_matches.begin(), all_matches.end(),
              [](const SensitiveMatch& a, const SensitiveMatch& b) {
                  return a.start_pos < b.start_pos;
              });
              
    return all_matches;
}

FileDetectionResult SensitiveDataDetector::detect_in_file(const std::filesystem::path& file_path) {
    FileDetectionResult result;
    result.file_path = file_path;
    result.error_occurred = false;
    
    try {
        spdlog::debug("开始检测文件: {}", file_path.string());
        
        // 安全读取文件内容
        SecureBuffer buffer = file_handler_.read_file_secure(file_path);
        std::string content(buffer.data(), buffer.size());
        
        // 检测敏感数据
        result.matches = detect(content);
        
        // 清理缓冲区
        buffer.clear();
        
        spdlog::debug("文件 {} 检测完成，发现 {} 处敏感数据",
                     file_path.string(), result.matches.size());
    } catch (const std::exception& e) {
        spdlog::error("文件 {} 检测错误: {}", file_path.string(), e.what());
        result.error_occurred = true;
        result.error_message = e.what();
    }
    
    return result;
}

std::vector<FileDetectionResult> SensitiveDataDetector::detect_in_files(const std::vector<std::filesystem::path>& file_paths) {
    std::vector<FileDetectionResult> results(file_paths.size());
    
    // 使用TBB并行处理文件检测
    tbb::parallel_for(size_t(0), file_paths.size(), [&](size_t i) {
        results[i] = detect_in_file(file_paths[i]);
    });
    
    return results;
}

std::string SensitiveDataDetector::type_to_string(SensitiveType type) {
    switch (type) {
        case SensitiveType::ID_CARD: return "身份证号";
        case SensitiveType::PHONE_NUMBER: return "手机号码";
        case SensitiveType::EMAIL: return "邮箱地址";
        case SensitiveType::BANK_CARD: return "银行卡号";
        case SensitiveType::IP_ADDRESS: return "IP地址";
        case SensitiveType::MAC_ADDRESS: return "MAC地址";
        case SensitiveType::API_KEY: return "API密钥";
        case SensitiveType::PASSWORD: return "密码";
        case SensitiveType::CREDIT_CARD: return "信用卡号";
        case SensitiveType::PASSPORT: return "护照号";
        case SensitiveType::LICENSE_PLATE: return "车牌号";
        default: return "未知类型";
    }
}
