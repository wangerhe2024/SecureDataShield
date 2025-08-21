#ifndef SENSITIVE_DATA_DETECTOR_H
#define SENSITIVE_DATA_DETECTOR_H

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <regex>
#include <re2/re2.h>
#include <filesystem>
#include "config/config_manager.h"
#include "utils/secure_buffer.h"
#include "file_handler/file_handler.h"

// 敏感数据类型枚举
enum class SensitiveType {
    UNKNOWN,
    ID_CARD,         // 身份证号
    PHONE_NUMBER,    // 手机号码
    EMAIL,           // 邮箱地址
    BANK_CARD,       // 银行卡号
    IP_ADDRESS,      // IP地址
    MAC_ADDRESS,     // MAC地址
    API_KEY,         // API密钥
    PASSWORD,        // 密码
    CREDIT_CARD,     // 信用卡号
    PASSPORT,        // 护照号
    LICENSE_PLATE    // 车牌号
};

// 敏感数据匹配结果
struct SensitiveMatch {
    SensitiveType type;          // 敏感数据类型
    std::string value;           // 匹配到的原始值
    size_t start_pos;            // 在文本中的起始位置
    size_t length;               // 长度
    double confidence;           // 置信度（0-1）
};

// 单个文件的检测结果
struct FileDetectionResult {
    std::filesystem::path file_path;  // 文件路径
    std::vector<SensitiveMatch> matches;  // 匹配结果
    bool error_occurred;          // 是否发生错误
    std::string error_message;    // 错误信息
};

// 识别规则接口
class DetectionRule {
public:
    virtual ~DetectionRule() = default;
    virtual SensitiveType type() const = 0;
    virtual std::vector<SensitiveMatch> detect(const std::string& text) const = 0;
};

// 基于正则表达式的识别规则
class RegexRule : public DetectionRule {
private:
    SensitiveType type_;
    std::string pattern_;
    std::unique_ptr<re2::RE2> regex_;
    double confidence_;

public:
    RegexRule(SensitiveType type, const std::string& pattern, double confidence = 1.0);
    ~RegexRule() override = default;

    SensitiveType type() const override { return type_; }
    std::vector<SensitiveMatch> detect(const std::string& text) const override;
};

// 敏感数据识别器
class SensitiveDataDetector {
private:
    ConfigManager config_;
    std::vector<std::unique_ptr<DetectionRule>> rules_;
    FileHandler file_handler_;

    // 初始化默认规则
    void init_default_rules();
    
    // 从配置加载自定义规则
    void load_custom_rules();

public:
    explicit SensitiveDataDetector(const ConfigManager& config);

    // 检测文本中的敏感数据
    std::vector<SensitiveMatch> detect(const std::string& text);

    // 检测文件中的敏感数据
    FileDetectionResult detect_in_file(const std::filesystem::path& file_path);

    // 批量检测文件中的敏感数据（并行处理）
    std::vector<FileDetectionResult> detect_in_files(const std::vector<std::filesystem::path>& file_paths);

    // 获取敏感数据类型的字符串表示
    static std::string type_to_string(SensitiveType type);
};

#endif // SENSITIVE_DATA_DETECTOR_H
