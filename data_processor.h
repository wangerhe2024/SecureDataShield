#ifndef DATA_PROCESSOR_H
#define DATA_PROCESSOR_H

#include <vector>
#include <string>
#include <memory>
#include <filesystem>
#include "config/config_manager.h"
#include "detector/sensitive_data_detector.h"
#include "crypto/crypto_service.h"
#include "file_handler/file_handler.h"

// 处理策略枚举
enum class ProcessingStrategy {
    MASKING,        // 脱敏
    ENCRYPTION,     // 加密
    ANONYMIZATION   // 匿名化
};

// 处理结果
struct ProcessingResult {
    std::filesystem::path original_path;    // 原始文件路径
    std::filesystem::path processed_path;   // 处理后文件路径
    size_t processed_count;                 // 处理的敏感数据数量
    bool success;                           // 是否成功
    std::string error_message;              // 错误信息
};

// 处理器接口
class DataProcessorInterface {
public:
    virtual ~DataProcessorInterface() = default;
    virtual std::string process(const std::string& text, const std::vector<SensitiveMatch>& matches) = 0;
    virtual ProcessingStrategy strategy() const = 0;
};

// 脱敏处理器
class MaskingProcessor : public DataProcessorInterface {
private:
    // 根据不同类型采用不同的脱敏策略
    std::string mask_value(SensitiveType type, const std::string& value);

public:
    std::string process(const std::string& text, const std::vector<SensitiveMatch>& matches) override;
    ProcessingStrategy strategy() const override { return ProcessingStrategy::MASKING; }
};

// 加密处理器
class EncryptionProcessor : public DataProcessorInterface {
private:
    CryptoService& crypto_service_;

public:
    explicit EncryptionProcessor(CryptoService& crypto_service) : crypto_service_(crypto_service) {}
    std::string process(const std::string& text, const std::vector<SensitiveMatch>& matches) override;
    ProcessingStrategy strategy() const override { return ProcessingStrategy::ENCRYPTION; }
};

// 匿名化处理器
class AnonymizationProcessor : public DataProcessorInterface {
private:
    CryptoService& crypto_service_;

public:
    explicit AnonymizationProcessor(CryptoService& crypto_service) : crypto crypto_service_(crypto_service) {}
    std::string process(const std::string& text, const std::vector<SensitiveMatch>& matches) override;
    ProcessingStrategy strategy() const override { return ProcessingStrategy::ANONYMIZATION; }
};

// 数据处理器管理器
class DataProcessor {
private:
    ConfigManager config_;
    FileHandler file_handler_;
    CryptoService crypto_service_;
    std::unique_ptr<DataProcessorInterface> processor_;

    // 根据配置选择合适的处理器
    void select_processor();

    // 处理单个文件
    ProcessingResult process_file(const FileDetectionResult& detection_result);

public:
    explicit DataProcessor(const ConfigManager& config);

    // 批量处理文件
    std::vector<ProcessingResult> process(const std::vector<FileDetectionResult>& detection_results);

    // 获取处理策略的字符串表示
    static std::string strategy_to_string(ProcessingStrategy strategy);
};

#endif // DATA_PROCESSOR_H
