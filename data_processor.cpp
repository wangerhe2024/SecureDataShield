#include "data_processor.h"
#include <spdlog/spdlog.h>
#include <tbb/parallel_for.h>
#include <algorithm>
#include <sstream>

// 脱敏处理器实现
std::string MaskingProcessor::mask_value(SensitiveType type, const std::string& value) {
    switch (type) {
        case SensitiveType::ID_CARD: {
            // 身份证号：显示前6位和后4位，中间用*代替
            if (value.size() == 18) {
                return value.substr(0, 6) + "********" + value.substr(14);
            }
            return value;
        }
        case SensitiveType::PHONE_NUMBER: {
            // 手机号：显示前3位和后4位，中间用*代替
            if (value.size() == 11) {
                return value.substr(0, 3) + "****" + value.substr(7);
            }
            return value;
        }
        case SensitiveType::EMAIL: {
            // 邮箱：显示第一个字符和域名，中间用*代替
            size_t at_pos = value.find('@');
            if (at_pos != std::string::npos && at_pos > 1) {
                return value.substr(0, 1) + "*****" + value.substr(at_pos);
            }
            return value;
        }
        case SensitiveType::BANK_CARD: {
            // 银行卡号：显示最后4位，前面用*代替
            if (value.size() >= 4) {
                std::string last4 = value.substr(value.size() - 4);
                return "************" + last4;
            }
            return value;
        }
        case SensitiveType::API_KEY: {
            // API密钥：显示前4位和后4位，中间用*代替
            if (value.size() >= 8) {
                return value.substr(0, 4) + "****************" + value.substr(value.size() - 4);
            }
            return value;
        }
        default: {
            // 其他类型：显示前2位和后2位，中间用*代替
            if (value.size() > 4) {
                return value.substr(0, 2) + "*****" + value.substr(value.size() - 2);
            } else if (value.size() > 1) {
                return value.substr(0, 1) + "***";
            }
            return "***";
        }
    }
}

std::string MaskingProcessor::process(const std::string& text, const std::vector<SensitiveMatch>& matches) {
    if (matches.empty()) {
        return text;
    }

    // 创建结果字符串
    std::string result;
    result.reserve(text.size());

    size_t last_pos = 0;

    // 按位置处理每个匹配项
    for (const auto& match : matches) {
        // 添加上一个匹配项结束到当前匹配项开始之间的文本
        if (match.start_pos > last_pos) {
            result.append(text.substr(last_pos, match.start_pos - last_pos));
        }

        // 添加脱敏后的值
        result.append(mask_value(match.type, match.value));

        // 更新最后处理位置
        last_pos = match.start_pos + match.length;
    }

    // 添加剩余文本
    if (last_pos < text.size()) {
        result.append(text.substr(last_pos));
    }

    return result;
}

// 加密处理器实现
std::string EncryptionProcessor::process(const std::string& text, const std::vector<SensitiveMatch>& matches) {
    if (matches.empty()) {
        return text;
    }

    // 创建结果字符串
    std::string result;
    result.reserve(text.size() * 2);  // 预留更多空间，因为加密后会变长

    size_t last_pos = 0;

    // 按位置处理每个匹配项
    for (const auto& match : matches) {
        // 添加上一个匹配项结束到当前匹配项开始之间的文本
        if (match.start_pos > last_pos) {
            result.append(text.substr(last_pos, match.start_pos - last_pos));
        }

        // 加密敏感值，并添加加密标记
        std::string encrypted = crypto_service_.encrypt(match.value);
        result.append("[ENC(" + encrypted + ")]");

        // 更新最后处理位置
        last_pos = match.start_pos + match.length;
    }

    // 添加剩余文本
    if (last_pos < text.size()) {
        result.append(text.substr(last_pos));
    }

    return result;
}

// 匿名化处理器实现
std::string AnonymizationProcessor::process(const std::string& text, const std::vector<SensitiveMatch>& matches) {
    if (matches.empty()) {
        return text;
    }

    // 创建结果字符串
    std::string result;
    result.reserve(text.size());

    size_t last_pos = 0;

    // 按位置处理每个匹配项
    for (const auto& match : matches) {
        // 添加上一个匹配项结束到当前匹配项开始之间的文本
        if (match.start_pos > last_pos) {
            result.append(text.substr(last_pos, match.start_pos - last_pos));
        }

        // 对敏感值进行哈希处理（不可逆）
        std::string hashed = crypto_service_.hash(match.value);
        result.append("[HASH(" + hashed.substr(0, 16) + ")]");  // 只取前16位哈希值

        // 更新最后处理位置
        last_pos = match.start_pos + match.length;
    }

    // 添加剩余文本
    if (last_pos < text.size()) {
        result.append(text.substr(last_pos));
    }

    return result;
}

// 数据处理器管理器实现
DataProcessor::DataProcessor(const ConfigManager& config)
    : config_(config), file_handler_(config), crypto_service_(config) {
    select_processor();
}

void DataProcessor::select_processor() {
    std::string strategy = config_.get_processing_strategy();
    
    if (strategy == "encryption") {
        processor_ = std::make_unique<EncryptionProcessor>(crypto_service_);
        spdlog::info("选择加密处理策略");
    } else if (strategy == "anonymization") {
        processor_ = std::make_unique<AnonymizationProcessor>(crypto_service_);
        spdlog::info("选择匿名化处理策略");
    } else {
        // 默认使用脱敏策略
        processor_ = std::make_unique<MaskingProcessor>();
        spdlog::info("选择脱敏处理策略");
    }
}

ProcessingResult DataProcessor::process_file(const FileDetectionResult& detection_result) {
    ProcessingResult result;
    result.original_path = detection_result.file_path;
    result.processed_count = 0;
    result.success = false;

    try {
        if (detection_result.error_occurred) {
            result.error_message = "检测阶段错误: " + detection_result.error_message;
            return result;
        }

        if (detection_result.matches.empty()) {
            // 没有敏感数据，无需处理
            result.success = true;
            result.processed_path = detection_result.file_path;
            return result;
        }

        spdlog::debug("处理文件: {}", detection_result.file_path.string());

        // 读取文件内容
        SecureBuffer buffer = file_handler_.read_file_secure(detection_result.file_path);
        std::string content(buffer.data(), buffer.size());

        // 处理内容
        std::string processed_content = processor_->process(content, detection_result.matches);
        result.processed_count = detection_result.matches.size();

        // 确定输出路径
        std::filesystem::path output_dir = config_.get_output_directory();
        if (output_dir.empty()) {
            // 如果未指定输出目录，在原目录创建处理后的文件
            output_dir = detection_result.file_path.parent_path();
            result.processed_path = output_dir / (detection_result.file_path.stem().string() + ".processed" + detection_result.file_path.extension().string());
        } else {
            // 使用指定的输出目录，保持原目录结构
            std::filesystem::create_directories(output_dir);
            result.processed_path = output_dir / detection_result.file_path.filename();
        }

        // 写入处理后的内容
        file_handler_.write_file_secure(result.processed_path, processed_content);

        // 清理缓冲区
        buffer.clear();

        result.success = true;
        spdlog::debug("文件 {} 处理完成，处理了 {} 处敏感数据",
                     detection_result.file_path.string(), result.processed_count);
    } catch (const std::exception& e) {
        spdlog::error("文件 {} 处理错误: {}", detection_result.file_path.string(), e.what());
        result.error_message = e.what();
    }

    return result;
}

std::vector<ProcessingResult> DataProcessor::process(const std::vector<FileDetectionResult>& detection_results) {
    std::vector<ProcessingResult> results(detection_results.size());
    
    // 使用TBB并行处理文件
    tbb::parallel_for(size_t(0), detection_results.size(), [&](size_t i) {
        results[i] = process_file(detection_results[i]);
    });
    
    return results;
}

std::string DataProcessor::strategy_to_string(ProcessingStrategy strategy) {
    switch (strategy) {
        case ProcessingStrategy::MASKING: return "脱敏";
        case ProcessingStrategy::ENCRYPTION: return "加密";
        case ProcessingStrategy::ANONYMIZATION: return "匿名化";
        default: return "未知策略";
    }
}
