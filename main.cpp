#include <iostream>
#include <memory>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <string>

#include "./data_processor.h"
#include "config/config_manager.h"
#include "file_scanner.h"
#include "report_generator.h"
#include "sensitive_data_detector.h"
#include "utils/version.h"

// 初始化日志系统
void init_logging(const std::string &log_file) {
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  auto file_sink =
      std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file);

  console_sink->set_level(spdlog::level::info);
  file_sink->set_level(spdlog::level::debug);

  spdlog::logger logger("main", {console_sink, file_sink});
  logger.set_level(spdlog::level::debug);

  spdlog::set_default_logger(std::make_shared<spdlog::logger>(logger));
}

// 显示帮助信息
void print_help(const std::string &program_name) {
  std::cout << "SecureDataShield - 敏感数据扫描与自动化处理工具\n";
  std::cout << "版本: " << SECURE_DATA_SHIELD_VERSION << "\n\n";
  std::cout << "用法: " << program_name << " [选项] <扫描路径>\n\n";
  std::cout << "选项:\n";
  std::cout << "  -c, --config <文件>   指定配置文件路径\n";
  std::cout << "  -o, --output <目录>   指定输出目录\n";
  std::cout << "  -r, --report <格式>   报告格式 (html, csv, json)\n";
  std::cout << "  -t, --threads <数量>  指定线程数\n";
  std::cout << "  -d, --dry-run         仅扫描不处理\n";
  std::cout << "  -v, --verbose         详细输出\n";
  std::cout << "  -h, --help            显示帮助信息\n";
  std::cout << "  --version             显示版本信息\n";
}

int main(int argc, char *argv[]) {
  try {
    // 解析命令行参数
    std::string config_path;
    std::string output_dir;
    std::string report_format = "html";
    std::string scan_path;
    int thread_count = 0;
    bool dry_run = false;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "-h" || arg == "--help") {
        print_help(argv[0]);
        return 0;
      } else if (arg == "--version") {
        std::cout << "SecureDataShield " << SECURE_DATA_SHIELD_VERSION
                  << std::endl;
        return 0;
      } else if (arg == "-c" || arg == "--config") {
        if (i + 1 < argc)
          config_path = argv[++i];
        else {
          std::cerr << "错误: 缺少配置文件参数\n";
          return 1;
        }
      } else if (arg == "-o" || arg == "--output") {
        if (i + 1 < argc)
          output_dir = argv[++i];
        else {
          std::cerr << "错误: 缺少输出目录参数\n";
          return 1;
        }
      } else if (arg == "-r" || arg == "--report") {
        if (i + 1 < argc)
          report_format = argv[++i];
        else {
          std::cerr << "错误: 缺少报告格式参数\n";
          return 1;
        }
      } else if (arg == "-t" || arg == "--threads") {
        if (i + 1 < argc)
          thread_count = std::stoi(argv[++i]);
        else {
          std::cerr << "错误: 缺少线程数参数\n";
          return 1;
        }
      } else if (arg == "-d" || arg == "--dry-run") {
        dry_run = true;
      } else if (arg == "-v" || arg == "--verbose") {
        verbose = true;
      } else if (scan_path.empty()) {
        scan_path = arg;
      } else {
        std::cerr << "错误: 未知参数 " << arg << std::endl;
        return 1;
      }
    }

    if (scan_path.empty()) {
      std::cerr << "错误: 未指定扫描路径\n";
      print_help(argv[0]);
      return 1;
    }

    // 初始化日志
    init_logging("securedatashield.log");
    spdlog::info("SecureDataShield 版本: {}", SECURE_DATA_SHIELD_VERSION);
    spdlog::info("扫描路径: {}", scan_path);

    // 加载配置
    ConfigManager config_manager;
    if (!config_path.empty()) {
      config_manager.load_from_file(config_path);
    }

    // 应用命令行参数到配置
    if (!output_dir.empty()) {
      config_manager.set_output_directory(output_dir);
    }
    config_manager.set_report_format(report_format);
    if (thread_count > 0) {
      config_manager.set_thread_count(thread_count);
    }
    config_manager.set_dry_run(dry_run);
    config_manager.set_verbose(verbose);

    // 初始化扫描器
    FileScanner scanner(config_manager);

    // 扫描文件
    spdlog::info("开始扫描文件...");
    auto files = scanner.scan(scan_path);
    spdlog::info("扫描完成，找到 {} 个文件", files.size());

    if (files.empty()) {
      spdlog::info("没有找到需要处理的文件");
      return 0;
    }

    // 初始化敏感数据识别器
    SensitiveDataDetector detector(config_manager);

    // 识别敏感数据
    spdlog::info("开始识别敏感数据...");
    auto detection_results = detector.detect_in_files(files);
    spdlog::info("敏感数据识别完成");

    // 处理敏感数据（如果不是dry run）
    DataProcessor processor(config_manager);
    std::vector<ProcessingResult> processing_results;

    if (!dry_run) {
      spdlog::info("开始处理敏感数据...");
      processing_results = processor.process(detection_results);
      spdlog::info("敏感数据处理完成");
    }

    // 生成报告
    spdlog::info("生成报告...");
    ReportGenerator report_generator(config_manager);
    report_generator.generate(detection_results, processing_results);
    spdlog::info("报告已生成: {}", report report_generator.get_report_path());

    spdlog::info("操作完成");
    return 0;
  } catch (const std::exception &e) {
    spdlog::critical("程序异常终止: {}", e.what());
    return 1;
  }
}
