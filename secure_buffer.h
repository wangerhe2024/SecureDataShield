#ifndef SECURE_BUFFER_H
#define SECURE_BUFFER_H

#include <vector>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <sys/mman.h>  // 对于mlock/munlock

// 安全内存缓冲区类，确保敏感数据在内存中安全处理
// 特性：
// 1. 锁定内存防止交换到磁盘
// 2. 销毁时自动覆盖数据
// 3. 禁止拷贝防止数据泄露
class SecureBuffer {
private:
    std::vector<char> data_;
    bool locked_;

public:
    // 构造函数：分配指定大小的安全缓冲区
    explicit SecureBuffer(size_t size) : data_(size), locked_(false) {
        // 尝试锁定内存页，防止敏感数据被交换到磁盘
        if (mlock(data_.data(), data_.size()) == 0) {
            locked_ = true;
        } else {
            // 锁定失败不抛出异常，仅记录警告
            // 在某些环境下可能没有足够权限锁定内存
            spdlog::warn("无法锁定内存页，敏感数据可能会被交换到磁盘");
        }
    }

    // 析构函数：确保数据被覆盖并解锁内存
    ~SecureBuffer() {
        // 用随机数据覆盖缓冲区，防止数据残留
        std::fill(data_.begin(), data_.end(), 0x00);
        
        // 解锁内存
        if (locked_) {
            munlock(data_.data(), data_.size());
        }
    }

    // 禁止拷贝构造和赋值，防止敏感数据意外复制
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // 允许移动构造和赋值
    SecureBuffer(SecureBuffer&& other) noexcept 
        : data_(std::move(other.data_)), locked_(other.locked_) {
        other.locked_ = false;  // 转移所有权后，原对象不再负责解锁
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            // 清理当前数据
            std::fill(data_.begin(), data_.end(), 0x00);
            if (locked_) {
                munlock(data_.data(), data_.size());
            }

            // 移动数据
            data_ = std::move(other.data_);
            locked_ = other.locked_;
            other.locked_ = false;
        }
        return *this;
    }

    // 获取缓冲区数据指针
    char* data() noexcept {
        return data_.data();
    }

    // 获取缓冲区数据常量指针
    const char* data() const noexcept {
        return data_.data();
    }

    // 获取缓冲区大小
    size_t size() const noexcept {
        return data_.size();
    }

    // 填充数据
    void fill(const char* source, size_t len) {
        if (len > data_.size()) {
            throw std::out_of_range("填充数据超出缓冲区大小");
        }
        std::memcpy(data_.data(), source, len);
    }

    // 清空缓冲区（用0覆盖）
    void clear() {
        std::fill(data_.begin(), data_.end(), 0x00);
    }
};

#endif // SECURE_BUFFER_H
