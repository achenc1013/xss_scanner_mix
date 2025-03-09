#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
日志模块，负责管理日志输出
"""

import os
import logging
import sys
from datetime import datetime

class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""
    
    # 定义颜色代码
    COLORS = {
        'DEBUG': '\033[94m',  # 蓝色
        'INFO': '\033[92m',   # 绿色
        'WARNING': '\033[93m', # 黄色
        'ERROR': '\033[91m',  # 红色
        'CRITICAL': '\033[91m\033[1m', # 红色加粗
        'RESET': '\033[0m'    # 重置
    }
    
    def __init__(self, fmt=None, datefmt=None, style='%', use_color=True):
        """
        初始化格式化器
        
        Args:
            fmt: 日志格式
            datefmt: 日期格式
            style: 格式风格
            use_color: 是否使用彩色输出
        """
        super().__init__(fmt, datefmt, style)
        self.use_color = use_color and sys.platform != 'win32' or os.name == 'posix'
    
    def format(self, record):
        """
        格式化日志记录
        
        Args:
            record: 日志记录
            
        Returns:
            str: 格式化后的日志
        """
        levelname = record.levelname
        
        # 使用原始格式化方法格式化日志
        message = super().format(record)
        
        # 如果启用了彩色输出，则添加颜色
        if self.use_color and levelname in self.COLORS:
            message = f"{self.COLORS[levelname]}{message}{self.COLORS['RESET']}"
        
        return message


def setup_logger(log_level=logging.INFO, no_color=False):
    """
    设置日志系统
    
    Args:
        log_level: 日志级别
        no_color: 是否禁用彩色输出
        
    Returns:
        logging.Logger: 日志记录器
    """
    # 创建日志记录器
    logger = logging.getLogger('xss_scanner')
    logger.setLevel(log_level)
    
    # 清除之前的处理器
    for handler in logger.handlers:
        logger.removeHandler(handler)
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # 设置日志格式
    log_format = '[%(asctime)s] [%(levelname)s] %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # 创建格式化器
    formatter = ColoredFormatter(
        fmt=log_format,
        datefmt=date_format,
        use_color=not no_color
    )
    
    # 设置处理器的格式化器
    console_handler.setFormatter(formatter)
    
    # 将处理器添加到记录器
    logger.addHandler(console_handler)
    
    return logger


def setup_file_logger(log_file, log_level=logging.INFO):
    """
    设置文件日志
    
    Args:
        log_file: 日志文件路径
        log_level: 日志级别
        
    Returns:
        logging.Logger: 日志记录器
    """
    # 创建日志记录器
    logger = logging.getLogger('xss_scanner')
    
    # 创建文件处理器
    try:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(log_level)
        
        # 设置日志格式
        log_format = '[%(asctime)s] [%(levelname)s] %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'
        
        # 创建格式化器
        formatter = logging.Formatter(fmt=log_format, datefmt=date_format)
        
        # 设置处理器的格式化器
        file_handler.setFormatter(formatter)
        
        # 将处理器添加到记录器
        logger.addHandler(file_handler)
    except Exception as e:
        logger.error(f"设置文件日志失败: {str(e)}")
    
    return logger 