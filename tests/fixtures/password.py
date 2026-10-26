# 测试样例: 明文密码(用于验证 workbuddy 自定义规则 password-plaintext)
password = "Admin@123456"          # 英文赋值形态 → password-plaintext 应检出
数据库密码 = "222222"                # 中文形态(密码 后可无分隔符) → password-plaintext 应检出
# 注意: JSON 形态 "password": "xxx" 不在 workbuddy 规则英文分支的匹配范围
# (password 后紧跟闭合引号), 该形态由默认规则 generic-password 覆盖(需启用该规则):
# config = {"password": "Admin@123456"}
# 以下是应被规则 filter 丢弃的误报样例:
# password is weak                 (纯字母值, 丢弃)
# password: please_change_me       (占位符词表, 丢弃)
