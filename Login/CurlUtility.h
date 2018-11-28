#pragma once
#include "curl/curl.h"
#include "curl/easy.h"
#include <string>
struct CurrentDirectoryAutoChange
{
    CString m_oldpath;
    CurrentDirectoryAutoChange();
    ~CurrentDirectoryAutoChange();
};

class CurlUtility
{
public:
    static CurlUtility& Get();
    bool Login(CString userName,CString passWord);
    bool LoginWithCookie();
    CurlUtility();
    ~CurlUtility();
    std::string GetUrl();
    void SaveCookies();
    void RemoveCookies();
};

