#include "stdafx.h"
#include "CurlUtility.h"
#include <iostream>
#include <string.h>
#include <vector>
#pragma comment(lib,"libcurl_a.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wldap32.lib")
using namespace std;
size_t writeFunction(void *ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*)ptr, size * nmemb);
    return size * nmemb;
}


string findcsrf(string & responsestr)
{
    auto index = responsestr.find("name=\"_token\"");
    if (index != responsestr.npos)
    {
        string tmp = responsestr.substr(index, 100);
        int index2 = tmp.find("value=");
        if (index2==tmp.npos)
        {
            return "";
        }
        auto tmp1 = tmp.substr(index2);
        index2 = tmp1.find("\"");
        if (index2==tmp1.npos)
        {
            return "";
        }
        tmp1 = tmp1.substr(index2 + 1);
        int index3 = tmp1.find("\"");
        if (index3==tmp1.npos)
        {
            return "";
        }
        tmp1 = tmp1.substr(0, index3);
        return tmp1;
    }
    return "";
}
int curlget(string const& urlget,std::string &header_string,std::string &response_string)
{
    auto curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, urlget.data());
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_USERPWD, "user:pass");
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.42.0");
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookies2.txt");
        if (PathFileExists(L"cookies.txt"))
        {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");
        }
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_perform(curl);
        char* url;
        long response_code;
        double elapsed;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
        curl_easy_cleanup(curl);
        CurlUtility::Get().SaveCookies();
        return response_code;
    }
}



int curlpost(string urlget,string const& postfields, std::string &header_string, std::string &response_string) {

    auto curl = curl_easy_init();
    if (curl) {
        struct curl_slist *chunk = NULL;

        curl_easy_setopt(curl, CURLOPT_URL, urlget.data());
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        //char *output = curl_easy_escape(curl, postfields.c_str(),postfields.length());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields.c_str());
        //curl_easy_setopt(curl, CURLOPT_USERPWD, "user:pass");
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36");
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        headers = curl_slist_append(headers, "Accept-Language: en,en-US;q=0.9,zh-CN;q=0.8,zh;q=0.7,de;q=0.6");
        headers = curl_slist_append(headers, "DNT: 1");

        /* pass our list of custom made headers */
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookies2.txt");
        if (PathFileExists(L"cookies.txt"))
        {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");
        }
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_perform(curl);

        char* url;
        long response_code;
        double elapsed;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
        curl_easy_cleanup(curl);

        CurlUtility::Get().SaveCookies();
        curl = NULL;
        return response_code;
    }
}

bool IsLogin(string &csrf) {

    string header_string;
    string response_string;
    string urlhome = CurlUtility::Get().GetUrl() + "/home";
    int resp_code = curlget(urlhome, header_string, response_string);
    csrf = findcsrf(response_string);
    bool islogin = csrf != "";
    if (!islogin)
    {
        string url = CurlUtility::Get().GetUrl() + "/login";
        int resp_code = curlget(url, header_string, response_string);
        csrf = findcsrf(response_string);
    }
    return islogin;
}
bool AttemptLogin(string _token, string username, string password) {
    string postfields = "_token=" + _token + "&" + "email=" + username + "&"
        + "password=" + password;
    string header_string, response_string;
    string url = CurlUtility::Get().GetUrl()+"/login";
    int respcode = curlpost(url, postfields, header_string, response_string);
    if (respcode==302)
    {
        if (response_string.find(CurlUtility::Get().GetUrl()+"/home")!=response_string.npos)
        {
            return true;
        }
    }
    return false;
}
CurlUtility & CurlUtility::Get()
{
    static CurlUtility s_curlUtil;
    return s_curlUtil;
}


bool CurlUtility::Login(CString userName, CString passWord)
{
    CurrentDirectoryAutoChange dirchange;
    string csrf;
    bool isLogin = IsLogin(csrf);
    USES_CONVERSION;
    string username = W2A(userName.GetBuffer()); //"test@163.com";
    string password = W2A(passWord.GetBuffer()); //"123456";
    if (!isLogin)
    {
        if (!AttemptLogin(csrf, username, password))
        {
            AfxMessageBox(L"用户名或密码错误！");
            return false;
        }
    }
    //string header_string;
    //string response_string;
    //curlget("http://homestead.test/deletefile?id=35",header_string,response_string);
    return true;
}

bool CurlUtility::LoginWithCookie()
{
    CurrentDirectoryAutoChange dirchange;
    string csrf;
    return IsLogin(csrf);
}

CurlUtility::CurlUtility()
{
}


CurlUtility::~CurlUtility()
{
}

std::string CurlUtility::GetUrl()
{
    return "http://111.192.100.98:8090";
}

void CurlUtility::SaveCookies()
{
    if (PathFileExists(L"cookies33.txt"))
    {
        CFile::Remove(L"cookies33.txt");
    }
    if (PathFileExists(L"cookies.txt"))
    {
        CFile::Rename(L"cookies.txt", L"cookies33.txt");
    }
    if (PathFileExists(L"cookies2.txt"))
    {
        CFile::Rename(L"cookies2.txt", L"cookies.txt");
    }
}

void CurlUtility::RemoveCookies()
{
    if (PathFileExists(L"cookies33.txt"))
    {
        CFile::Remove(L"cookies33.txt");
    }
    if (PathFileExists(L"cookies.txt"))
    {
        CFile::Remove(L"cookies.txt");
    }
    if (PathFileExists(L"cookies2.txt"))
    {
        CFile::Remove(L"cookies2.txt");
    }
}

CurrentDirectoryAutoChange::CurrentDirectoryAutoChange()
{
    wchar_t buffer[MAX_PATH];
    wchar_t currentdirectory[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    GetCurrentDirectory(MAX_PATH, currentdirectory);
    CString filepath = buffer;
    int index = filepath.ReverseFind(L'\\');
    filepath = filepath.Left(index);
    m_oldpath = currentdirectory;
    SetCurrentDirectory(filepath);
}

CurrentDirectoryAutoChange::~CurrentDirectoryAutoChange()
{
    SetCurrentDirectory(m_oldpath);
}
