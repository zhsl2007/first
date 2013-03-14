// IEConfig.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <string>
#include <vector>
using namespace std;

#include <shlwapi.h>
#pragma comment (lib, "shlwapi.lib")

#include <conio.h>
#include <ctype.h>

#include "Logger.h"

#define IAM_EVENT_RUNASADMINISTER  L"EventRunAsAdminister"
#ifndef SAFE_DELETE
#define SAFE_DELETE(p)       { if(p) { delete (p);     (p)=NULL; } }

#endif

bool isRunUAC(void)
{
    bool isRunUAC = false; 
    //
    DWORD dwVersion = 0;
    DWORD dwMajorVersion = 0;
    DWORD dwMinorVersion = 0;
    DWORD dwBuild = 0; 
    dwVersion = GetVersion();  
    // Get the Windows version. 
    dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
    dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion))); 
    // Get the build number. 
    if (dwVersion < 0x80000000)
    {
        dwBuild = (DWORD)(HIWORD(dwVersion));
    }
    //
    if(dwMajorVersion > 5)
    {
        LONG    status;
        HKEY    hKEY;
        DWORD   dwEnableLUA = 0;
        DWORD   dwType = REG_DWORD;
        DWORD   dwSize = sizeof( DWORD );
        //
        status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                            TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"),
                            0,
                            KEY_READ,
                            &hKEY ); 
        if(status == ERROR_SUCCESS)
        {
            status = RegQueryValueEx(hKEY,
                                   TEXT("EnableLUA"),
                                   NULL,
                                   &dwType,
                                   (BYTE*)&dwEnableLUA,
                                   &dwSize ); 
            if(status == ERROR_SUCCESS)
            {
                if(0 == dwEnableLUA)
                {
                    isRunUAC = false;
                }
                else
                {
                    isRunUAC = true;
                }
            }
            RegCloseKey( hKEY );
        }
    }
    return isRunUAC;
}


// 管理员权限
BOOL g_isAdmin = FALSE;
HANDLE g_hEventRunAsAdminister = NULL;

HANDLE RunAsAdimin( LPCWSTR lpPath)
{
	wstring strCommand = L"runas";
	wstring strParam = L"";
	wstring strFilePath = lpPath;

	g_isAdmin = TRUE;
	g_hEventRunAsAdminister = ::CreateEvent(NULL, TRUE, FALSE, IAM_EVENT_RUNASADMINISTER);

	SHELLEXECUTEINFO appInfo;
	ZeroMemory(&appInfo, sizeof(appInfo));
	appInfo.cbSize = sizeof(appInfo);
	appInfo.hwnd = NULL;
	appInfo.fMask = SEE_MASK_NOCLOSEPROCESS; 
	appInfo.lpVerb = strCommand.c_str();	
	appInfo.lpParameters = strParam.c_str();
	appInfo.lpFile = strFilePath.c_str(); 	
	appInfo.nShow = SW_SHOWDEFAULT;

	BOOL bResult = ::ShellExecuteEx(&appInfo);
	if ( bResult )
	{
		if ( NULL != appInfo.hProcess )
		{
			return appInfo.hProcess; 
		}
	}

	return NULL;
}
// 是否是管理员进程
BOOL	isAdminProcess(void)
{
	BOOL isAdminProcess = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup; 
    BOOL isCheckOK = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup); 
    if(isCheckOK) 
    {
        isCheckOK = CheckTokenMembership( NULL, AdministratorsGroup, &isAdminProcess);
        isAdminProcess = isCheckOK ? isAdminProcess : FALSE;
        FreeSid(AdministratorsGroup); 
    } 
    return isAdminProcess;
}

vector<wstring>* getIPAdress(const wchar_t * section, const wchar_t* path)
{
	// 获得ini
	int nLocalCount = GetPrivateProfileInt(section, L"count", 0, path);
	vector<wstring>* vctLocal = new vector<wstring>();
	WCHAR wszIP[] = L"IP%d";
	for(int i =0; i < nLocalCount; i++)
	{
		WCHAR wszKeyLocal[10]={0};
		wsprintf(wszKeyLocal, L"IP%d", i+1);
		WCHAR wszValueLocal[MAX_PATH]={0};
		GetPrivateProfileString(section, wszKeyLocal, NULL, wszValueLocal,  MAX_PATH, path);
		wstring wstrValueLocal(wszValueLocal);
		if(wstrValueLocal.length() != 0)
		{
			vctLocal->push_back(wstrValueLocal);
		}
	}
	return vctLocal; 
}

string IAM_W2A(const wchar_t* wch)
{
	int nchLen = wcslen(wch);
	char ch[MAX_PATH]={0};
	::WideCharToMultiByte(CP_ACP, 0, wch, -1, ch, MAX_PATH, NULL, NULL);
	string strRe(ch);
	return strRe;

}


bool IsIP(const char* szIP)
{
	if (strlen(szIP) == 0)
    {
        return FALSE;
    }
    
    int ip_part1 = 0;
    int ip_part2 = 0;
    int ip_part3 = 0;
    int ip_part4 = 0;
    
    if (sscanf(szIP, "%d.%d.%d.%d", &ip_part1, &ip_part2, &ip_part3, &ip_part4) != 4)
    {
        return FALSE;
    }
    
    if (!((ip_part1 >= 0 && ip_part1 <= 255) && (ip_part2 >= 0 && ip_part2 <= 255) && (ip_part3 >= 0 && ip_part3 <= 255) && (ip_part4 >= 0 && ip_part4 <= 255)))
    {
        return FALSE;
    }    

    return TRUE;
}

/************************************************************************/
/* 添加站点                                                             
/* DWORD dwType 2--受信任站点  4--受限制站点                                                                            
/************************************************************************/
bool SetTrustfulUrl(HKEY hKey, char *szUrl, DWORD dwType)
{
    HKEY hkResult;

    int rc = 0;
    char *p = NULL;
    char szProtocol[MAX_PATH] = {0};
    char szData[MAX_PATH] = {0};
    char szTemp[MAX_PATH] = {0};
        
    char szRegPath[MAX_PATH] = {0};

    strcpy(szTemp, szUrl);
    //获取协议
    p = strchr(szTemp, ':');

    if (p != NULL)
    {
        *p = '\0';
        strcpy(szProtocol, szTemp);
        p += 3;
        strcpy(szTemp, p);
    }
    else
    {
        strcpy(szProtocol, "*");
    }

    //去除多余的url
    p = strrchr(szTemp, '/');
    if (p != NULL)
    {
        *p = '\0';
    }
    
    //判断是IP还是域名
    if (IsIP(szTemp))            //IP类站点添加
    {
        DWORD dwKeys = 0;

        sprintf(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges");
        
        rc = RegCreateKeyA(hKey, szRegPath, &hkResult);
        //先获取该key下有多少个项
        rc = RegQueryInfoKey(hkResult, NULL, NULL, NULL, &dwKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        
        RegCloseKey(hkResult);
        hkResult = NULL;

        if (rc != ERROR_SUCCESS)
        {
            return FALSE;
        }
        else
        {            
            sprintf(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges\\Range%d", dwKeys+10);
            
            rc = RegCreateKeyA(hKey, szRegPath, &hkResult);
            //必须要先创建DWORD值，再创建字符串值，否则不能在Internet选项中信任站点列表中显示
            RegSetValueExA(hkResult, szProtocol, NULL, REG_DWORD, (BYTE *)&dwType, sizeof(DWORD));
            RegSetValueExA(hkResult, ":Range", NULL, REG_SZ, (BYTE *)&szTemp, strlen(szTemp));
            
            RegCloseKey(hkResult);
            hkResult = NULL;
        }
    }
    else                //域名类站点添加
    {
        p = strrchr(szTemp, '.');
        
        if (p == NULL)
        {
            sprintf(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s", szTemp);
        } 
        else
        {
            char szTempStr[MAX_PATH] = {0};
            strcpy(szTempStr, p);

            *p = '\0';
            p = strrchr(szTemp, '.');
            if (p == NULL)
            {
                sprintf(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s%s", szTemp, szTempStr);
            }
            else
            {
                *p = '\0';
                p++;
                sprintf(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s%s\\%s", p, szTempStr, szTemp);
            }
        }

        rc = RegCreateKeyA(hKey, szRegPath, &hkResult);
        RegSetValueExA(hkResult, szProtocol, NULL, REG_DWORD, (BYTE*)&dwType, sizeof(DWORD));
        
        RegCloseKey(hkResult);
        hkResult = NULL;
    }

    return TRUE;
}




int _tmain(int argc, _TCHAR* argv[])
{
	INFO_LOGA("config start.");
	// UAC
	BOOL isUAC = isRunUAC();
	BOOL isAdmin = isAdminProcess();
	if(!isAdmin && isUAC)
	{
		INFO_LOGA("is Admin and UAC is opend.");
		if(RunAsAdimin(L"IEConfig.exe"))
		{
			::PostQuitMessage(0);
		}	
	}

	// 提示确定要配置的站点ini
	WCHAR wszPath[MAX_PATH]={0};
	::GetModuleFileName(NULL, wszPath, MAX_PATH);
	wstring wstExePath(wszPath);
	int nLast = wstExePath.find_last_of(L"\\");
	wstring wstrDirectoryExe=wstExePath.substr(0, nLast);
	wstring wstrIniPath = wstrDirectoryExe + L"\\config.ini";

	INFO_LOGW(L"the ini path is %s", wstrIniPath.c_str());
	if(!PathFileExists(wstrIniPath.c_str()))
	{
		printf("请把要配置的config文件放入exe同级目录。\n");
		printf("配置完成后，请按任意键继续。\n");
	}
	else
	{
		printf("确定配置后，请按任意键继续。\n");
	}
	//int i = 0;
	//scanf("%d", &i);
	int ch = _getch();


	// 获得ini
	// 本地intranet
	vector<wstring>* pvctLocal = getIPAdress(L"LocalIntranet", wstrIniPath.c_str());
	// 信任站点
	vector<wstring>* pvctTrust = getIPAdress(L"TrustSite", wstrIniPath.c_str());
	// 受限站点
	vector<wstring>* pvctLimit = getIPAdress(L"LimitSite", wstrIniPath.c_str());

	// 修改注册表
	// 本地intranet
	vector<wstring>::iterator iterLocal = pvctLocal->begin();
	for(; iterLocal != pvctLocal->end(); iterLocal++)
	{

		wstring wstrSite = *iterLocal;
		string strSite =IAM_W2A(wstrSite.c_str());
		INFO_LOGA("the local intranet site is %s", strSite.c_str());
		SetTrustfulUrl(HKEY_CURRENT_USER, const_cast<char*>(strSite.c_str()), 1);
	}
	// 信任站点
	vector<wstring>::iterator iterTrust = pvctTrust->begin();
	for(; iterTrust != pvctTrust->end(); iterTrust++)
	{
		wstring wstrSite = *iterTrust;
		string strSite =IAM_W2A(wstrSite.c_str());
		INFO_LOGA("the trust site is %s", strSite.c_str());
		SetTrustfulUrl(HKEY_CURRENT_USER, const_cast<char*>(strSite.c_str()), 2);
	}
	//  受限站点
	vector<wstring>::iterator iterLimit = pvctLimit->begin();
	for(; iterLimit != pvctLimit->end(); iterLimit++)
	{
		wstring wstrSite = *iterLimit;
		string strSite =IAM_W2A(wstrSite.c_str());
		INFO_LOGA("the limit site is %s", strSite.c_str());
		SetTrustfulUrl(HKEY_CURRENT_USER, const_cast<char*>(strSite.c_str()), 4);
	}

	// 释放内存
	SAFE_DELETE(pvctLocal);
	SAFE_DELETE(pvctTrust);
	SAFE_DELETE(pvctLimit);
	

	// 删除event
	if(g_isAdmin)
	{
		if(NULL != g_hEventRunAsAdminister)
		{
			::SetEvent(g_hEventRunAsAdminister);
		}			
	}


	return 0;
}

