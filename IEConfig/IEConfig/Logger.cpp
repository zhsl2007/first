#include "StdAfx.h"
#include "Logger.h"
#include <shlwapi.h>
#pragma comment (lib, "shlwapi.lib")
#include <shlobj.h>
#pragma comment (lib,"shell32.lib")

#ifndef SAFE_DELETE
#define SAFE_DELETE(p)       { if(p) { delete (p);     (p)=NULL; } }
#endif
#ifndef SAFE_DELETE_ARRAY
#define SAFE_DELETE_ARRAY(p) { if(p) { delete[] (p);   (p)=NULL; } }
#endif

WCHAR m_systime[36];
WCHAR m_filename[MAX_PATH];
HANDLE Logger::hMutex = CreateMutex(NULL, FALSE, L"KeyInfo_logMutex");
BOOL Logger::m_isLogEnable = FALSE;     // the flag to write error log.
int g_logLevel = 0;

#define LOGCONFIGFILENAME L":\\IEConfig.ini"
#define LOGDIRECTORY L"\\IEConfig"

Logger::Logger(void)
{
}

Logger::~Logger(void)
{
}

void Logger::endLog()
{
	if( NULL != hMutex)
	{
		CloseHandle(hMutex);
	}
}

inline void Logger::getSystemTime( IN INT8 type)
{
	ZeroMemory( m_systime, 36 );

	SYSTEMTIME systime;
	GetLocalTime( &systime );

	if ( 0 == type )
	{
		swprintf_s( m_systime, 36, L"%4d-%02d-%02d", systime.wYear, systime.wMonth, systime.wDay );
	}
	else
	{
		swprintf_s( m_systime, 36, L"%02d:%02d:%02d", systime.wHour, systime.wMinute, systime.wSecond );
	}
}

inline int Logger::createLogPathName()
{
	int nRet = 0;
	HKEY hKey = NULL;
	WCHAR szLogPath[MAX_PATH] = {0};
	DWORD dwPathLen=MAX_PATH*sizeof(WCHAR);
	WCHAR szLogLevel[10] = {0};
	DWORD dwLevelLen=10*sizeof(10);
	LONG lRet = 0;

	// ----------------------------------------------
	//lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE, L"SOFTWARE\\IAM\\KeyInfo", 0, KEY_QUERY_VALUE, &hKey );
	////lRet = RegOpenKey( HKEY_LOCAL_MACHINE, L"SOFTWARE\\IAM\\KeyInfo",&hKey );
	//if( lRet != ERROR_SUCCESS )
	//{
	//	return 1;
	//}
	//lRet = RegQueryValueEx( hKey, L"LogPath", NULL, NULL, (LPBYTE) szLogPath, &dwPathLen);
	//if( lRet != ERROR_SUCCESS )
	//{
	//	MessageBox(NULL, L"注册表中值有误，请更正。", L"错误", MB_OK);
	//	return -1;
	//}
	//lRet = RegQueryValueEx( hKey, L"LogLevel", NULL, NULL, (LPBYTE) szLogLevel, &dwLevelLen);
	//if( lRet != ERROR_SUCCESS )
	//{
	//	MessageBox(NULL, L"注册表中值有误，请更正。", L"错误", MB_OK);
	//	return -1;
	//}

	//wcscpy_s(m_filename, dwPathLen, szLogPath);
	//int nLevel = 0;
	//nLevel = _wtoi(szLogLevel);
	//if( 0 != nLevel)
	//{
	//	m_isLogEnable = TRUE;
	//}

	//RegCloseKey( hKey );
	// ----------------------------------------------

	//---------------------------本地文件------------------------------
	//[Log]
	//LogLevel = 0; 
	//
	// level
	int nLevel = 0;
	WCHAR wchPath[MAX_PATH]={0};
	GetSystemDirectory(wchPath, MAX_PATH);
	WCHAR wchLogPath[MAX_PATH] = {0};
	wchLogPath[0]=wchPath[0];
	wcscat(wchLogPath, LOGCONFIGFILENAME);
	nLevel=::GetPrivateProfileInt(L"Log",L"LogLevel", 0, wchLogPath);
	//MessageBox(NULL, wchLogPath, L"wchLogPath", MB_OK);
	char chTxt[10]={0};
	//MessageBoxA(NULL, _itoa(nLevel,chTxt,10), "LogLevel", MB_OK);
	if( 0 != nLevel)
	{
		m_isLogEnable = TRUE;

		SHGetSpecialFolderPath(NULL, szLogPath, CSIDL_APPDATA, 0);
		wcscat(szLogPath, LOGDIRECTORY);
		if(FALSE == ::PathFileExists(szLogPath))
		{
			//MessageBoxA(NULL, _itoa(nLevel,chTxt,10), "CreateDirectory", MB_OK);
			BOOL bCreate = CreateDirectory(szLogPath, NULL);
			if(bCreate)
			{
				MessageBox(NULL, szLogPath, L"szLogPath", MB_OK);
			}
		}
		wcscpy(m_filename,szLogPath);
		//wcscpy_s(m_filename, wcslen(szLogPath), szLogPath);
		
		nRet = 0;
	}
	else
	{
		nRet = 1;
	}
	//MessageBox(NULL, m_filename, L"m_filename", MB_OK);

	return nRet;
	

	//---------------------------------------------------------

	

	return nRet;
}

inline void Logger::createLogFileName()
{
	getSystemTime();
	wcscat_s( m_filename, MAX_PATH, L"\\");
	wcscat_s( m_filename, MAX_PATH, m_systime);
	wcscat_s( m_filename, MAX_PATH, L".log");
}
void Logger::writeLog( IN LOGTYPE logtype, IN wchar_t* fileName, IN INT32 line, IN const WCHAR* pstrMessage )
{
	WaitForSingleObject(hMutex, INFINITE);	// get the mutex

	WCHAR *logtext = new WCHAR[MAX_PATH];
	getSystemTime(1);

	switch(logtype)
	{
	case _ERRORLOG:
		swprintf_s( logtext, MAX_PATH, L"[%s]  [%s]  [%s] %d  \t", L"ERROR", m_systime, PathFindFileName(fileName), line);
		break;
	case _INFOLOG:
		swprintf_s( logtext, MAX_PATH, L"[%s]  [%s]  [%s] %d  \t", L"INFO ", m_systime,  PathFindFileName(fileName), line);
		break;
	case _WARNLOG:
		swprintf_s( logtext, MAX_PATH, L"[%s]  [%s]  [%s] %d  \t", L"WARN ", m_systime, PathFindFileName(fileName), line);
	    break;
	default:
	    break;
	}

	int nResult = createLogPathName();
	if( 0 == nResult )
	{
		createLogFileName();
	}
	else
	{
		SAFE_DELETE_ARRAY(logtext);
		endLog();
		return ;
	}
	
	//if ( FALSE == PathFileExists(m_filename) )
	//{
	//	MessageBox(NULL, L"注册表中值LogPath有误，请更正。", L"错误", MB_OK);
	//	SAFE_DELETE_ARRAY(logtext);
	//	endLog();
	//	return;
	//}

	// Local
	locale &loc=locale::global(locale(locale(),"",LC_CTYPE));

	// the output file stream
	wofstream m_outfile;					
	m_outfile.open(m_filename, ios::app);

	if (m_outfile.is_open())
	{
		// Local
		locale::global(loc);
		m_outfile<<logtext<<pstrMessage<<endl;
		m_outfile.close();
	}
	SAFE_DELETE_ARRAY(logtext);

	// release the mutex
	ReleaseMutex(hMutex);					
}

void Logger::outputPrintA( IN LOGTYPE logtype, IN wchar_t* fileName, IN INT32 line, const char *fmt, ... )
{
	// level
	//int nLevel = 0;
	WCHAR wchPath[MAX_PATH]={0};
	GetSystemDirectory(wchPath, MAX_PATH);
	WCHAR wchLogPath[MAX_PATH] = {0};
	wchLogPath[0]=wchPath[0];
	wcscat(wchLogPath, LOGCONFIGFILENAME);
	g_logLevel=::GetPrivateProfileInt(L"Log",L"LogLevel", 0, wchLogPath);
	if( g_logLevel == 0)
	{
		return;
	}

	// Format string
	char buffer[1024*50] = {0};
	va_list arglist;
	va_start( arglist, fmt );
	vsprintf( buffer, fmt, arglist );
	va_end(arglist);

	wchar_t wbuffer[1024*50] = {0};

	::MultiByteToWideChar(CP_ACP, 0, buffer, -1, wbuffer, 1024*50);

	writeLog( logtype,  fileName, line, wbuffer);

}

void Logger::outputPrintW( IN LOGTYPE logtype, IN wchar_t* fileName, IN INT32 line, const wchar_t *fmt, ... )
{
	// level
	WCHAR wchPath[MAX_PATH]={0};
	GetSystemDirectory(wchPath, MAX_PATH);
	WCHAR wchLogPath[MAX_PATH] = {0};
	wchLogPath[0]=wchPath[0];
	wcscat(wchLogPath, L":\\IEConfig.ini");
	g_logLevel=::GetPrivateProfileInt(L"Log",L"LogLevel", 0, wchLogPath);
	if( g_logLevel == 0)
	{
		return;
	}

	// Format string
	wchar_t wbuffer[1024*50] = {0};
	va_list arglist;
	va_start( arglist, fmt );
	wvsprintf( wbuffer, fmt, arglist );
	va_end(arglist);

	writeLog( logtype,  fileName, line, wbuffer);
}