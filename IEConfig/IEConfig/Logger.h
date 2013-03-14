#ifdef __cplusplus
#ifndef LOGGER__H
#define LOGGER__H

#include <fstream>
#include <string>
#include <time.h> 
#include <windows.h>
#include <direct.h>

using namespace std;

//#define OUTPUT_LOGA( strMessage )     Log::outputLogA( __FILEW__, __LINE__, strMessage )
//#define OUTPUT_LOGW( strMessage )    Log::outputLogW( __FILEW__, __LINE__, strMessage )

#define INFO_LOGA( strMessage, ...)    Logger::outputPrintA( _INFOLOG, __FILEW__, __LINE__, strMessage, __VA_ARGS__)
#define INFO_LOGW( strMessage, ...)    Logger::outputPrintW(_INFOLOG, __FILEW__, __LINE__, strMessage, __VA_ARGS__)
#define ERROR_LOGA( strMessage, ...)    Logger::outputPrintA(_ERRORLOG, __FILEW__, __LINE__, strMessage, __VA_ARGS__ )
#define ERROR_LOGW( strMessage,...)    Logger::outputPrintW(_ERRORLOG, __FILEW__, __LINE__, strMessage, __VA_ARGS__)

#define ENDLOG()                   Logger::endLog()

enum LOGTYPE
{
	_INFOLOG,
	_ERRORLOG,
	_WARNLOG,
};

class Logger
{
public:
	Logger(void);
	~Logger(void);

	static void endLog();
	//static void outputLogA( IN wchar_t* fileName, IN INT32 line, IN const string& strMassage );
	//static void outputLogW( IN wchar_t* fileName, IN INT32 line, IN const wstring& strMassage );
	static void outputPrintA( IN LOGTYPE logtype, IN wchar_t* fileName, IN INT32 line,  const char *fmt, ... );
	static void outputPrintW( IN LOGTYPE logtype, IN wchar_t* fileName, IN INT32 line,  const wchar_t *fmt, ... );

	static void writeLog( IN LOGTYPE logtype, IN wchar_t* fileName, IN INT32 line, IN const WCHAR* pstrMassage );

	inline static void getSystemTime( IN INT8 type = 0 );

	inline static void createLogFileName( void );

	inline static int createLogPathName( void );

private:
	static HANDLE hMutex;            
	static BOOL m_isLogEnable;     // the flag to write error log.
};

#endif
#endif
