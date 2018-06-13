#ifndef _WEB_SOCKET_DLL_H_
#define _WEB_SOCKET_DLL_H_

#ifdef	COMMANDLIB_EXPORTS
#define	COMMANDLIB_API __declspec(dllexport)
#else
#define COMMANDLIB_API __declspec(dllexport)
#endif

#include "stdafx.h"
#include <string>
#include <sstream>
#include <map>

class CWebSocketHandler{
public:
	COMMANDLIB_API std::string getHandShakeResponse(char* _socketBuffer, WORD _bufferSize);
	COMMANDLIB_API int parserWebSocketFrame(char* _socketBuffer, int _socketBufferSize, char* _outBuffer);
	COMMANDLIB_API int packageWebSocketFrame(char* _inBuffer, int _inBufferSize);
	COMMANDLIB_API int closeConnect(char* _tempBuffer);
private:
	COMMANDLIB_API std::string splitHandShakekey(char* _strBuffer);
	COMMANDLIB_API std::string convertToHandShakeKey(std::string _secWebSocketKey);
};
#endif