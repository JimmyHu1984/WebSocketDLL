#include "stdafx.h"
#include "WebSocketDLL.h"
#include "Encoder\base64.h"
#include "Encoder\sha1.h"

#define HAND_SHAKE_KEY	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define BUFFER_SIZE 2048

#define MASK_OFFSET_FIN				0x01
#define MASK_OFFSET_RSV_1			0x02
#define MASK_OFFSET_RSV_2			0x04
#define MASK_OFFSET_RSV_3			0x08
#define MASK_OFFSET_OP_CODE			0x0F
#define MASK_OFFSET_MASK_FLAG		0x80
#define MASK_OFFSET_PAYLOAD_LENTH	0x7F

std::string CWebSocketHandler::getHandShakeResponse(char* _socketBuffer, WORD _bufferSize){
	if (_socketBuffer == NULL || _bufferSize == 0){
		return "";  
	}
	char convertBuffer[BUFFER_SIZE];
	memcpy(convertBuffer, _socketBuffer, _bufferSize);
	convertBuffer[_bufferSize] = '\0';
	std::string clientKey = splitHandShakekey(convertBuffer);
	if(clientKey.size() == 0){
		return "";
	}
	return convertToHandShakeKey(clientKey);
}

std::string CWebSocketHandler::splitHandShakekey(char* _strBuffer){
	std::istringstream strStream(_strBuffer);
	std::string strRequest;
	std::getline(strStream, strRequest);  

	std::map<std::string, std::string> m_mapReqField;
	std::string strHead;  
    std::string::size_type sEnd;  
    while (std::getline(strStream, strHead) && strHead != "\r"){  
		if (strHead[strHead.size() - 1] != '\r'){
			continue;  
		}else{ 
			strHead.erase(strHead.end() - 1); 
		}
        sEnd = strHead.find(": ", 0);  
        if (sEnd != std::string::npos){  
            std::string key = strHead.substr(0, sEnd);  
            std::string val = strHead.substr(sEnd + 2);  
            m_mapReqField[key] = val;  
        }  
    }  
	if (m_mapReqField.size() == std::string::npos){
		return "";  
	}
    std::string tmpKey = m_mapReqField["Sec-WebSocket-Key"];  
	if (tmpKey.empty()){
		return "";  
	}
	return tmpKey;
}


std::string CWebSocketHandler::convertToHandShakeKey(std::string _secWebSocketKey){
	_secWebSocketKey.append(HAND_SHAKE_KEY);

	SHA1 sha;
    unsigned int iDigSet[5];  
    sha.Reset();  
    sha << _secWebSocketKey.c_str();  
    sha.Result(iDigSet);  
  
    for (int i = 0; i < 5; i++){
		iDigSet[i] = htonl(iDigSet[i]);
	}
    std::string tmpStr = base64_encode(reinterpret_cast<const unsigned char*>(iDigSet), 20);   
    std::stringstream ssReponse;  
    ssReponse << "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " << tmpStr << "\r\nUpgrade: websocket\r\n\r\n"; 

    return ssReponse.str();
}


int CWebSocketHandler::parserWebSocketFrame(char* _socketBuffer, int _socketBufferSize, char* _outBuffer){

	int FIN = _socketBuffer[0] & MASK_OFFSET_FIN;
	int RSV_1 = _socketBuffer[0] & MASK_OFFSET_RSV_1;
	int RSV_2 = _socketBuffer[0] & MASK_OFFSET_RSV_2;
	int RSV_3 = _socketBuffer[0] & MASK_OFFSET_RSV_3;
	int opCode = _socketBuffer[0] & MASK_OFFSET_OP_CODE;
	BOOL maskFlag = (_socketBuffer[1] & MASK_OFFSET_MASK_FLAG) >> 7;
	INT64 payloadLenth = _socketBuffer[1] & MASK_OFFSET_PAYLOAD_LENTH;
	int maskArrayStartByte = 2;
	int playLoadStartByte = 6;
	
	if(payloadLenth == 126){
		payloadLenth =((unsigned char)_socketBuffer[2] <<8 | (unsigned char)_socketBuffer[3]);
		maskArrayStartByte = maskArrayStartByte + 2;
		playLoadStartByte  = playLoadStartByte + 2;
	}else if(payloadLenth >= 127){
		for(int i=0; i<8; ++i ){
			payloadLenth = (unsigned char)_socketBuffer[i] << (56 - 8*i);
		}

		maskArrayStartByte = maskArrayStartByte + 8;
		playLoadStartByte  = playLoadStartByte + 8;
	}
	BYTE maskArray[4];
	char *payloadData = &_socketBuffer[playLoadStartByte];
	std::string out;
	if(maskFlag == TRUE){
		for(int i=0; i < 4; ++i){
			maskArray[i] = _socketBuffer[maskArrayStartByte+i];
		}
		for(int i=0; i < payloadLenth; ++i){
			payloadData[i] = payloadData[i] ^ maskArray[i % 4];
		}
	}
	memcpy(_outBuffer, payloadData, (size_t)payloadLenth);
	return (int)payloadLenth;
}

int CWebSocketHandler::packageWebSocketFrame(char* _inBuffer, int _inBufferSize){
	
	char tempFrame[BUFFER_SIZE] = {};


	if(_inBufferSize+8 > 65535){
		//more than 65535 bytes
		return 0;
	}
	int FIN = 1;
	int opCode = 1;

	BOOL maskFlag = 0;
	tempFrame[0] = (char) 0x81;

	int frameOffset ;
	if(_inBufferSize < 126){
		tempFrame[1] = (maskFlag<<7 | (unsigned char)_inBufferSize);
		memcpy(&tempFrame[2], _inBuffer, _inBufferSize);
		frameOffset = 2;
	}else{
		tempFrame[1] = (maskFlag << 7 | 126) ;
		tempFrame[2] = ((unsigned char)(_inBufferSize >> 8) & 0xFF);
		tempFrame[3] = ((unsigned char)_inBufferSize & 0xFF);
		memcpy(&tempFrame[4], _inBuffer, _inBufferSize);
		frameOffset = 4;
	}

	memcpy(_inBuffer, tempFrame, _inBufferSize + frameOffset);
	

	return _inBufferSize + frameOffset;
}

int CWebSocketHandler::closeConnect(char* _tempBuffer){
	_tempBuffer[0] = (char) 0x88;
	_tempBuffer[1] = (char) 0x00;
	return 2; 
}