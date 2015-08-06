# WebSocketUpgrade
Easily upgrade any TCP Socket class to a WebSocket implementation including streaming deflate

I assembled these classes because I could not find a simple and free websocket implementation, including streaming deflate, that could be overloaded onto any standard Delphi/FreePascal socket class.  I also included an AES256-based openssl-compatible encryption package (or, more technically, AES-256-CBC + HMAC-SHA-256).  If you require a more comprehensive encryption, hashing, and authentication library, I recommend you check out my [libsodium delphi wrapper](https://github.com/alexpmorris/libsodium-delphi).

This approach makes WebSockets seem much less daunting to manage and implement.  As you can tell from the code, a WebSocket is a relatively simple protocol layer over a standard TCP socket connection.  It can also easily be abstracted away from any underlying socket class.  If not currently available, it should also be a straight-forward process to port similar functionality to other languages.

Usage should be straight-forward, and includes a demo.

Requirements: DelphiZlib, DCPCrypt2, plus a few Synapse dependencies (all included).

This package builds on the work of the Bauglir Internet Library Websocket, which hasn't been updated since 2012: https://code.google.com/p/bauglir-websocket/

**WebSocketUpgrade.pas Functions**

```pascal
//creates Server TWebSocketConnection object, with socket.send() headers in fWebSocketHeaders
//to upgrade the socket if client sent a WebSocket HTTP header
//tryDeflate = 0 for false, or zlib windowBits for true (ie. default = 15)
function CreateServerWebSocketConnection(str_headers: AnsiString; tryDeflate: byte = 15): TWebSocketConnection;

//creates Client TWebSocketConnection object, with socket.send() headers in fncWebSocketHeaders
function CreateClientWebSocketConnection(wsUri: AnsiString; tryDeflate: boolean): TWebSocketConnection;

//confirms Client TWebSocketConnection handshake with server
//returns true if succesful, or false upon failure (and also frees wsConn)
function ConfirmClientWebSocketConnection(var wsConn: TWebSocketConnection; str_headers: string): boolean;

//if websocket, send data packets here to be decoded
function WebSocketReadData(var aData: AnsiString; const wsConn: TWebSocketConnection; var aCode: integer): AnsiString;

//if websocket, send text to this method to send encoded packet
//masking should only be used if socket is a ClientSocket and not a ServerSocket
function WebSocketSendData(aData: AnsiString; const wsConn: TWebSocketConnection; aCode: integer = 1{wsCodeText}; tryDeflate: boolean = true): AnsiString;
```

**Streaming zlib inflate/deflate functions**

```pascal
//uses ZLibEx, ZLibExApi - windowBits = -1..-15 for raw deflate, or 31 for gzip
//create a buffer from stream (same can be used for compress and decompress): FZBuffer := TZlibBuffer.Create;
//create Compress Stream:  ZCompressCheck(ZDeflateInit2(outFZStream, zcLevel8, -15, 9, zsDefault));
//compress: compText = ZlibStreamCompressString(outFZStream,messageText,FZBuffer);
//free Compress Stream and Buffer:  try ZCompressCheck(ZDeflateEnd(outFZStream)); except end;  FZBuffer.Free;
//reset Compress Stream:  ZCompressCheck(ZDeflateReset(outFZStream));
function ZlibStreamCompressString(var outFZStream: TZStreamRec; const aText: AnsiString; const zBuf: TZlibBuffer): AnsiString;

//uses ZLibEx, ZLibExApi - windowBits = -1..-15 for raw deflate, or 31 for gzip
//create a buffer from stream (same can be used for compress and decompress): FZBuffer := TZlibBuffer.Create;
//create Decompress Stream:  ZDecompressCheck(ZInflateInit2(inFZStream, -15));
//decompress: decompText = ZlibStreamDecompressString(inFZStream,compressedText,FZBuffer);
//free Decompress Stream and Buffer:  try ZDecompressCheck(ZInflateEnd(inFZStream)); except end;  FZBuffer.Free;
//reset Decompress Stream:  ZDecompressCheck(ZInflateReset(inFZStream));
function ZlibStreamDecompressString(var inFZStream: TZStreamRec; const aText: AnsiString; const zBuf: TZlibBuffer; aTextPos: Cardinal = 0): AnsiString;

//zlib single-use (no context) inflate/deflate functions
function ZlibCompressString(const aText: AnsiString; const aCompressionLevel: TZCompressionLevel; const windowBits: integer; const memLevel: integer; const strategy: TZStrategy): AnsiString;
function ZlibDecompressString(const aText: AnsiString; const windowBits: integer): AnsiString;

//zlib helper functions exported
function ZCompressCheck(code: Integer): Integer;
function ZDecompressCheck(code: Integer; raiseBufferError: Boolean = True): Integer;
```

**WebSocketCrypt.pas Functions (AES-256-CBC + HMAC-SHA-256)**

*See WebSocketCrypt.pas for additional notes on how to pass messages back and forth to a browser in javascript*

```pascal
//256-bit openssl-compatible AES format text-based packet encryption/decryption functions
//  testStr :='encrypt me!';
//  EncryptOpenSSLAES256CBC('mySecretKey',testStr);  // testStr is now encrypted
//  DecryptOpenSSLAES256CBC('mySecretKey',testStr);  // testStr should again equal 'encrypt me!'
//
//  messages can be easily encrypted/decrypted from javascript using crypto-js
procedure EncryptOpenSSLAES256CBC(const hashS: AnsiString; var msgS: AnsiString);
procedure DecryptOpenSSLAES256CBC(const hashS: AnsiString; var msgS: AnsiString);

//get len bytes worth of salt
function CreateSalt(const len: integer): AnsiString;

//create an SHA256 hash of mySecretKey using mySalt with iter iterations
function GetSha256KeyHash(const mySecretKey,mySalt: AnsiString; const iter: integer): AnsiString;

//create a 256-bit PBKDF2 hash of mySecretKey using mySalt with iter iterations
//shaMode=1 to use Sha1 for compatibility with CryptoJS.PBKDF2()
//shaMode=2 to uses Sha256 as hash function
function GetPBKDF2KeyHash(const mySecretKey,mySalt: AnsiString; const iter: integer; const shaMode: Byte): AnsiString;

//create an HMAC + SHA256 message authentication using mySecretKey
function GetHmacSha256Auth(const mySecretKey,myMessage: AnsiString): AnsiString;

//constant time string comparision in delphi to prevent timing attacks, based on XORing
function time_strcmp(const str1, str2: AnsiString): boolean;
```
