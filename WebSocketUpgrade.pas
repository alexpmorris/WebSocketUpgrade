{

used code from Bauglir Internet Library as framework to easily upgrade any
TCP Socket class to a WebSocket implementation including streaming deflate that can
maintain current zlib context and state

v0.10, 2015-07-31, by Alexander Morris

See interface functions for usage details

Requirements: SynAUtil, SynACode (from Synapse), DelphiZlib

References:
http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17
http://tools.ietf.org/html/rfc6455
http://dev.w3.org/html5/websockets/#refsFILEAPI
https://www.igvita.com/2013/11/27/configuring-and-optimizing-websocket-compression/
http://stackoverflow.com/questions/22169036/websocket-permessage-deflate-in-chrome-with-no-context-takeover

}



{==============================================================================|

| Project : Bauglir Internet Library                                           |
|==============================================================================|
| Content: Generic connection and server                                       |
|==============================================================================|
| Copyright (c)2011-2012, Bronislav Klucka                                     |
| All rights reserved.                                                         |
| Source code is licenced under original 4-clause BSD licence:                 |
| http://licence.bauglir.com/bsd4.php                                          |
|                                                                              |
|                                                                              |
| Project download homepage:                                                   |
|   http://code.google.com/p/bauglir-websocket/                                |
| Project homepage:                                                            |
|   http://www.webnt.eu/index.php                                              |
| WebSocket RFC:                                                               |
|   http://tools.ietf.org/html/rfc6455                                         |
|                                                                              |
|==============================================================================|}


unit WebSocketUpgrade;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$H+}

interface

uses
  Classes, SysUtils, ScktComp, SynAUtil, SynACode, ZLibEx, ZLibExApi;

const
  {:Constants section defining what kind of data are sent from one pont to another}
  {:Continuation frame }
  wsCodeContinuation = $0;
  {:Text frame }
  wsCodeText         = $1;
  {:Binary frame }
  wsCodeBinary       = $2;
  {:Close frame }
  wsCodeClose        = $8;
  {:Ping frame }
  wsCodePing         = $9;
  {:Frame frame }
  wsCodePong         = $A;


 {:Constants section defining close codes}
 {:Normal valid closure, connection purpose was fulfilled}
 wsCloseNormal              = 1000;
 {:Endpoint is going away (like server shutdown) }
 wsCloseShutdown            = 1001;
 {:Protocol error }
 wsCloseErrorProtocol       = 1002;
 {:Unknown frame data type or data type application cannot handle }
 wsCloseErrorData           = 1003;
 {:Reserved }
 wsCloseReserved1           = 1004;
 {:Close received by peer but without any close code. This close code MUST NOT be sent by application. }
 wsCloseNoStatus            = 1005;
 {:Abnotmal connection shutdown close code. This close code MUST NOT be sent by application. }
 wsCloseErrorClose          = 1006;
 {:Received text data are not valid UTF-8. }
 wsCloseErrorUTF8           = 1007;
 {:Endpoint is terminating the connection because it has received a message that violates its policy. Generic error. }
 wsCloseErrorPolicy         = 1008;
 {:Too large message received }
 wsCloseTooLargeMessage     = 1009;
 {:Client is terminating the connection because it has expected the server to negotiate one or more extension, but the server didn't return them in the response message of the WebSocket handshake }
 wsCloseClientExtensionError= 1010;
 {:Server is terminating the connection because it encountered an unexpected condition that prevented it from fulfilling the request }
 wsCloseErrorServerRequest  = 1011;
 {:Connection was closed due to a failure to perform a TLS handshake. This close code MUST NOT be sent by application. }
 wsCloseErrorTLS            = 1015;


type
  TZlibBuffer = class
  published
    constructor Create(bufSize: Cardinal = 16384);
    Destructor Destroy; override;
  public
    bufferSize: Cardinal;
    readBuffer: Array of Byte;
    writeBuffer: Array of Byte;
    procedure SetBufferSize(bufSize: Cardinal);
  end;

  TWebSocketConnection = class
  private

  published
    Constructor Create;
    Destructor Destroy; override;
  public
    isServerConnection: boolean;
    isPerMessageDeflate: boolean;
    fCookie: AnsiString;
    fVersion: integer;
    fProtocol: AnsiString;
    fResourceName: AnsiString;
    fOrigin: AnsiString;
    fExtension: AnsiString;
    fPort: AnsiString;
    fHost: AnsiString;
    fHeaders: AnsiString;
    fWebSocketHeaders: AnsiString;
    fwsKey: AnsiString;
    fHandShake: boolean;
    fMasking: boolean;
    fRequireMasking: boolean;
    inCompWindowBits: integer;
    outCompWindowBits: integer;
    inFZStream: TZStreamRec;
    outFZStream: TZStreamRec;
    FZBuffer: TZlibBuffer;
    inCompNoContext: boolean;
    outCompNoContext: boolean;
  end;


//creates Server TWebSocketConnection object, with socket.send() headers in fWebSocketHeaders
//to upgrade the socket if client sent a WebSocket HTTP header
//tryDeflate = 0 for false, or zlib windowBits for true (ie. default = 15)
function CreateServerWebSocketConnection(str_headers: AnsiString; tryDeflate: byte = 15): TWebSocketConnection;

//creates Client TWebSocketConnection object, with socket.send() headers in fncWebSocketHeaders
function CreateClientWebSocketConnection(wsUri: AnsiString; tryDeflate: boolean): TWebSocketConnection;

//confirms Client TWebSocketConnection handshake with server
//returns true if succesful, or false upon failure (and also frees wsConn)
function ConfirmClientWebSocketConnection(var wsConn: TWebSocketConnection; str_headers: AnsiString): boolean;


//if websocket, send data packets here to be decoded
function WebSocketReadData(var aData: AnsiString; const wsConn: TWebSocketConnection; var aCode: integer): AnsiString;

//if websocket, send text to this method to send encoded packet
//masking should only be used if socket is a ClientSocket and not a ServerSocket
function WebSocketSendData(aData: AnsiString; const wsConn: TWebSocketConnection; aCode: integer = 1{wsCodeText}; tryDeflate: boolean = true): AnsiString;


//streaming zlib inflate/deflate functions

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


implementation


uses Math, Windows;


{$IFDEF Win32} {$O-} {$ENDIF Win32}


function ZCompressCheck(code: Integer): Integer;
begin
  result := code;

  if code < 0 then
  begin
    raise EZCompressionError.Create(code);
  end;
end;

function ZDecompressCheck(code: Integer; raiseBufferError: Boolean = True): Integer;
begin
  Result := code;

  if code < 0 then
  begin
    if (code <> Z_BUF_ERROR) or raiseBufferError then
    begin
      raise EZDecompressionError.Create(code);
    end;
  end;
end;



constructor TWebSocketConnection.Create;
begin
  fCookie := '';
  fVersion := 0;
  fProtocol := '-';
  fResourceName := '';
  fOrigin := '';
  fExtension := '-';
  fPort := '';
  fHost := '';
  fHeaders := '';
  fWebSocketHeaders := '';
  fMasking := false;
  fRequireMasking := false;
  isPerMessageDeflate := false;
  inCompWindowBits := 0;
  outCompWindowBits := 0;
  inCompNoContext := False;
  outCompNoContext := False;
  FillChar(inFZStream,SizeOf(inFZStream),0);
  FillChar(outFZStream,SizeOf(outFZStream),0);
  FZBuffer := nil;
end;


destructor TWebSocketConnection.Destroy;
begin
  if isPerMessageDeflate then begin
    try ZDecompressCheck(ZInflateEnd(inFZStream)); except end;
    try ZCompressCheck(ZDeflateEnd(outFZStream)); except end;
    FZBuffer.Free;
   end;
  inherited Destroy;
end;


function ZlibStreamCompressString(var outFZStream: TZStreamRec; const aText: AnsiString; const zBuf: TZlibBuffer): AnsiString;
var
  zresult: Integer;
  len,i,outLen: integer;
  aTextPos: Cardinal;
begin
  result := '';

  try

    zresult := Z_OK;
    aTextPos := 0;
    while (aTextPos+1 < Length(aText)) do begin
      len := length(aText)-aTextPos;
      if (len > zBuf.bufferSize) then len := zBuf.bufferSize;
      Move(aText[aTextPos+1], zBuf.readBuffer[0], len);
      aTextPos := aTextPos + len;
      outFZStream.next_in := @zBuf.readBuffer[0];
      outFZStream.avail_in := len;
      outFZStream.next_out := @zBuf.writeBuffer[0];
      outFZStream.avail_out := zBuf.bufferSize;
      zresult := ZCompressCheck(ZDeflate(outFZStream, zfNoFlush));
      outLen := zBuf.bufferSize-outFZStream.avail_out;
      if (outLen > 0) then begin
        SetLength(result,length(result)+outLen);
        Move(zBuf.writeBuffer[0], result[length(result)-outLen+1], outLen);
       end;
     end;
    while (zresult = Z_OK) do begin
      outFZStream.next_out := @zBuf.writeBuffer[0];
      outFZStream.avail_out := zBuf.bufferSize;
      try
        zresult := ZCompressCheck(ZDeflate(outFZStream, zfSyncFlush));
        outLen := zBuf.bufferSize-outFZStream.avail_out;
        if (outLen > 0) then begin
          SetLength(result,length(result)+outLen);
          Move(zBuf.writeBuffer[0], result[length(result)-outLen+1], outLen);
         end;
      except zresult := Z_STREAM_END; end;
      if (outFZStream.avail_out > 0) then zresult := Z_STREAM_END;
     end;
    if (Copy(Result,length(Result)-8,9) = #$00#$00#$ff#$ff#$00#$00#$00#$ff#$ff) then Delete(Result,length(Result)-8,9) else  // remove 9 octets from tail, for cases of hitting buffer boundary
      Delete(Result,length(Result)-3,4);  //remove 4 octets from tail

  except
    on E: EZCompressionError do
      result := '[compressionError:'+E.Message+']';
  end;

end;

function ZlibStreamDecompressString(var inFZStream: TZStreamRec; const aText: AnsiString; const zBuf: TZlibBuffer; aTextPos: Cardinal = 0): AnsiString;
var
  zresult: Integer;
  len,i,outLen: integer;
begin
  result := '';

  try

    zresult := Z_OK;
    //aTextPos := 0;  // <-- defined as parameter
    inFZStream.avail_in := 0;
    while (inFZStream.avail_in > 0) or (aTextPos+1 < Length(aText)) do begin
      if (inFZStream.avail_in = 0) then begin
        len := length(aText)-aTextPos;
        if (len > zBuf.bufferSize) then len := zBuf.bufferSize;
        Move(aText[aTextPos+1], zBuf.readBuffer[0], len);
        inFZStream.next_in := @zBuf.readBuffer[0];
        inFZStream.avail_in := len;
       end else len := 0;
      inFZStream.next_out := @zBuf.writeBuffer[0];
      inFZStream.avail_out := zBuf.bufferSize;

      zresult := ZDecompressCheck(ZInflate(inFZStream, zfNoFlush));
      aTextPos := aTextPos + len;
      outLen := zBuf.bufferSize-inFZStream.avail_out;
      if (outLen > 0) then begin
        SetLength(result,length(result)+outLen);
        Move(zBuf.writeBuffer[0], result[length(result)-outLen+1], outLen);
       end;

     end;
    //add 4 octets to tail
    inFZStream.next_in := @zBuf.readBuffer[0];
    inFZStream.avail_in := 4;
    zBuf.readBuffer[0]:=$00; zBuf.readBuffer[1]:=$00; zBuf.readBuffer[2]:=$ff; zBuf.readBuffer[3]:=$ff;
    while (zresult = Z_OK) do begin
      inFZStream.next_out := @zBuf.writeBuffer[0];
      inFZStream.avail_out := zBuf.bufferSize;
      try
        zresult := ZDecompressCheck(ZInflate(inFZStream, zfNoFlush));
        outLen := zBuf.bufferSize-inFZStream.avail_out;
        if (outLen > 0) then begin
          SetLength(result,length(result)+outLen);
          Move(zBuf.writeBuffer[0], result[length(result)-outLen+1], outLen);
         end;
      except
        if (copy(inFZStream.msg,1,7)='invalid') then
          ZDecompressCheck(ZInflateReset(inFZStream));  //try resetting context, if extra BFINAL byte added to stream
        zresult := Z_STREAM_END;
      end;
      if (inFZStream.avail_out > 0) then zresult := Z_STREAM_END;
     end;

  except
    on E: EZDecompressionError do
      result := '[DecompressionError:'+E.Message+']';
  end;

end;


function ZlibCompressString(const aText: AnsiString; const aCompressionLevel: TZCompressionLevel; const windowBits: integer; const memLevel: integer; const strategy: TZStrategy): AnsiString;
var
  strInput,
  strOutput: TStringStream;
  Zipper: TZCompressionStream;
begin
  Result := '';
  strInput := TStringStream.Create(aText);
  strOutput := TStringStream.Create('');
  try
    Zipper := TZCompressionStream.Create(strOutput, aCompressionLevel, windowBits, memLevel, strategy);
    try
      Zipper.CopyFrom(strInput, strInput.Size);
    finally
      Zipper.Free;
    end;
    Result := strOutput.DataString;
  finally
    strInput.Free;
    strOutput.Free;
  end;
end;

function ZlibDecompressString(const aText: AnsiString; const windowBits: integer): AnsiString;
var
  strInput,
  strOutput: TStringStream;
  Unzipper: TZDecompressionStream;
begin
  Result := '';
  strInput := TStringStream.Create(aText);
  strOutput := TStringStream.Create('');
  try
    Unzipper := TZDecompressionStream.Create(strInput, windowBits);
    try        
      strOutput.CopyFrom(Unzipper, Unzipper.Size);
    finally
      Unzipper.Free;
    end;
    Result := strOutput.DataString;
  finally
    strInput.Free;
    strOutput.Free;
  end;
end;


function httpCode(code: integer): AnsiString;
begin
  case (code) of
     100: result := 'Continue';
     101: result := 'Switching Protocols';
     200: result := 'OK';
     201: result := 'Created';
     202: result := 'Accepted';
     203: result := 'Non-Authoritative Information';
     204: result := 'No Content';
     205: result := 'Reset Content';
     206: result := 'Partial Content';
     300: result := 'Multiple Choices';
     301: result := 'Moved Permanently'; 
     302: result := 'Found';
     303: result := 'See Other';
     304: result := 'Not Modified';
     305: result := 'Use Proxy';
     307: result := 'Temporary Redirect'; 
     400: result := 'Bad Request';
     401: result := 'Unauthorized';
     402: result := 'Payment Required';
     403: result := 'Forbidden';
     404: result := 'Not Found'; 
     405: result := 'Method Not Allowed'; 
     406: result := 'Not Acceptable';
     407: result := 'Proxy Authentication Required'; 
     408: result := 'Request Time-out';
     409: result := 'Conflict';
     410: result := 'Gone';
     411: result := 'Length Required';
     412: result := 'Precondition Failed'; 
     413: result := 'Request Entity Too Large';
     414: result := 'Request-URI Too Large'; 
     415: result := 'Unsupported Media Type';
     416: result := 'Requested range not satisfiable';
     417: result := 'Expectation Failed'; 
     500: result := 'Internal Server Error'; 
     501: result := 'Not Implemented';
     502: result := 'Bad Gateway'; 
     503: result := 'Service Unavailable';
     504: result := 'Gateway Time-out';
     else result := 'unknown code: $code';
  end;
end;


procedure SplitExtension(var extString,key,value: AnsiString);
var i: integer;
    tmps: AnsiString;
begin
  i := Pos('; ',extString);
  if (i <> 0) then begin
    tmps := trim(lowercase(copy(extString,1,i-1)));
    delete(extString,1,i);
   end else begin
     tmps := trim(lowercase(extString));
     extString := '';
    end;
  i := Pos('=',tmps);
  if (i <> 0) then begin
    key := trim(copy(tmps,1,i-1));
    value := trim(copy(tmps,i+1,length(tmps)));
   end else begin
     key := trim(tmps);
     value := '';
    end;
end;

//tryDeflate = 0 for false, or zlib windowBits for true (ie. 15)
function CreateServerWebSocketConnection(str_headers: AnsiString; tryDeflate: Byte = 15): TWebSocketConnection;
var headers, hrs: TStringList;
    get,extKey,extVal: AnsiString;
    s, key, version: AnsiString;
    iversion, vv: integer;
    res: boolean;
    r : TWebSocketConnection;
    fncResourceName: AnsiString;
    fncHost: AnsiString;
    fncPort: AnsiString;
    fncOrigin: AnsiString;
    fncProtocol: AnsiString;
    fncExtensions: AnsiString;
    fncCookie: AnsiString;
    fncHeaders: AnsiString;
    fncWebSocketHeaders: AnsiString;
    fncResultHttp: integer;
    fncInCompWindowBits: byte;
    fncOutCompWindowBits: byte;
    fncinCompNoContext: boolean;
    fncoutCompNoContext: boolean;
    fncPerMessageDeflate: boolean;
begin
  result := nil;
  headers := TStringList.Create;
  try
    for vv:=length(str_headers)-1 downto 1 do begin
      if (copy(str_headers,vv,2)=': ') then begin
        str_headers[vv]:='='; delete(str_headers,vv+1,1);
       end;
     end;
    headers.Text := str_headers;
    get := '';
    if (headers.count<>0) then begin
      get := headers[0];  res := True;
     end;
    if (res) then
    begin
      res := false;
      try
        //CHECK HTTP GET
        if ((Pos('GET ', Uppercase(get)) <> 0) and (Pos(' HTTP/1.1', Uppercase(get)) <> 0)) then
        begin
          fncResourceName := SeparateRight(get, ' ');
          fncResourceName := SeparateLeft(fncResourceName, ' ');
        end
        else exit;
        fncResourceName := trim(fncResourceName);

        //CHECK HOST AND PORT
        s := headers.Values['host'];
        if (s <> '') then
        begin
          fncHost := trim(s);
          fncPort := SeparateRight(fncHost, ':');
          fncHost := SeparateLeft(fncHost, ':');
        end;
        fncHost := trim(fncHost);
        fncPort := trim(fncPort);

        if (fncHost = '') then exit;

        //WEBSOCKET KEY
        s := headers.Values['sec-websocket-key'];
        if (s <> '') then
        begin
          if (Length(DecodeBase64(s)) = 16) then
          begin
            key := s;
          end;

        end;
        if (key = '') then exit;
        key := trim(key);

        //WEBSOCKET VERSION
        s := headers.Values['sec-websocket-version'];
        if (s <> '') then
        begin
          vv := StrToIntDef(s, -1);

          if ((vv >= 7) and (vv <= 13)) then
          begin
            version := s;
          end;
        end;
        if (version = '') then exit;
        version := trim(version);
        iversion := StrToIntDef(version, 13);

        if (LowerCase(headers.Values['upgrade']) <> LowerCase('websocket')) or (pos('upgrade', LowerCase(headers.Values['connection'])) = 0) then
          exit;

        //COOKIES

        fncProtocol := '-';
        fncExtensions := '-';
        fncCookie := '-';
        fncOrigin := '-';
        fncPerMessageDeflate := false;

        if (iversion < 13) then
        begin
          if (headers.IndexOfName('sec-websocket-origin') > -1) then
            fncOrigin := trim(headers.Values['sec-websocket-origin']);
        end
        else begin
          if (headers.IndexOfName('origin') > -1) then
            fncOrigin := trim(headers.Values['origin']);
        end;

        if (headers.IndexOfName('sec-websocket-protocol') > -1) then
          fncProtocol := trim(headers.Values['sec-websocket-protocol']);
        if (headers.IndexOfName('sec-websocket-extensions') > -1) then begin
          fncExtensions := trim(headers.Values['sec-websocket-extensions']);
          if (Pos('permessage-deflate',fncExtensions) <> 0) then begin
            try
            if (tryDeflate>0) then begin
              //fncExtensions := 'permessage-deflate; client_max_window_bits=12; server_max_window_bits=12';//; client_no_context_takeover';
              fncInCompWindowBits := tryDeflate;
              fncOutCompWindowBits := tryDeflate;
              while (fncExtensions <> '') do begin
                SplitExtension(fncExtensions,extKey,extVal);
                if (extKey = 'client_max_window_bits') then begin
                  if (extVal <> '') and (extVal <> '0') then fncInCompWindowBits := StrToInt(extVal);
                  if (fncInCompWindowBits < 8) or (fncInCompWindowBits > tryDeflate) then fncInCompWindowBits := tryDeflate;
                 end;
                if (extKey = 'client_no_context_takeover') then fncinCompNoContext := true;
               end;
              fncExtensions := 'permessage-deflate; client_max_window_bits';
              if (fncInCompWindowBits > 0) then fncExtensions := fncExtensions+'='+IntToStr(fncInCompWindowBits);
              fncExtensions := fncExtensions + '; server_max_window_bits';
              if (fncOutCompWindowBits > 0) then fncExtensions := fncExtensions+'='+IntToStr(fncOutCompWindowBits);
              fncExtensions := fncExtensions + '; ';
              if fncinCompNoContext then fncExtensions := fncExtensions + 'client_no_context_takeover; ';
              if fncoutCompNoContext then fncExtensions := fncExtensions + 'server_no_context_takeover; ';
              delete(fncExtensions,length(fncExtensions)-1,2);  //delete extra '; '
              fncPerMessageDeflate := true;
             end else fncExtensions := '-';
            except
              fncExtensions := '-';
            end;
           end;
         end;
        if (headers.IndexOfName('cookie') > -1) then
          fncCookie := trim(headers.Values['cookie']);

        fncHeaders := trim(headers.text);

        res := true;
      finally
        if (res) then
        begin
          fncResultHttp := 101;
          hrs := TStringList.Create;
          hrs.Assign(headers);
          if (1=1) then
          begin
            if (fncResultHttp <> 101) then //HTTP ERROR FALLBACK
            begin
              fncWebSocketHeaders := fncWebSocketHeaders + Format('HTTP/1.1 %d %s'+#13#10, [fncResultHttp, httpCode(fncResultHttp)]);
              fncWebSocketHeaders := fncWebSocketHeaders + Format('%d %s'+#13#10#13#10, [fncResultHttp, httpCode(fncResultHttp)]);
            end
            else
            begin

              key := EncodeBase64(SHA1(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'));

              s :=        'HTTP/1.1 101 Switching Protocols' + #13#10;
              s := s +    'Upgrade: websocket' + #13#10;
              s := s +    'Connection: Upgrade' + #13#10;
              s := s +    'Sec-WebSocket-Accept: ' + key + #13#10;
              if (fncProtocol <> '-') then
              begin
                s := s +  'Sec-WebSocket-Protocol: ' + fncProtocol + #13#10;
              end;
              if (fncExtensions <> '-') then
              begin
                s := s +  'Sec-WebSocket-Extensions: ' + fncExtensions + #13#10;
              end;
              s := s + #13#10;

              fncWebSocketHeaders := fncWebSocketHeaders + s;

              result := TWebSocketConnection.Create;
              TWebSocketConnection(result).isServerConnection := true;
              TWebSocketConnection(result).fCookie := fncCookie;
              TWebSocketConnection(result).fVersion := StrToInt(version);
              TWebSocketConnection(result).fProtocol := fncProtocol;
              TWebSocketConnection(result).fResourceName := fncResourceName;
              TWebSocketConnection(result).fOrigin := fncOrigin;
              TWebSocketConnection(result).fExtension := fncExtensions;
              TWebSocketConnection(result).fPort := fncPort;
              TWebSocketConnection(result).fHost := fncHost;
              TWebSocketConnection(result).fHeaders := fncHeaders;
              TWebSocketConnection(result).fWebSocketHeaders := fncWebSocketHeaders;
              TWebSocketConnection(result).fHandshake := true;
              TWebSocketConnection(result).fMasking := false;  //server must not mask frames sent to client
              TWebSocketConnection(result).isPerMessageDeflate := fncPerMessageDeflate;
              TWebSocketConnection(result).InCompWindowBits := fncInCompWindowBits;
              TWebSocketConnection(result).OutCompWindowBits := fncOutCompWindowBits;
              TWebSocketConnection(result).inCompNoContext := fncinCompNoContext;
              TWebSocketConnection(result).outCompNoContext := fncoutCompNoContext;
              if fncPerMessageDeflate then begin
                TWebSocketConnection(result).FZBuffer := TZlibBuffer.Create;
                ZCompressCheck(ZDeflateInit2(TWebSocketConnection(result).outFZStream, zcLevel8, -1*fncOutCompWindowBits, 9, zsDefault));
                ZDecompressCheck(ZInflateInit2(TWebSocketConnection(result).inFZStream, -1*fncInCompWindowBits));
               end;
               
            end;
          end;
          hrs.Free;
        end;
      end;
    end;
  finally
    headers.Free;
  end;
end;


function CreateClientWebSocketConnection(wsUri: AnsiString; tryDeflate: boolean): TWebSocketConnection;
var key, s, get: AnsiString;
    i: integer;
    fncOrigin: AnsiString;
    fncHost: AnsiString;
    fncPort: AnsiString;
    fncResourceName: AnsiString;
    fncProtocol: AnsiString;
    fncExtension: AnsiString;
    fncCookie: AnsiString;
    fncHeaders: AnsiString;
    fncWebSocketHeaders: AnsiString;
    fncResultHttp: integer;
    fncVersion: integer;
    wsProt,wsUser,wsPass,wsPara: AnsiString;
begin
                                                         
    ParseURL(wsUri,wsProt,wsUser,wsPass,fncHost,fncPort,fncResourceName,wsPara);
    fncOrigin := wsProt+'://'+fncHost;
    if (fncPort<>'80') then fncOrigin := fncOrigin + ':'+fncPort;

    fncVersion := 13;
    if tryDeflate then fncExtension := 'permessage-deflate; client_max_window_bits';

    s := Format('GET %s HTTP/1.1' + #13#10, [fncResourceName]);
    s := s + Format('Upgrade: websocket' + #13#10, []);
    s := s + Format('Connection: Upgrade' + #13#10, []);
    s := s + Format('Host: %s:%s' + #13#10, [fncHost, fncPort]);

    for I := 1 to 16 do key := key + ansichar(Random(85) + 32);
    key := EncodeBase64(key);
    s := s + Format('Sec-WebSocket-Key: %s' + #13#10, [(key)]);
    s := s + Format('Sec-WebSocket-Version: %d' + #13#10, [fncVersion]);

    //TODO extensions
    if (fncProtocol <> '-') then
      s := s + Format('Sec-WebSocket-Protocol: %s' + #13#10, [fncProtocol]);
    if (fncOrigin <> '-') then
    begin
      if (fncVersion < 13) then
        s := s + Format('Sec-WebSocket-Origin: %s' + #13#10, [fncOrigin])
      else
        s := s + Format('Origin: %s' + #13#10, [fncOrigin]);
    end;
    if (fncCookie <> '-') then
      s := s + Format('Cookie: %s' + #13#10, [(fncCookie)]);
    if (fncExtension <> '-') then
      s := s + Format('Sec-WebSocket-Extensions: %s' + #13#10, [fncExtension]);
    s := s + #13#10;

    fncWebSocketHeaders := s;

    result := TWebSocketConnection.Create;
    TWebSocketConnection(result).isServerConnection := false;
    TWebSocketConnection(result).fCookie := fncCookie;
    TWebSocketConnection(result).fVersion := fncVersion;
    TWebSocketConnection(result).fProtocol := fncProtocol;
    TWebSocketConnection(result).fResourceName := fncResourceName;
    TWebSocketConnection(result).fOrigin := fncOrigin;
    TWebSocketConnection(result).fExtension := '-';  //assigned upon response from server
    TWebSocketConnection(result).fPort := fncPort;
    TWebSocketConnection(result).fHost := fncHost;
    TWebSocketConnection(result).fHeaders := fncHeaders;
    TWebSocketConnection(result).fWebSocketHeaders := fncWebSocketHeaders;
    TWebSocketConnection(result).fwsKey := key;
    TWebSocketConnection(result).fHandshake := false;
    TWebSocketConnection(result).fMasking := true;  //client must mask frames sent to server

end;

function ConfirmClientWebSocketConnection(var wsConn: TWebSocketConnection; str_headers: string): boolean;
var headers: TStringList;
    vv: integer;
    get,fncExtensions,extKey,extVal: AnsiString;
begin
  result := false;
  if (wsConn = nil) then exit;

  result := true;
  headers := TStringList.Create;
  try
    for vv:=length(str_headers)-1 downto 1 do begin
      if (copy(str_headers,vv,2)=': ') then begin
        str_headers[vv]:='='; delete(str_headers,vv+1,1);
       end;
     end;
    headers.Text := str_headers;
    get := '';
    if (headers.count<>0) then begin
      get := headers[0];
     end else result := false;

    if (result) then result := pos(LowerCase('HTTP/1.1 101'), LowerCase(get)) = 1;
    if (result) then result := (LowerCase(headers.Values['upgrade']) = LowerCase('websocket')) and (LowerCase(headers.Values['connection']) = 'upgrade');
    if (result) then begin
      if (headers.IndexOfName('sec-websocket-protocol') > -1) then
        wsConn.fProtocol := trim(headers.Values['sec-websocket-protocol']);
      if (headers.IndexOfName('sec-websocket-extensions') > -1) then
        wsConn.fExtension := trim(headers.Values['sec-websocket-extensions']);
     end;
    if (result) then result := (headers.Values['sec-websocket-accept'] = EncodeBase64(SHA1(wsConn.fwsKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));

  except
    headers.Free;
  end;

  if (result) then begin
    wsConn.fHandshake := true;
    wsConn.fHeaders := str_headers;

    fncExtensions := wsConn.fExtension;
    if (Pos('permessage-deflate',fncExtensions) <> 0) then begin
      try
         //fncExtensions := 'permessage-deflate; client_max_window_bits=12; server_max_window_bits=12';//; client_no_context_takeover';
         wsConn.inCompWindowBits := 15;
         wsConn.outCompWindowBits := 15;
         while (fncExtensions <> '') do begin
           SplitExtension(fncExtensions,extKey,extVal);
           if (extKey = 'client_max_window_bits') then begin
             if (extVal <> '') and (extVal <> '0') then wsConn.outCompWindowBits := StrToInt(extVal);
             if (wsConn.outCompWindowBits < 8) or (wsConn.outCompWindowBits > 15) then wsConn.outCompWindowBits := 15;
            end;
           if (extKey = 'server_max_window_bits') then begin
             if (extVal <> '') and (extVal <> '0') then wsConn.inCompWindowBits := StrToInt(extVal);
             if (wsConn.inCompWindowBits < 8) or (wsConn.inCompWindowBits > 15) then wsConn.inCompWindowBits := 15;
            end;
           if (extKey = 'server_no_context_takeover') then wsConn.inCompNoContext := true;
          end;
         wsConn.isPerMessageDeflate := true;
         wsConn.FZBuffer := TZlibBuffer.Create;
         ZCompressCheck(ZDeflateInit2(wsConn.outFZStream, zcLevel8, -1*wsConn.outCompWindowBits, 9, zsDefault));
         ZDecompressCheck(ZInflateInit2(wsConn.inFZStream, -1*wsConn.inCompWindowBits));
       except

       end;
     end;

   end else begin
    wsConn.Free;
    wsConn := nil;
   end;

end;


function hexToStr(aDec: integer; aLength: integer): AnsiString;
var tmp: AnsiString;
    i: integer;
begin
  tmp := IntToHex(aDec, aLength);
  result := '';
  for i := 1 to (Length(tmp)+1) div 2 do
  begin
    result := result + ansichar(StrToInt('$'+Copy(tmp, i * 2 - 1, 2)));
  end;
end;

function StrToHexstr2(str: string): AnsiString;
var i: integer;
begin
  result := '';
  for i := 1 to Length(str) do result := result + IntToHex(ord(str[i]), 2) + ' ';
end;


function WebSocketReadData(var aData: AnsiString; const wsConn: TWebSocketConnection; var aCode: integer): AnsiString;
var timeout, i, j: integer;
    b: byte;
    mask: boolean;
    len, iPos: int64;
    mBytes: array[0..3] of byte;
    aFinal, aRes1, aRes2, aRes3: boolean;
begin
  result := '';
  aCode := -1;
  if (aData = '') then exit;
  len := 0;  iPos := 1;

  b := ord(aData[iPos]);  iPos:=iPos+1;

  try
    try
      // BASIC INFORMATIONS
      aFinal := (b and $80) = $80;
      aRes1 := (b and $40) = $40;
      aRes2 := (b and $20) = $20;
      aRes3 := (b and $10) = $10;
      aCode := b and $F;


      // MASK AND LENGTH
      mask := false;
      if (iPos <= length(aData)) then
      begin
        b := ord(aData[iPos]);  iPos:=iPos+1;
        mask := (b and $80) = $80;
        len := (b and $7F);
        if (len = 126) then
        begin
          if (iPos <= length(aData)) then
          begin
            b := ord(aData[iPos]);  iPos:=iPos+1;
            len := b * $100; // 00 00
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b;
            end;
          end;
        end
        else if (len = 127) then    //00 00 00 00 00 00 00 00
        begin

          //TODO nesting og get byte should be different
          if (iPos <= length(aData)) then
          begin
            b := ord(aData[iPos]);  iPos:=iPos+1;
            len := b * $100000000000000;
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b * $1000000000000;
            end;
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b * $10000000000;
            end;
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b * $100000000;
            end;
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b * $1000000;
            end;
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b * $10000;
            end;
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b * $100;
            end;
            if (iPos <= length(aData)) then
            begin
              b := ord(aData[iPos]);  iPos:=iPos+1;
              len := len + b;
            end;
          end;
        end;
      end;

      if (iPos <= length(aData)) and (wsConn.fRequireMasking) and (not mask) then
      begin
        // TODO some protocol error
        raise Exception.Create('mask');
      end;

      // MASKING KEY
      if (mask) and (iPos <= length(aData)) then
      begin
        if (iPos <= length(aData)) then begin
          mBytes[0] := ord(aData[iPos]);  iPos:=iPos+1;
         end;
        if (iPos <= length(aData)) then begin
          mBytes[1] := ord(aData[iPos]);  iPos:=iPos+1;
         end;
        if (iPos <= length(aData)) then begin
          mBytes[2] := ord(aData[iPos]);  iPos:=iPos+1;
         end;
        if (iPos <= length(aData)) then begin
          mBytes[3] := ord(aData[iPos]);  iPos:=iPos+1;
         end;
      end;
      // READ DATA
      if (iPos+len-1 <= length(aData)) then
      begin
        //process complete packet and remove from incoming stream
        for i := 0 to len-1 do begin
          if mask then begin
            result := result + chr(Ord(aData[iPos+i]) xor mBytes[i mod 4]);
          end else result := result + aData[iPos+i];
         end;
        delete(aData,1,iPos+len-1);

        if aRes1 and wsConn.isPerMessageDeflate then begin {deflate}
          //result := ZlibDecompressString(result,-1*wsConn.InCompWindowBits);
          result := ZlibStreamDecompressString(wsConn.inFZStream,result,wsConn.FZBuffer);
          if wsConn.inCompNoContext then ZDecompressCheck(ZInflateReset(wsConn.inFZStream));
         end;

      end;
    except
      result := '';
    end;
  finally
  end;

end;


function WebSocketSendData(aData: AnsiString; const wsConn: TWebSocketConnection; aCode: integer = 1{wsCodeText}; tryDeflate: boolean = true): AnsiString;
var b: byte;
    s: AnsiString;
    mBytes: array[0..3] of byte;
    len: int64;
    aFinal, aRes1, aRes2, aRes3: boolean;
    i,j: integer;
begin
  result := '';
    try

      s := '';

      aFinal := true;  aRes1 := false;  aRes2 := false;  aRes3 := false;

      if tryDeflate and wsConn.isPerMessageDeflate then begin
        //http://stackoverflow.com/questions/22169036/websocket-permessage-deflate-in-chrome-with-no-context-takeover
        aRes1 := true;
        //aData := ZlibCompressString(aData,zcLevel8,-1*wsConn.CompWindowBits,9{memLevel},zsDefault) + #0 {#0=BFINAL, forces no-context};
        aData := ZlibStreamCompressString(wsConn.outFZStream,aData,wsConn.FZBuffer);
        if wsConn.outCompNoContext then ZCompressCheck(ZDeflateReset(wsConn.outFZStream));
       end;

      b := 0;
      // BASIC INFORMATION
      b := IfThen(aFinal, 1, 0) * $80;
      b := b + IfThen(aRes1, 1, 0) * $40;
      b := b + IfThen(aRes2, 1, 0) * $20;
      b := b + IfThen(aRes3, 1, 0) * $10;
      b := b + aCode;
      s := s + ansichar(b);

      b := 0;
      // MASK AND LENGTH
      b := IfThen(wsConn.fMasking, 1, 0) * $80;
      if (length(aData) < 126) then
        b := b + length(aData)
      else if (length(aData) < 65536) then
        b := b + 126
      else
        b := b + 127;
      s := s + ansichar(b);
      if (length(aData) >= 126) then
      begin
        if (length(aData) < 65536) then
        begin
          s := s + hexToStr(length(aData), 4);
        end
        else
        begin
          s := s + hexToStr(length(aData), 16);
        end;
      end;

      // MASKING KEY
      if (wsConn.fMasking) then
      begin
        mBytes[0] := Random(256);
        mBytes[1] := Random(256);
        mBytes[2] := Random(256);
        mBytes[3] := Random(256);


        s := s + ansichar(mBytes[0]);
        s := s + ansichar(mBytes[1]);
        s := s + ansichar(mBytes[2]);
        s := s + ansichar(mBytes[3]);

        for i := 1 to length(aData) do begin
          s := s + chr(Ord(aData[i]) xor mBytes[(i-1) mod 4]);
         end;
        result := s;

      end else result := s+aData;

   except result := ''; end;
end;


//TZlibBuffer class primitives

constructor TZlibBuffer.Create(bufSize: Cardinal = 16384);
begin
  SetBufferSize(bufSize);
end;

destructor TZlibBuffer.Destroy;
begin
  SetBufferSize(0);
  inherited Destroy;
end;

procedure TZlibBuffer.SetBufferSize(bufSize: Cardinal);
begin
  bufferSize := bufSize;
  SetLength(readBuffer,bufferSize);
  SetLength(writeBuffer,bufferSize);
end;

initialization
  Randomize;


end.

