//demo for WebSocketUpgrade and WebSocketCrypt
//
//  v0.10, 2015-07-31, by Alexander Morris
//
//  to test from Chrome Browser on same machine, visit https://www.websocket.org/echo.html and
//  set Location field to ws://127.0.0.1:8080 then hit "Connect"
//

unit wsDemo1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, Sockets, ScktComp, WinSock,
  WebSocketUpgrade, WebSocketCrypt;

type
  TForm1 = class(TForm)
    ClientMemo: TMemo;
    ServerMemo: TMemo;
    ServerListenBtn: TButton;
    ClientConnectBtn: TButton;
    ServerSocket: TServerSocket;
    ClientSocket: TClientSocket;
    ServerEdt: TEdit;
    ClientEdt: TEdit;
    ServerSendBtn: TButton;
    ClientSendBtn: TButton;
    ClientConnectWSBtn: TButton;
    EncryptBtn: TButton;
    procedure ClientConnectBtnClick(Sender: TObject);
    procedure ServerListenBtnClick(Sender: TObject);
    procedure ServerSocketClientConnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ServerSocketClientRead(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ServerSendBtnClick(Sender: TObject);
    procedure ClientConnectWSBtnClick(Sender: TObject);
    procedure ClientSocketConnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ClientSocketRead(Sender: TObject; Socket: TCustomWinSocket);
    procedure ClientSendBtnClick(Sender: TObject);
    procedure EncryptBtnClick(Sender: TObject);
    procedure ServerSocketClientDisconnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ServerSocketClientError(Sender: TObject;
      Socket: TCustomWinSocket; ErrorEvent: TErrorEvent;
      var ErrorCode: Integer);
    procedure ClientSocketDisconnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ClientSocketError(Sender: TObject; Socket: TCustomWinSocket;
      ErrorEvent: TErrorEvent; var ErrorCode: Integer);
  private
    { Private declarations }
  public
    { Public declarations }
   end;

  APISktDataType = record
                     firstPacket: boolean;
                     DataSktStr,webSktStr: string;
                     webSocket: TWebSocketConnection;
                     hbTime: DWORD;
                   end;
  APISktDataTypePtr = ^APISktDataType;


var
  Form1: TForm1;
  useWebSocket: boolean = False;


implementation

{$R *.dfm}


procedure TForm1.ClientConnectBtnClick(Sender: TObject);
begin
  if ClientSocket.Active then begin
    ClientSocket.Active := false;
    exit;
   end;
  useWebSocket := false;
  ClientSocket.Active := true;
  ClientMemo.Lines.Insert(0,'Connecting to '+ClientSocket.Address+':'+IntToStr(ClientSocket.Port));
end;

procedure TForm1.ServerListenBtnClick(Sender: TObject);
begin
  if ServerSocket.Active then exit;
  ServerSocket.Active := true;
  ServerMemo.Lines.Insert(0,'Listening on Port '+IntToStr(ServerSocket.Port));
end;

Function GotTextPos(const Strg: String; Var Size,StrPos: Integer; Var DataS: String): Boolean;
var DumS: String;
    i,j,tmpLen: Integer;
Begin
  result := False;
  try
    DataS := '';
    Size := 0;
    If (Strg = '') Then Exit;

    DumS := '';  j := 0;
    for i := StrPos+1 to Length(Strg) do Begin
      DumS := DumS + Strg[i];  inc(j);
      If (DumS[j] = #10) or (DumS[j] = #13) Then Begin DumS[j] := #13; Break; End;
     End;
    If (DumS <> '') and (DumS[Length(DumS)] = #13) Then Begin
      Size := Length(DumS);  DataS := Copy(DumS,1,Length(DumS)-1);  StrPos := StrPos + Size;  result := True;
      while (StrPos+1 < Length(Strg)) and ((Strg[StrPos+1] = #10) or (Strg[StrPos+1] = #13)) do inc(StrPos);
     End;
  except end;
End;

procedure TForm1.ServerSocketClientConnect(Sender: TObject;
  Socket: TCustomWinSocket);
var i: integer;
    apiSktData: APISktDataTypePtr;
begin
  i:=1; setsockopt(Socket.Handle,IPPROTO_TCP,TCP_NODELAY,PChar(@i),sizeof(i));
  ServerMemo.Lines.Insert(0,'connected from '+Socket.RemoteAddress+':'+IntToStr(Socket.LocalPort));
  new(apiSktData);
  FillChar(apiSktData^,sizeof(apiSktData^),0);
  Socket.Data := apiSktData;
  apiSktData.firstPacket := true;
end;

procedure TForm1.ServerSocketClientRead(Sender: TObject;
  Socket: TCustomWinSocket);
var apiSktData: APISktDataTypePtr;
    Buf: Array [1..8192] of Char;
    TmpS,BufS,EventStr: string;
    i,BufLen,dPos,Size: integer;
begin
  If (Socket = Nil) or (Socket.Data = Nil) Then Exit;
  apiSktData := Socket.Data;

  While (Socket.ReceiveLength > 0) Do Begin
    BufLen := Socket.ReceiveBuf(Buf,8192);
    BufS := Buf;  SetLength(BufS,BufLen);

    if apiSktData.firstPacket then begin
      apiSktData.firstPacket := false;
      if (Pos(': websocket',BufS) <> 0) then begin
        apiSktData.webSocket := CreateServerWebSocketConnection(BufS,15{deflateMaxWindowBits});
        if (apiSktData.webSocket <> nil) and (apiSktData.webSocket.fWebSocketHeaders <> '') then begin
          try Socket.SendText(apiSktData.webSocket.fWebSocketHeaders); except end;
          ServerMemo.Lines.Insert(0,'ws_upgrade '+Socket.RemoteAddress+':'+IntToStr(Socket.LocalPort)+' '+apiSktData.webSocket.fExtension);
         end;
        i := Pos(#13#10#13#10,BufS);
        if (i<>0) then Delete(BufS,1,i+3) else BufS := '';
       end;
     end;

    if (apiSktData.webSocket = nil) then apiSktData.DataSktStr := apiSktData.DataSktStr + BufS else
      apiSktData.webSktStr := apiSktData.webSktStr + BufS;

   End;

  if (apiSktData.webSocket <> nil) then begin
    if (apiSktData.webSktStr <> '') then begin
      repeat
        TmpS := WebSocketReadData(apiSktData.webSktStr,apiSktData.webSocket,i);
        if (TmpS <> '') then begin
          if (TmpS[length(TmpS)] <> #13) and (TmpS[length(TmpS)] <> #10) then TmpS := TmpS + #13;
          apiSktData.DataSktStr := apiSktData.DataSktStr + TmpS;
         end;
        if (i = wsCodePing) then begin
          apiSktData.hbTime := GetTickCount;
          TmpS := WebSocketSendData('',apiSktData.webSocket,wsCodePong);
          try Socket.SendText(TmpS); except end;
         end;
        if (i = wsCodeClose) then begin
          try Socket.Close; except end;
          Exit;
         end;
      until (TmpS = '');
     end;
   end;

  dPos := 0;
  While GotTextPos(apiSktData.DataSktStr,Size,dPos,EventStr) do begin
    ServerMemo.Lines.Insert(0,TimeToStr(now)+': '+EventStr);
   end;
  Delete(apiSktData.DataSktStr,1,dPos);

end;

procedure TForm1.ServerSendBtnClick(Sender: TObject);
var ac: integer;
    apiSktData: APISktDataTypePtr;
    wsPacket,msgText: string;
    Socket: TCustomWinSocket;
begin
  msgText := ServerEdt.Text;
  for ac := 0 to ServerSocket.Socket.ActiveConnections-1 do begin
    Socket := ServerSocket.Socket.Connections[ac];
    apiSktData := Socket.Data;
    if (apiSktData <> nil) and (apiSktData.webSocket <> nil) then
      wsPacket := WebSocketSendData(msgText,apiSktData.webSocket,1) else
        wsPacket := msgText + #13;
    try socket.SendText(wsPacket); except end;
  end;
end;

procedure TForm1.ClientSendBtnClick(Sender: TObject);
var apiSktData: APISktDataTypePtr;
    wsPacket,msgText: string;
    Socket: TCustomWinSocket;
begin
  Socket := ClientSocket.Socket;
  if (Socket = nil) or (not Socket.Connected) then exit;

  msgText := ClientEdt.Text;
  apiSktData := Socket.Data;
  if (apiSktData <> nil) and (apiSktData.webSocket <> nil) then
    wsPacket := WebSocketSendData(msgText,apiSktData.webSocket,1) else
      wsPacket := msgText + #13;
  try socket.SendText(wsPacket); except end;
end;

procedure TForm1.ClientConnectWSBtnClick(Sender: TObject);
begin
  if ClientSocket.Active then begin
    ClientSocket.Active := false;
    exit;
   end;
  useWebSocket := true;
  ClientSocket.Active := true;
  ClientMemo.Lines.Insert(0,'WebSocket: Connecting to '+ClientSocket.Address+':'+IntToStr(ClientSocket.Port));
end;

procedure TForm1.ClientSocketConnect(Sender: TObject;
  Socket: TCustomWinSocket);
var i: integer;
    apiSktData: APISktDataTypePtr;
begin
  i:=1; setsockopt(Socket.Handle,IPPROTO_TCP,TCP_NODELAY,PChar(@i),sizeof(i));
  ClientMemo.Lines.Insert(0,'connected to '+Socket.RemoteAddress+':'+IntToStr(Socket.RemotePort));
  new(apiSktData);
  FillChar(apiSktData^,sizeof(apiSktData^),0);
  Socket.Data := apiSktData;
  apiSktData.firstPacket := true;
  if useWebSocket then begin
    apiSktData.webSocket := CreateClientWebSocketConnection('ws://127.0.0.1:8080',true);
    try Socket.SendText(apiSktData.webSocket.fWebSocketHeaders); except end;
   end;
end;

procedure TForm1.ClientSocketRead(Sender: TObject;
  Socket: TCustomWinSocket);
var apiSktData: APISktDataTypePtr;
    Buf: Array [1..8192] of Char;
    TmpS,BufS,EventStr: string;
    i,BufLen,dPos,Size: integer;
begin
  If (Socket = Nil) or (Socket.Data = Nil) Then Exit;
  apiSktData := Socket.Data;

  While (Socket.ReceiveLength > 0) Do Begin
    BufLen := Socket.ReceiveBuf(Buf,8192);
    BufS := Buf;  SetLength(BufS,BufLen);

    if apiSktData.firstPacket then begin
      apiSktData.firstPacket := false;
      if (Pos(': websocket',BufS) <> 0) then begin
        ConfirmClientWebSocketConnection(apiSktData.webSocket,BufS);
        if (apiSktData.webSocket <> nil) and (apiSktData.webSocket.fWebSocketHeaders <> '') then begin
          ClientMemo.Lines.Insert(0,'ws_upgrade '+Socket.RemoteAddress+':'+IntToStr(Socket.LocalPort)+' '+apiSktData.webSocket.fExtension);
         end;
        i := Pos(#13#10#13#10,BufS);
        if (i<>0) then Delete(BufS,1,i+3) else BufS := '';
       end;
     end;

    if (apiSktData.webSocket = nil) then apiSktData.DataSktStr := apiSktData.DataSktStr + BufS else
      apiSktData.webSktStr := apiSktData.webSktStr + BufS;

   End;

  if (apiSktData.webSocket <> nil) then begin
    if (apiSktData.webSktStr <> '') then begin
      repeat
        TmpS := WebSocketReadData(apiSktData.webSktStr,apiSktData.webSocket,i);
        if (TmpS <> '') then begin
          if (TmpS[length(TmpS)] <> #13) and (TmpS[length(TmpS)] <> #10) then TmpS := TmpS + #13;
          apiSktData.DataSktStr := apiSktData.DataSktStr + TmpS;
         end;
        if (i = wsCodePing) then begin
          apiSktData.hbTime := GetTickCount;
          TmpS := WebSocketSendData('',apiSktData.webSocket,wsCodePong);
          try Socket.SendText(TmpS); except end;
         end;
        if (i = wsCodeClose) then begin
          try Socket.Close; except end;
          Exit;
         end;
      until (TmpS = '');
     end;
   end;

  dPos := 0;
  While GotTextPos(apiSktData.DataSktStr,Size,dPos,EventStr) do begin
    ClientMemo.Lines.Insert(0,TimeToStr(now)+': '+EventStr);
   end;
  Delete(apiSktData.DataSktStr,1,dPos);

end;

procedure TForm1.EncryptBtnClick(Sender: TObject);
var mySalt,myKeyHash,testStr,outputS,HmacAuth,CheckHmacAuth: string;
begin
  mySalt := CreateSalt(10);
  myKeyHash := GetSha256KeyHash('mySecretKey',mySalt,100);
  testStr :='encrypt me!';
  outputS := 'OpenSSL-compatible AES256-CBC Demo with 100-iteration Sha256 KeyHash and HMAC Authentication'#13#10#13#10+
             'mySalt = '+mySalt+#13#10+'myKeyHash = '+myKeyHash+#13#10+'testStr = "'+testStr+'"'#13#10#13#10;
  EncryptOpenSSLAES256CBC(myKeyHash,testStr);  // testStr is now encrypted
  HmacAuth := GetHmacSha256Auth(myKeyHash,testStr);
  testStr := testStr + HmacAuth;
  outputS := outputS + 'Encrypted Text + HMAC = "' + testStr + '"'#13#10#13#10;

  hmacAuth := Copy(testStr,Length(testStr)-63,64);
  delete(testStr,Length(testStr)-63,64);
  CheckHmacAuth := GetHmacSha256Auth(myKeyHash,testStr);

  if (HmacAuth = CheckHmacAuth) then begin
    DecryptOpenSSLAES256CBC(myKeyHash,testStr);  // testStr should again equal 'encrypt me!'
    outputS := outputS + 'Decrypted Text = "' + testStr + '"'#13#10#13#10;
   end else begin
     outputS := outputS + 'Decrypted Text = HMAC auth FAILED!  [signed:'+HmacAuth+' expected:'+CheckHmacAuth+']'#13#10#13#10;
    end;

  EncryptOpenSSLAES256CBC(myKeyHash,testStr);  // testStr is now encrypted
  HmacAuth := GetHmacSha256Auth(myKeyHash,testStr);
  testStr := testStr + HmacAuth;

  testStr[random(length(testStr))] := 'a';
  outputS := outputS + 'Manipulated Encrypted Text + HMAC = "' + testStr + '"'#13#10#13#10;

  hmacAuth := Copy(testStr,Length(testStr)-63,64);
  delete(testStr,Length(testStr)-63,64);
  CheckHmacAuth := GetHmacSha256Auth(myKeyHash,testStr);

  if (HmacAuth = CheckHmacAuth) then begin
    DecryptOpenSSLAES256CBC(myKeyHash,testStr);  // testStr should again equal 'encrypt me!'
    outputS := outputS + 'Decrypted Text = "' + testStr + '"'#13#10#13#10;
   end else begin
     outputS := outputS + 'Decrypted Text = HMAC auth FAILED!  [signed:'+HmacAuth+' expected:'+CheckHmacAuth+']'#13#10#13#10;
    end;


  ShowMessage(outputS);
end;


procedure TForm1.ServerSocketClientDisconnect(Sender: TObject;
  Socket: TCustomWinSocket);
var apiSktData: APISktDataTypePtr;
begin
  apiSktData := Socket.Data;
  if (apiSktData <> nil) then begin
    if (apiSktData.webSocket <> nil) then apiSktData.webSocket.Free;
    Dispose(apiSktData);
    Socket.Data := nil;
   end;
end;

procedure TForm1.ServerSocketClientError(Sender: TObject;
  Socket: TCustomWinSocket; ErrorEvent: TErrorEvent;
  var ErrorCode: Integer);
var apiSktData: APISktDataTypePtr;
begin
  apiSktData := Socket.Data;
  if (apiSktData <> nil) then begin
    if (apiSktData.webSocket <> nil) then apiSktData.webSocket.Free;
    Dispose(apiSktData);
    Socket.Data := nil;
   end;
  ErrorCode := 0;
  try Socket.Close; except end;
end;

procedure TForm1.ClientSocketDisconnect(Sender: TObject;
  Socket: TCustomWinSocket);
var apiSktData: APISktDataTypePtr;
begin
  apiSktData := Socket.Data;
  if (apiSktData <> nil) then begin
    if (apiSktData.webSocket <> nil) then apiSktData.webSocket.Free;
    Dispose(apiSktData);
    Socket.Data := nil;
   end;
end;

procedure TForm1.ClientSocketError(Sender: TObject;
  Socket: TCustomWinSocket; ErrorEvent: TErrorEvent;
  var ErrorCode: Integer);
var apiSktData: APISktDataTypePtr;
begin
  apiSktData := Socket.Data;
  if (apiSktData <> nil) then begin
    if (apiSktData.webSocket <> nil) then apiSktData.webSocket.Free;
    Dispose(apiSktData);
    Socket.Data := nil;
   end;
  ErrorCode := 0;
  try Socket.Close; except end;
end;


initialization
  Randomize;


end.
