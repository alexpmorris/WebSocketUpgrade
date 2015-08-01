object Form1: TForm1
  Left = 296
  Top = 204
  Width = 444
  Height = 369
  Caption = 'webSocket Client/Server Demo'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object ClientMemo: TMemo
    Left = 18
    Top = 226
    Width = 380
    Height = 89
    Hint = 'ClientData'
    Lines.Strings = (
      'ClientData')
    ParentShowHint = False
    ReadOnly = True
    ScrollBars = ssBoth
    ShowHint = True
    TabOrder = 0
  end
  object ServerMemo: TMemo
    Left = 17
    Top = 132
    Width = 380
    Height = 89
    Hint = 'ServerData'
    Lines.Strings = (
      'ServerData')
    ParentShowHint = False
    ReadOnly = True
    ScrollBars = ssBoth
    ShowHint = True
    TabOrder = 1
  end
  object ServerListenBtn: TButton
    Left = 320
    Top = 18
    Width = 75
    Height = 25
    Caption = 'LISTEN'
    TabOrder = 2
    OnClick = ServerListenBtnClick
  end
  object ClientConnectBtn: TButton
    Left = 286
    Top = 51
    Width = 110
    Height = 25
    Caption = 'connectRaw'
    TabOrder = 3
    OnClick = ClientConnectBtnClick
  end
  object ServerEdt: TEdit
    Left = 49
    Top = 21
    Width = 121
    Height = 21
    TabOrder = 4
    Text = 'Hello from Server!'
  end
  object ClientEdt: TEdit
    Left = 49
    Top = 52
    Width = 121
    Height = 21
    TabOrder = 5
    Text = 'Hello From Client!'
  end
  object ServerSendBtn: TButton
    Left = 173
    Top = 21
    Width = 49
    Height = 25
    Hint = 'Server: Send Message '
    Caption = 'sSEND'
    ParentShowHint = False
    ShowHint = True
    TabOrder = 6
    OnClick = ServerSendBtnClick
  end
  object ClientSendBtn: TButton
    Left = 173
    Top = 49
    Width = 49
    Height = 25
    Hint = 'Client: Send Message'
    Caption = 'cSEND'
    ParentShowHint = False
    ShowHint = True
    TabOrder = 7
    OnClick = ClientSendBtnClick
  end
  object ClientConnectWSBtn: TButton
    Left = 285
    Top = 83
    Width = 112
    Height = 25
    Caption = 'connectWebSocket'
    TabOrder = 8
    OnClick = ClientConnectWSBtnClick
  end
  object EncryptBtn: TButton
    Left = 50
    Top = 92
    Width = 75
    Height = 25
    Caption = 'CryptDemo'
    TabOrder = 9
    OnClick = EncryptBtnClick
  end
  object ServerSocket: TServerSocket
    Active = False
    Port = 8080
    ServerType = stNonBlocking
    OnClientConnect = ServerSocketClientConnect
    OnClientDisconnect = ServerSocketClientDisconnect
    OnClientRead = ServerSocketClientRead
    OnClientError = ServerSocketClientError
    Left = 13
    Top = 19
  end
  object ClientSocket: TClientSocket
    Active = False
    Address = '127.0.0.1'
    ClientType = ctNonBlocking
    Port = 8080
    OnConnect = ClientSocketConnect
    OnDisconnect = ClientSocketDisconnect
    OnRead = ClientSocketRead
    OnError = ClientSocketError
    Left = 14
    Top = 52
  end
end
