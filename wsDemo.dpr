program wsDemo;
//{$apptype console}

uses
  Forms,
  wsDemo1 in 'wsDemo1.pas' {Form1},
  WebSocketCrypt in 'WebSocketCrypt.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
