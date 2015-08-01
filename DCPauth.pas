//  DCPCrypt2 module implements:
//    HMAC (Hash-based message authentication code)
//    PBKDF1/PBKDF2 (Password-Based Key Derivation Function)
//
//
//  adapted from code found at http://keit.co/p/dcpcrypt-hmac-rfc2104/

uses dcpcrypt2, Math;
 
function RPad(x: AnsiString; c: Char; s: Integer): AnsiString;
var
  i: Integer;
begin
  Result := x;
  if Length(x) < s then
    for i := 1 to s-Length(x) do
      Result := Result + c;
end;
 
function XorBlock(s, x: AnsiString): AnsiString;  {$ifdef Version2005Plus} inline; {$endif}
var
  i: Integer;
begin
  SetLength(Result, Length(s));
  for i := 1 to Length(s) do
    Result[i] := Char(Byte(s[i]) xor Byte(x[i]));
end;
 
function CalcDigest(text: AnsiString; dig: TDCP_hashclass): AnsiString;
var
  x: TDCP_hash;
begin
  x := dig.Create(nil);
  try
    x.Init;
    x.UpdateStr(text);
    SetLength(Result, x.GetHashSize div 8);
    x.Final(Result[1]);
  finally
    x.Free;
  end;
end;
 
function CalcHMAC(message, key: AnsiString; hash: TDCP_hashclass): AnsiString;
const
  blocksize = 64;
begin
  // Definition RFC 2104
  if Length(key) > blocksize then
    key := CalcDigest(key, hash);
  key := RPad(key, #0, blocksize);
 
  Result := CalcDigest(XorBlock(key, RPad('', #$36, blocksize)) + message, hash);
  Result := CalcDigest(XorBlock(key, RPad('', #$5c, blocksize)) + result, hash);
end;
 
function PBKDF1(pass, salt: AnsiString; count: Integer; hash: TDCP_hashclass): AnsiString;
var
  i: Integer;
begin
  Result := pass+salt;
  for i := 0 to count-1 do
    Result := CalcDigest(Result, hash);
end;

function PBKDF2(pass, salt: AnsiString; count, kLen: Integer; hash: TDCP_hashclass): AnsiString;
 
  function IntX(i: Integer): AnsiString; {$ifdef Version2005Plus} inline; {$endif}
  begin
    Result := Char(i shr 24) + Char(i shr 16) + Char(i shr 8) + Char(i);
  end;
 
var
  D, I, J: Integer;
  T, F, U: AnsiString;
begin
  T := '';
  D := Ceil(kLen / (hash.GetHashSize div 8));
  for i := 1 to D do
  begin
    F := CalcHMAC(salt + IntX(i), pass, hash);
    U := F;
    for j := 2 to count do
    begin
      U := CalcHMAC(U, pass, hash);
      F := XorBlock(F, U);
    end;
    T := T + F;
  end;
  Result := Copy(T, 1, kLen);
end;

