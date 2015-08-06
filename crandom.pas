unit crandom;
(*

Random number unit for encryption using multiple sources of randomness from Windows and Intel (if available)

by Alexander Morris, 2015-08-05

Delphi's Random() function isn't enough because every CSPRNG should satisfy the next-bit test.
That is, given the first k bits of a random sequence, there is no polynomial-time algorithm that
can predict the (k+1)th bit with probability of success better than 50%. This is not the case of
Delphi's Random().  CryptGenRandom() and RdRand() are considered to satisfy the CSPRNG test.

CryptGenRandomBytes() function will randomly choose between CryptGenRandom(), RdRand(), and fall
back to Random() as a last resort.

usage:

var buf: array[0..7] of byte;
CryptGenRandomBytes(@buf,8);

References:
http://stackoverflow.com/questions/3946869/how-reliable-is-the-random-function-in-delphi
http://www.merlyn.demon.co.uk/pas-rand.htm#Rand
http://stackoverflow.com/questions/28538370/using-intels-rdrand-opcode-in-delphi-6-7
http://stackoverflow.com/questions/2621897/are-there-any-cryptographically-secure-prng-libraries-for-delphi

*)

interface

uses WinTypes;

//forceMode=-1 (default) to randomly select between Windows and Intel
//forceMode=0 forces CryptGenRandom() if avail, forceMode=1 forces RdRand() if avail, forceMode=2 forces Random()
procedure CryptGenRandomBytes(const pbBuffer: PAnsiChar; const dwLength: DWORD; const forceMode: ShortInt = -1);

implementation

uses Classes;


type fWCCryptAcquireContextA = Function (phProv: Pointer; pszContainer: LPCSTR; pszProvider: LPCSTR; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;
     fWCCryptReleaseContext = Function (hProv: Pointer; dwFlags: DWORD): BOOL; stdcall;
     fWCCryptGenRandom = Function (hProv: ULONG; dwLen: DWORD; pbBuffer: PBYTE): BOOL; stdcall;

var winCryptOk: integer = 0;  //Windows Random function available
    intCryptOk: integer = 0;  //Intel Random RdRand function available
    hProvider: ULONG = 0;  //Windows HCryptProvider Handle
    WinCryptHndl: THandle = 0;
    WCCryptAcquireContextA: fWCCryptAcquireContextA;
    WCCryptReleaseContext: fWCCryptReleaseContext;
    WCCryptGenRandom: fWCCryptGenRandom;


//http://stackoverflow.com/questions/28538370/using-intels-rdrand-opcode-in-delphi-6-7
function TryRdRand(out Value: Cardinal): Boolean;
asm
  db   $0f
  db   $c7
  db   $f1
  jc   @success
  xor  eax,eax
  ret
@success:
  mov  [eax],ecx
  mov  eax,1
end;

procedure InitWinCrypto;
var rnd: cardinal;
begin
  intCryptOk := 1;
  try TryRdRand(rnd); except intCryptOk := -1; end;
  WinCryptHndl := LoadLibrary(PChar('advapi32.dll'));
  if (WinCryptHndl < 32) then begin
    winCryptOk := -1;
    exit;
   end;
  @WCCryptAcquireContextA := GetProcAddress(WinCryptHndl,'CryptAcquireContextA');
  @WCCryptReleaseContext := GetProcAddress(WinCryptHndl,'CryptReleaseContext');
  @WCCryptGenRandom := GetProcAddress(WinCryptHndl,'CryptGenRandom');

  if WCCryptAcquireContextA(@hProvider, Nil, Nil, 1{PROV_RSA_FULL}, $F0000000{CRYPT_VERIFYCONTEXT}) then
    winCryptOk := 1;
end;

//forceMode=-1 (default) to randomly select between Windows and Intel
//forceMode=0 forces Windows CryptGenRandom() if avail
//forceMode=1 forces Intel RdRand() if avail
//forceMode=2 forces Delphi Random()
procedure CryptGenRandomBytes(const pbBuffer: PAnsiChar; const dwLength: DWORD; const forceMode: ShortInt = -1);
var i,mode,byteCount,fails: integer;
    rnd: cardinal;
    rndBufArr: array [0..3] of Byte absolute rnd;
begin
  byteCount := 0;
  if (forceMode >= 0) and (forceMode <= 2) then mode := forceMode else  //force mode of operation
    mode := Random(2);  //randomize entropy source functions
  repeat
    if (mode = 0) and (winCryptOk <> 1) then mode := 1;
    if (mode = 1) and (intCryptOk <> 1) then mode := 2;
    if (mode=2) then begin
      for i := 0 to dwLength-1 do pbBuffer[i] := AnsiChar(random(256));
      exit;
     end else
    if (mode=1) then begin
      try
        repeat
          if TryRdRand(rnd) then begin
            fails := 0;
            for i := 0 to 3 do begin
              if (byteCount < dwLength-1) then begin
                if (rndBufArr[i] <> 0) then begin
                  pbBuffer[byteCount] := AnsiChar(rndBufArr[i]);
                  byteCount := byteCount + 1;
                 end;
               end else exit;
             end;
           end else fails := fails + 1;
          if (fails >= 10) then mode := 2;
        until (byteCount >= dwLength-1) or (mode=2);
      except mode := 2; end;
      if (mode=2) then intCryptOk := -1;
    end else begin
      if WCCryptGenRandom(hProvider, dwLength, @pbBuffer[0]) then exit;
      mode := 1;
      winCryptOk := -1;
     end;
  until false;
end;


initialization
begin
  Randomize;
  InitWinCrypto;
end;

finalization
begin
  if (hProvider > 0) then WCCryptReleaseContext(@hProvider, 0);
end;

end.

