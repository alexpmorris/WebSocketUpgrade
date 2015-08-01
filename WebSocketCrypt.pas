(*

OpenSSL-compatible encrypt/decrypt routines can be used to protect non-TLS (wss://) websocket
connections using a shared secret key in a text-friendly manner.

v0.10, 2015-07-31, by Alexander Morris

Requirements: DCPCrypt2

References:
http://deusty.blogspot.com/2009/04/decrypting-openssl-aes-files-in-c.html
http://stackoverflow.com/questions/8313992/dcpcrypt-delphi-not-properly-encoding-rijndael
http://stackoverflow.com/questions/8806481/how-can-i-decrypt-something-with-pycrypto-that-was-encrypted-using-openssl
http://security.stackexchange.com/questions/20129/how-and-when-do-i-use-hmac


The secret key must somehow be preshared, for example, to access a desktop app from a mobile app.
Additionally, 2FA can be achieved once the mobile client has the key, since the key can be
further encrypted and locally stored on the mobile device with a unique password provided by the user.
Even if the mobile device is lost, the key remains secure as long as the secondary password is unknown.

If you require more comprehensive security / encryption, including automatic key exchange,
TLS1.2 sockets should be used instead (ie. wss://) using a socket implementation such as
DnTlsBox in IOCPengine: https://bitbucket.org/voipobjects/iocpengine



in Delphi:

  mySalt := CreateSalt(10);
  myKeyHash := GetSha256KeyHash('mySecretKey',mySalt,100);
    myKeyHash := GetPBKDF2KeyHash('mySecretKey',mySalt,1000,1);  // <-- PBKDF2 can be used as an alternative
  testStr :='encrypt me!';
  EncryptOpenSSLAES256CBC(myKeyHash,testStr);  // testStr is now encrypted
  DecryptOpenSSLAES256CBC(myKeyHash,testStr);  // testStr should again equal 'encrypt me!'

  you should also authenticate the integrity of the encrypted message by including an HMAC+SHA256
  signature along with the encrypted message:

  authHash := GetHmacSha256Auth('mySecretKey',EncryptedMessage);


messages can be easily encrypted/decrypted from javascript using crypto-js:

<script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/sha256.js"></script>
<script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/aes.js"></script>
<script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/hmac-sha256.js"></script>
<script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/pbkdf2.js"></script>

<script language="javascript" type="text/javascript">

function hex2a(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

// create a key/hash with a salt and xxx iterations
// ie. msgJson = {"typ":"auth","salt":"SOcYFih","iter":100};

      if (msgJson.typ == "auth") {
        for (var j=1;j<=msgJson.iter;j++) {
          hash = CryptoJS.SHA256(hash+privateKey+msgJson.salt).toString();
        }

//encrypt
  var encryptedMsg = CryptoJS.AES.encrypt(msg,hash).toString();
  encryptedMsg += CryptoJS.HmacSHA256(encryptedMsg,hash);

//decrypt  
  var hmacCheck = json.substr(encryptedMsg.length-64,64);
  encryptedMsg = encryptedMsg.substr(0,encryptedMsg.length-64);
  if (hmacCheck == CryptoJS.HmacSHA256(encryptedMsg,hash)) {
    packet = hex2a(CryptoJS.AES.decrypt(encryptedMsg,hash).toString());
  } else { packet = "cannotAuthenticatePacket"; }

</script>


WARNING: Using websocket deflate with encryption is useless.  To use encryption + deflate,
you must deflate then encrypt.  From javascript, you can use the following code:

<script src="https://cdnjs.cloudflare.com/ajax/libs/pako/0.2.7/pako.min.js"></script>
<script language="javascript" type="text/javascript">

var deflate = new pako.Deflate({ level: 8, windowBits: -15, memLevel:9, to: 'string'});
var inflate = new pako.Inflate({ windowBits: -15, to: 'string'});

//deflate
  if (msgDeflate) {
    deflate.push(msg, 2);  //type 2 = Z_SYNC_FLUSH
    msg = CryptoJS.enc.Latin1.parse(deflate.result.substr(0,deflate.result.length-4));
  }
  encryptedMsg = CryptoJS.AES.encrypt(msg,hash).toString();
  encryptedMsg += CryptoJS.HmacSHA256(encryptedMsg,hash);

//inflate
  if (packet.substr(0,10) == "U2FsdGVkX1") {  //packet is encrypted
    var hmacCheck = json.substr(packet.length-64,64);
    packet = encryptedMsg.substr(0,packet.length-64);
    if (hmacCheck == CryptoJS.HmacSHA256(packet,hash)) {
      packet = hex2a(CryptoJS.AES.decrypt(packet,hash).toString());
      if (msgDeflate) {
        inflate.push(packet+"\x00\x00\xff\xff", 2);  //type 2 = Z_SYNC_FLUSH
        packet = inflate.result;
      }
    } else { packet = "cannotAuthenticatePacket"; }
  }

</script>


*)


unit WebSocketCrypt;

interface

uses SysUtils, DCPrijndael, DCPmd5, DCPbase64, DCPsha1, DCPsha256;


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


implementation

{$i DCPauth.pas}

procedure PKS7Padding(var rawS: AnsiString);
var i,padSize: integer;
begin
  padSize := 16 - (length(rawS) mod 16);
  for i := 1 to padSize do rawS:=rawS+chr(padSize);
end;


procedure EncryptOpenSSLAES256CBC(const hashS: AnsiString; var msgS: AnsiString);
//256-bit openssl-compatible AES format
var Cipher: TDCP_rijndael;
    Hash: TDCP_md5;
    key,key2,iv: array [0..31] of AnsiChar;
    salt,tmpKeyS,pwdS: AnsiString;
    rawS,tmpS: AnsiString;
    i: integer;
begin
  if (hashS = '') then exit;

  try
    salt := '';  tmpKeyS := '';  pwdS := '';
    for i := 0 to 7 do salt := salt + chr(random(254)+1);
    PKS7Padding(msgS);
    pwdS := hashS;
    Hash := TDCP_md5.Create(nil);
    Hash.Init;
    Hash.UpdateStr(pwdS+salt);
    Hash.Final(key);
    Hash.Init;
    for i:=0 to 15 do tmpKeyS:=tmpKeyS+key[i];
    Hash.UpdateStr(tmpKeyS+pwdS+salt);
    Hash.Final(key2);
    for i:=0 to 15 do begin tmpKeyS:=tmpKeyS+key2[i]; key[i+16]:=key2[i]; end;
    Hash.Init;
    Hash.UpdateStr(copy(tmpKeyS,17,16)+pwdS+salt);
    Hash.Final(iv);
    Hash.Free;
  except exit end;
//writeln('slt=',StringToHex(salt));
//write('key='); for i:= 0 to 31 do write(lowercase(IntToHex(ord(key[i]),2))); writeln;
//write('iv ='); for i:= 0 to 15 do write(lowercase(IntToHex(ord(iv[i]),2))); writeln;

  Cipher := TDCP_rijndael.Create(nil);

  Cipher.Init(key,256,@iv);
  try Cipher.EncryptCBC(msgS[1],msgS[1],length(msgS)); except end;
  msgS := Base64EncodeStr('Salted__'+salt+msgS);
//writeln(msgS);
  Cipher.Burn;
  Cipher.Free;
end;


//http://deusty.blogspot.com/2009/04/decrypting-openssl-aes-files-in-c.html
//http://stackoverflow.com/questions/8313992/dcpcrypt-delphi-not-properly-encoding-rijndael
//http://stackoverflow.com/questions/8806481/how-can-i-decrypt-something-with-pycrypto-that-was-encrypted-using-openssl
procedure DecryptOpenSSLAES256CBC(const hashS: AnsiString; var msgS: AnsiString);
//256-bit openssl-compatible AES format
var Cipher: TDCP_rijndael;
    Hash: TDCP_md5;
    key,key2,iv: array [0..31] of AnsiChar;
    salt,tmpKeyS,pwdS: AnsiString;
    rawS,tmpS: AnsiString;
    i,padLen: integer;
begin
  if (hashS = '') then exit;
  try
    rawS := Base64DecodeStr(msgS);
    salt := '';  tmpKeyS := '';  pwdS := '';
    if (copy(rawS,1,8)='Salted__') then begin  //openssl format
      salt := copy(rawS,9,8);
      delete(rawS,1,16);
     end;
    pwdS := hashS;
    Hash := TDCP_md5.Create(nil);
    Hash.Init;
    Hash.UpdateStr(pwdS+salt);
    Hash.Final(key);
    Hash.Init;
    for i:=0 to 15 do tmpKeyS:=tmpKeyS+key[i];
    Hash.UpdateStr(tmpKeyS+pwdS+salt);
    Hash.Final(key2);
    for i:=0 to 15 do begin tmpKeyS:=tmpKeyS+key2[i]; key[i+16]:=key2[i]; end;
    Hash.Init;
    Hash.UpdateStr(copy(tmpKeyS,17,16)+pwdS+salt);
    Hash.Final(iv);
    Hash.Free;
  except exit; end;
//writeln('slt=',StringToHex(salt));
//write('key='); for i:= 0 to 31 do write(lowercase(IntToHex(ord(key[i]),2))); writeln;
//write('iv ='); for i:= 0 to 15 do write(lowercase(IntToHex(ord(iv[i]),2))); writeln;

  Cipher := TDCP_rijndael.Create(nil);
  Cipher.Init(key,256,@iv);

  try Cipher.DecryptCBC(rawS[1],rawS[1],length(rawS)); except end;
  padLen := ord(copy(rawS,length(rawS),1)[1]);
  if (padLen > 0) then delete(rawS,length(rawS)-padLen+1,padLen);
  msgS := rawS;
  //  try msgS := Cipher.DecryptString(Base64EncodeStr(rawS)); except end;
  Cipher.Burn;
  Cipher.Free;
end;


//get len bytes worth of salt
function CreateSalt(const len: integer): AnsiString;
var ch: AnsiChar;
begin
  result := '';
  while (length(result)<len) do begin ch := chr(45+random(65)); if (ch in ['0'..'9','A'..'Z','a'..'z','$','&','#','@','_','*','!','~','.','?',':',';','^','%']) then result:=result+ch; end;
end;

//create an SHA256 hash of mySecretKey using mySalt with iter iterations
function GetSha256KeyHash(const mySecretKey,mySalt: AnsiString; const iter: integer): AnsiString;
var Hash: TDCP_sha256;
    Digest: array[0..31] of byte; //256-bit sha256 digest (32 bytes)
    tmpHashS: AnsiString;
    i,j: integer;
begin
  tmpHashS := '';
  Hash := TDCP_sha256.Create(nil);
  for i := 1 to iter do begin
    Hash.Init;
    Hash.UpdateStr(tmpHashS+mySecretKey+mySalt);
    Hash.Final(Digest);
    tmpHashS := '';  for j := 0 to 31 do begin tmpHashS := tmpHashS + lowercase(IntToHex(Digest[j],2)); end;
   end;
  Hash.Free;
  result := tmpHashS;
end;


//create a 256-bit PBKDF2 hash of mySecretKey using mySalt with iter iterations
//shaMode=1 to use Sha1 for compatibility with CryptoJS.PBKDF2()
//shaMode=2 to uses Sha256 as hash function
function GetPBKDF2KeyHash(const mySecretKey,mySalt: AnsiString; const iter: integer; const shaMode: Byte): AnsiString;
var tmpHashS: AnsiString;
    i: integer;
begin
  if (shaMode <= 1) then tmpHashS := PBKDF2(mySecretKey,mySalt,iter,256 div 8,TDCP_sha1) else
    tmpHashS := PBKDF2(mySecretKey,mySalt,iter,256 div 8,TDCP_sha256);
  result := '';  for i := 1 to 32 do begin result := result + lowercase(IntToHex(ord(tmpHashS[i]),2)); end;
end;


//create an HMAC + SHA256 message authentication using mySecretKey
function GetHmacSha256Auth(const mySecretKey,myMessage: AnsiString): AnsiString;
var tmpHashS: AnsiString;
    i: integer;
begin
  tmpHashS := CalcHMAC(myMessage, mySecretKey, TDCP_sha256);
  result := '';  for i := 1 to 32 do begin result := result + lowercase(IntToHex(ord(tmpHashS[i]),2)); end;
end;


initialization
  Randomize;

end.
