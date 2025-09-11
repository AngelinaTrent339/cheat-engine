unit feces;
//friends endorsing cheat engine system

{$mode objfpc}{$H+}

interface

{$ifdef windows}
uses
  Classes, SysUtils, System.uitypes, bcrypt, DOM, xmlutils, XmlRead, XMLWrite, dialogs, windows,
  graphics, math;

function canSignTables: boolean;
procedure signTable(cheattable: TDOMElement);
procedure signTableFile(f: string);
function isProperlySigned(cheattable: TDOMElement; out specialstring: string; out imagepos: integer; out image: tpicture): boolean;

{$endif}

implementation

{$ifdef windows}

uses cefuncproc, CustomBase85, registry, formsettingsunit, mainunit2;

resourcestring
  rsFailedToGetSignatureSize = 'Failed to get the signature size';
  rsFailedToFinishTheHash = 'Failed to finish the hash';
  rsFailedToGetHashlength = 'Failed to get hashlength';
  rsFailedHashingTable = 'Failed hashing table';
  rsFailedCreatingHash = 'Failed creating hash';
  rsFailedGettingTheObjectLength = 'Failed getting the object length';
  rsFailedCreatingHasAlgorithmProvider = 'Failed creating has algorithm '
    +'provider';
  rsFailedToLoadPrivateKey = 'Failed to load private key';
  rsIsPasswordCorrect='Is the password correct?';
  rsCouldNotOpenTheAlgorithmProvider = 'Could not open the algorithm provider.  Load the table as if it''s signature is valid?';
  rsBcryptCouldNotBeUsed = 'bcrypt could not be used';
  rsSelectYourCheatEngineSignatureFile = 'Select your '+strCheatEngine+' signature '
    +'file';
  rsCheatEngineSignatureFiles = strCheatEngine+' signature files';
  rsThisTableHasBeenModified = 'This table has been modified. To load this '
    +'table, remove the signature part with an editor (And check the file for '
    +'suspicious things while you''re at it)';
  rsFailedToFinishTheHash2 = 'Failed to finish the hash 2';
  rsFailedToGetHashlength2 = 'Failed to get hashlength 2';
  rsFailedHashingTable2 = 'Failed hashing table 2';
  rsFailedCreatingHash2 = 'Failed creating hash 2';
  rsInvalidPublicKey = 'The provided public key is invalid(Not signed by the '
    +strCheatEngine+' guy). Remove the signature section to load this table';
  rsFailedCreatingHasAlgorithmProvider2 = 'Failed creating has algorithm '
    +'provider';
  rsFailedToLoadTheTablePublicKey = 'Failed to load the table public key';
  rsFailedToLoadCheatEnginePublicKey = 'Failed to load '+strCheatEngine+' public key';
  rsNoSignedHash = 'This table''s signature does not contain a SignedHash '
    +'element';
  rsNoPublicKey =
    'This table''s signature does not contain a PublicKey element';


var
  cheatenginepublictablekey: BCRYPT_KEY_HANDLE=0;
  publictablekey: array [0..139] of byte =($45, $43, $53, $35, $42, $00, $00,
   $00, $01, $A3, $7A, $45, $2A, $66, $60, $85, $C7, $50, $9D, $8C, $3F, $34,
   $57, $D3, $FF, $50, $E3, $32, $CA, $4C, $4D, $61, $9B, $00, $19, $7E, $61,
   $6B, $1F, $52, $50, $7E, $01, $94, $8B, $F0, $A4, $91, $49, $FC, $58, $32,
   $D8, $43, $60, $F7, $F1, $46, $F5, $CB, $A0, $AB, $0B, $26, $D4, $1D, $9D,
   $BE, $40, $C8, $12, $30, $CA, $15, $01, $30, $A9, $4D, $03, $6E, $4E, $4A,
   $5E, $85, $CF, $85, $5D, $D7, $24, $47, $36, $A6, $25, $2B, $B0, $48, $7E,
   $95, $8F, $F2, $9A, $FF, $B3, $C9, $C9, $97, $85, $FB, $59, $4F, $8A, $D4,
   $FF, $A4, $80, $A4, $AE, $92, $B8, $48, $64, $74, $05, $7C, $97, $90, $A3,
   $7E, $0E, $72, $76, $5B, $B4, $D8, $18, $E5, $A6, $A2, $E3, $47);

threadvar pathtosigfile: pchar;
threadvar passwordhash: pbyte;

var passwordhashlength: integer;

//useless protection but hey, why not

type TCanSign=(csUnknown, csYes, csNo);

var
  EncodePointer:function(p: pointer):pointer; stdcall;
  DecodePointer:function(p: pointer):pointer; stdcall;

  _cansignstate: TCanSign=csUnknown;

var rv: dword=0;
function EncodePointerNI(p: pointer):pointer; stdcall; //not implemented (unpatched XP)
begin
  if rv=0 then
    rv:=1+random($fffffffd);

  result:=pointer(ptruint(p) xor rv);
end;

function DecodePointerNI(p: pointer):pointer; stdcall;
begin
  if rv=0 then exit(p);

  result:=pointer(ptruint(p) xor rv);
end;



procedure getXmlfileWithoutSignature(cheattable: TDOMElement; output: tstream);
var
  signature: TDOMNode;
begin
  signature:=CheatTable.FindNode('Signature');

  if signature<>nil then
  begin
    CheatTable.DetachChild(signature);
    signature.free;
  end;

  if cheattable<>nil then
  begin
    //showmessage(cheattable.TextContent);
    WriteXML(cheattable,output);
//    output.WriteAnsiString(cheattable.TextContent);
  end;
end;

function isProperlySigned(cheattable: TDOMElement; out specialstring: string; out imagepos: integer; out image: TPicture): boolean;
begin
  // Signature verification disabled - always return true
  specialstring := '';
  imagepos := 0;
  image := nil;
  result := true;
end;


function canSignTables: boolean;
begin
  // Always return false - signing disabled
  result := false;
end;

procedure signTable(cheattable: TDOMElement);
begin
  // Table signing disabled - do nothing
end;

procedure signTableFile(f: string);
begin
  // Table file signing disabled - do nothing
end;

procedure generateHash(password: pointer; passwordsize: integer; var hash: pointer; var hashsize: integer);
var
  s: ntstatus;
  hashAlgoritm: BCRYPT_ALG_HANDLE;
  hhash: BCRYPT_HASH_HANDLE;
  objectlength: dword;
  bHashObject: pointer;

  size: ulong;
  i,j: integer;
  secondaryvalue: byte;
begin
  hash:=nil;
  hashsize:=0;
  if passwordsize=0 then exit;

  s:=BCryptOpenAlgorithmProvider(hashAlgoritm, 'SHA512', nil, 0);
  if succeeded(s) then
  begin
    objectlength:=0;
    s:=BCryptGetProperty(hashAlgoritm, BCRYPT_OBJECT_LENGTH, @objectlength, sizeof(DWORD), size, 0);
    if succeeded(s) then
    begin
      getmem(bHashObject, objectlength);
      zeromemory(bHashObject, objectlength);
      hHash:=0;
      s:=BCryptCreateHash(hashAlgoritm, hHash, bHashObject, objectlength, nil, 0, 0);
      if succeeded(s) then
      begin
        s:=BCryptHashData(hHash, password, passwordsize, 0);
        if succeeded(s) then
        begin
          s:=BCryptGetProperty(hashAlgoritm, BCRYPT_HASH_LENGTH, @hashsize, sizeof(DWORD), size, 0);
          if succeeded(s) then
          begin
            getmem(hash, hashsize);
            s:=BCryptFinishHash(hHash, hash, hashsize, 0);

          end;
        end;
        BCryptDestroyHash(hashAlgoritm);
      end;
      FreeMemAndNil(bHashObject);
      BCryptCloseAlgorithmProvider(hashAlgoritm,0);
    end;
  end;
end;

procedure getPasswordHash(password: string; out pwhash: pointer; out pwhashlength: integer; wantedsize: integer);
var
  hash: array of byte;

  initialHash: pbyte;
  initialhashsize: integer;

  partialhash: pbyte;
  partialhashsize: integer;

  hashpos: integer;
  copysize: integer;
  i,j: integer;
begin
  pwhash:=nil;
  if password='' then exit;

  setlength(hash,wantedsize);


  //generate hashes until it's the size of the buffer
  hashpos:=0;

  generateHash(@password[1],length(password),initialhash,initialhashsize);

  j:=1;
  for i:=0 to initialhashsize-1 do
  begin
    initialhash[i]:=initialhash[i] xor ord(password[j]);
    inc(j);
    if j>length(password) then j:=1;
  end;

  generateHash(initialhash,initialhashsize,partialhash,partialhashsize);
  FreeMemAndNil(initialhash);

  copysize:=ifthen(partialhashsize>wantedsize, wantedsize, partialhashsize);
  copymemory(@hash[0],partialhash, copysize);
  FreeMemAndNil(partialhash);

  inc(hashpos, copysize);

  while hashpos<wantedsize do
  begin
    generateHash(@hash[hashpos-copysize],copysize,partialhash, partialhashsize);

    copysize:=ifthen(partialhashsize+hashpos>wantedsize, wantedsize-hashpos, partialhashsize);
    copymemory(@hash[hashpos],partialhash, copysize);
    FreeMemAndNil(partialhash);
    inc(hashpos,copysize);
  end;

  getmem(pwhash, wantedsize);
  copymemory(pwhash, @hash[0],wantedsize);

  setlength(hash,0);
end;


procedure passwordDecode(buffer: pbyte; buffersize: integer; pwhash: pbyte);
var
  i: integer;
begin
  for i:=0 to buffersize-1 do
    buffer[i]:=buffer[i] xor pwhash[i];
end;

var k32: HMODULE;
initialization
  k32:=GetModuleHandle('kernel32.dll');
  pointer(encodepointer):=GetProcAddress(k32,'EncodePointer');
  pointer(decodepointer):=GetProcAddress(k32,'DecodePointer');

  if not assigned(encodepointer) then
    (encodepointer):=@EncodePointerNI;

  if not assigned(decodepointer) then
    (decodepointer):=@DecodePointerNI;

{$endif}

end.

