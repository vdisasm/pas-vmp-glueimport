unit vmsweeper.reffile;

interface

uses
  System.Classes,
  System.Generics.Collections,
  System.SysUtils;

type
  TImpDispatchType =
  (
    Jump, // FF25..
    Call  // FF15..
  );

  // List of addresses referencing same function.
  TImp = record
    dispType: TImpDispatchType;
    srcVA: uint64;
    iatIndex: uint32;
  end;

  TImpList = TList<TImp>;

  TFuncName = string;
  TFuncPair = TPair<TFuncName, TImpList>;
  TFuncs = TObjectDictionary<TFuncName, TImpList>;

  TLibName = string;
  TLibPair = TPair<TLibName, TFuncs>;
  TLibs = TObjectDictionary<TLibName, TFuncs>;

procedure ParseImportsFromRefFile(const RefFileName: string; Libs: TLibs);

implementation

const
  HexDigits = ['0' .. '9', 'a' .. 'f', 'A' .. 'F'];

function IsHex(const s: string): boolean;
var
  c: char;
begin
  if s.IsEmpty then
    exit(false);
  for c in s do
    if not(CharInSet(c, HexDigits)) then
      exit(false);
  exit(true);
end;

procedure SplitWords(const line: string; words: TStringList);
var
  word: string;
  p: pchar;
  i, w0: integer;
begin
  words.Clear;
  if line.IsEmpty then
    exit;
  p := pchar(line);
  i := 0;
  w0 := -1;
  while i <= length(line) do
  begin
    if (p[0] = #0) or ((p[0] = ' ') and (p[1] = ' ')) then
    begin
      if w0 <> -1 then
      begin
        word := line.Substring(w0, i - w0);
        words.Add(word);
        w0 := -1;
      end;
    end
    else if (p[0] <> ' ') then
    begin
      if w0 = -1 then
        w0 := i;
    end;

    inc(p);
    inc(i);
  end;
end;

procedure AddFunc(va: uint64; const lib, func: string; Libs: TLibs; call: boolean);
var
  libName: string;
  funcs: TFuncs;
  list: TImpList;
  rec: TImp;
begin
  libName := lib.ToLower;
  if not Libs.TryGetValue(libName, funcs) then
  begin
    funcs := TFuncs.Create([doOwnsValues]);
    Libs.Add(libName, funcs);
  end;

  if not funcs.TryGetValue(func, list) then
  begin
    list := TImpList.Create;
    funcs.Add(func, list);
  end;

  if (call) then
    rec.dispType := TImpDispatchType.Call
  else
    rec.dispType := TImpDispatchType.Jump;

  rec.srcVA := va;
  rec.iatIndex := 0;

  list.Add(rec);
end;

function IsStatusDoneOrProcessing(txt: string): boolean; inline;
begin
  txt := txt.ToUpper();
  result := txt.Equals('DONE') or
            txt.Equals('PROCESSING');
end;

procedure ParseImportsFromRefFile(const RefFileName: string; Libs: TLibs);
var
  sl: TStringList;
  i: integer;
  words: TStringList;
  libFunc: TArray<string>;
  va: uint64;
  isCall: boolean;
begin
  sl := TStringList.Create;
  words := TStringList.Create;
  try
    sl.LoadFromFile(RefFileName);
    for i := 0 to sl.Count - 1 do
    begin
      SplitWords(sl[i], words);
      if (words.Count = 4) and IsStatusDoneOrProcessing(words[3]) and IsHex(words[0]) then
      begin
        libFunc := words[2].Split(['.']);
        if (length(libFunc) = 2) then
        begin
          isCall := words[1].ToUpper().StartsWith('CALL');
          va := uint64(StrToInt64('$' + words[0]));
          AddFunc(va, libFunc[0], libFunc[1], Libs, isCall);
        end;
      end;
    end;
  finally
    sl.Free;
    words.Free;
  end;
end;

end.
