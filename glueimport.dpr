program glueimport;

{$APPTYPE CONSOLE}
{$R *.res}
{$WARN SYMBOL_PLATFORM OFF}


uses
  System.Classes,
  System.Generics.Collections,
  System.SysUtils,

  vmsweeper.reffile in 'vmsweeper.reffile.pas',

  pe.build,

  pe.build.import,
  pe.common,
  pe.image,
  pe.imports,
  pe.imports.lib,
  pe.imports.func,
  pe.section,
  pe.types.directories;

procedure generate_new_imports(img: TPEImage; Libs: TLibs);
const
  opcJmpPtr: word = $25FF;
  opcCallPtr: word = $15FF;
var
  libPair: TLibPair;
  funcPair: TFuncPair;
  tmpVA, iatVA: uint64;
  lib: TPEImportLibrary;
  iatIndex: UInt32;
  imps: TImpList;
  i: Integer;
  rec: TImp;
  FlatImpList: TImpList;
  iatDir: TImageDataDirectory;
begin

  FlatImpList := TImpList.Create;
  try
    // Fill image imports.

    img.imports.Clear;

    iatIndex := 0;
    for libPair in Libs do
    begin
      writeln('  ', libPair.Key);

      lib := img.imports.NewLib(libPair.Key);
      for funcPair in libPair.Value do
      begin
        lib.NewFunction(funcPair.Key);

        imps := funcPair.Value;
        for i := 0 to imps.Count - 1 do
        begin
          rec := imps[i];
          rec.iatIndex := iatIndex;
          FlatImpList.Add(rec);
        end;

        inc(iatIndex);
      end;

      inc(iatIndex); // null item
    end;

    // Create new import table.
    ReBuildDirData(img, DDIR_IMPORT, true);

    // Redirect imports to new IAT.
    if not img.DataDirectories.Get(DDIR_IAT, @iatDir) then
      raise Exception.Create('Failed to get IAT.');

    iatVA := img.RVAToVA(iatDir.VirtualAddress);

    for rec in FlatImpList do
    begin
      // jmp dword ptr [...]
      img.PositionVA := rec.srcVA;

      if (rec.dispType = TImpDispatchType.Jump) then
      begin
        img.Write(opcJmpPtr, sizeof(opcJmpPtr));
      end
      else
      begin
        img.Write(opcCallPtr, sizeof(opcCallPtr));
      end;

      // address
      tmpVA := iatVA + rec.iatIndex * img.ImageWordSize;
      img.Write(tmpVA, img.ImageWordSize)
    end;
  finally
    FreeAndNil(FlatImpList);
  end;
end;

procedure PrintHeader;
begin
  writeln('VMProtect import fixer based on VMSweeper');
  writeln('Credits to Vamit');
  writeln;
  writeln('This tool applies imports found by VMSweeper to existing dump');
  writeln('Generally it''s for analysis, not for complete image unpack');
  writeln;
  writeln('Usage:');
  writeln('  <ref> <dump> [<out>]');
  writeln('  <ref>:  text file, just copy it from VMSweeper''s VM References window');
  writeln('          it must contain resolved imports');
  writeln('  <dump>: executable dump file name used to add imports');
  writeln('  <out>:  optional file name for result executable');
end;

procedure main(const refFn, dumpFn, outFn: string);
var
  Libs: TLibs;
  img: TPEImage;
  outputFn: string;
begin
  if (refFn.IsEmpty) or (dumpFn.IsEmpty) then
  begin
    PrintHeader;
    exit;
  end;

  Libs := TLibs.Create([doOwnsValues]);
  try
    write('Parsing reference file... ');
    ParseImportsFromRefFile(refFn, Libs);
    writeln(Libs.Count, ' libraries');

    img := TPEImage.Create;
    try
      write('Reading dump... ');
      // load dump only, don't parse directories' content
      if not img.LoadFromFile(dumpFn, []) then
      begin
        writeln('failed');
        exit;
      end;
      writeln('ok');

      writeln('Creating new imports');
      generate_new_imports(img, Libs);

      if outFn <> '' then
        outputFn := outFn
      else
        outputFn := ChangeFileExt(dumpFn, '_imp' + ExtractFileExt(dumpFn));

      writeln('Saving new image');
      img.SaveToFile(outputFn);

      writeln('Done');
    finally
      img.Free;
    end;
  finally
    FreeAndNil(Libs);
  end;
end;

begin
  ReportMemoryLeaksOnShutdown := true;
  try
    main(paramstr(1), paramstr(2), paramstr(3));
    if DebugHook <> 0 then
      readln;
  except
    on E: Exception do
      writeln(E.ClassName, ': ', E.Message);
  end;
end.
