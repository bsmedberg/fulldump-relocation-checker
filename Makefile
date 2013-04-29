DEPS = codeview.h
CXXFLAGS = -Zi -DEBUG -link -incremental:no

fulldump-relocation-checker.exe: fulldump-relocation-checker.cc Makefile $(DEPS)
	cl.exe -Fe$@ -Fd$($@:.exe=.pdb) $< $(CXXFLAGS)

run: fulldump-relocation-checker.exe
	$< ~/Desktop/juanb-b39f1aa7-8676-4be1-9d2e-f11836957863.dmp c:/builds/debugging-builds/ff-21.0b4/installed/xul.dll

debug: fulldump-relocation-checker.exe
	devenv -debugexe $< ~/Desktop/juanb-b39f1aa7-8676-4be1-9d2e-f11836957863.dmp c:/builds/debugging-builds/ff-21.0b4/installed/xul.dll