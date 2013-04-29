#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>

#include <windows.h>
#include <winnt.h>
#include <dbghelp.h>

#include "codeview.h"

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

void error(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);

  exit(1);
}

const void*
mmap(const char* path)
{
  HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
  if (INVALID_HANDLE_VALUE == file) {
    error("CreateFile failed (%d): %s", GetLastError(), path);
  }
  HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY,
                                     0, 0, NULL);
  if (NULL == mapping) {
    error("CreateFileMapping failed (%d): %s", GetLastError(), path);
  }

  void* addr = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
  if (NULL == addr) {
    error("MapViewOfFile failed (%d): %s", GetLastError(), path);
  }
  return addr;
}

template<class T>
class TPointer
{
public:
  TPointer(T* p) : mP(p) { }

  template<class D>
  operator D*() {
    return static_cast<D*>(mP);
  }

private:
  T* mP;
};
typedef TPointer<void> Pointer;
typedef TPointer<const void> ConstPointer;

static ConstPointer
offset(const void* base, ULONG64 offset)
{
  return static_cast<const char*>(base) + offset;
}

static Pointer
offset(void* base, ULONG64 offset)
{
  return static_cast<char*>(base) + offset;
}

// Given an RVA within a DLL file, find the offset of that data within
// the file on disk.
bool
GetDllOffsetFromRVA(const IMAGE_NT_HEADERS* headers, DWORD rva, DWORD* offset) 
{
  // Look up the section the RVA belongs to 

  bool found = false; 

  const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(headers); 
  const IMAGE_SECTION_HEADER* lastSection = section + headers->FileHeader.NumberOfSections;

  for( ; section < lastSection; ++section) {
    DWORD SectionSize = pSectionHeader->Misc.VirtualSize; 

    if(rva >= pSectionHeader->VirtualAddress &&
       rva < pSectionHeader->VirtualAddress + SectionSize) {
      found = true; 
      break; 
    }
  }

  if(!found) {
    return false; 
  }

  *offset = section->PointerToRawData + rva - section->VirtualAddress;

  return true; 
}

int main(int argc, char** argv)
{
  if (argc != 3) {
    error("Usage: fulldump-relocation-checker <dumpfile> <xul.dll>");
  }

  const void* dumpdata = static_cast<const char*>(mmap(argv[1]));
  const MINIDUMP_HEADER* dump = offset(dumpdata, 0);
  if (dump->Signature != MINIDUMP_SIGNATURE) {
    error("Minidump signature mismatch.");
  }
  if (!(dump->Flags & MiniDumpWithFullMemory)) {
    error("Not a full-memory minidump.");
  }

  const MINIDUMP_DIRECTORY* streams = offset(dumpdata, dump->StreamDirectoryRva);

  const MINIDUMP_MEMORY64_LIST* memorylist = NULL;
  const MINIDUMP_MODULE_LIST* modulelist = NULL;
  for (ULONG32 i = 0; i < dump->NumberOfStreams; ++i) {
    switch (streams[i].StreamType) {
    case Memory64ListStream:
      if (memorylist) {
        error("Multiple Memory64ListStream");
      }
      memorylist = offset(dumpdata, streams[i].Location.Rva);
      break;
    case ModuleListStream:
      if (modulelist) {
        error("Multiple ModuleListStream");
      }
      modulelist = offset(dumpdata, streams[i].Location.Rva);
    }
  }
  if (!memorylist) {
    error("No Memory64ListStream present");
  }
  if (!modulelist) {
    error("No ModuleListStream present");
  }

  // Load the DLL and find out it's debug name/signature

  const void* dlldata = mmap(argv[2]);
  const IMAGE_DOS_HEADER* dosheader = offset(dlldata, 0);
  if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) {
    error("Not a DLL");
  }

  const IMAGE_NT_HEADERS* dllheader = offset(dlldata, dosheader->e_lfanew);
  if (dllheader->Signature != IMAGE_NT_SIGNATURE) {
    error("No PE header");
  }

  const IMAGE_DATA_DIRECTORY* debuginfo =
    &dllheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

  DWORD debugDirectoriesOffset;
  if (!GetFileOffsetFromRVA(dllheader, debuginfo->VirtualAddress, &debugDirectoriesOffset)) {
    error("No section for debug directories");
  }

  const char* debugName = NULL;
  const MDGUID* debugSignature = NULL;

  const IMAGE_DEBUG_DIRECTORY* debugdirectories = offset(dlldata, debugDirectoriesOffset);
  const IMAGE_DEBUG_DIRECTORY* debugdirectoriesend =
    debugdirectories + (debuginfo->Size / sizeof(IMAGE_DEBUG_DIRECTORY));
  for (const IMAGE_DEBUG_DIRECTORY* curdebug = debugdirectories;
       curdebug < debugdirectoriesend; 
       ++curdebug) {
    if (curdebug->Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
      DWORD codeViewOffset;
      if (!GetFileOffsetFromRVA(dllheader, curdebug->AddressOfRawData, &codeViewOffset)) {
        error("No section for codeview data");
      }
      const MDCVInfoPDB70* codeview = offset(dlldata, codeViewOffset);
      if (codeview->cv_signature != MD_CVINFOPDB70_SIGNATURE) {
        error("Codeview signature mismatch");
      }

      debugName = reinterpret_cast<const char*>(codeview->pdb_file_name);
      debugSignature = &codeview->signature;
      break;
    }
  }
  if (!debugName) {
    error("No debug signature found.");
  }

  // Find the dump code module which matches this DLL

  const MINIDUMP_MODULE* matchingModule = NULL;

  for (const MINIDUMP_MODULE* module = modulelist->Modules;
       module < modulelist->Modules + modulelist->NumberOfModules;
       ++module) {
    const MDCVInfoPDB70* codeview = offset(dumpdata, module->CvRecord.Rva);
    if (!codeview || codeview->cv_signature != MD_CVINFOPDB70_SIGNATURE) {
      continue;
    }
    if (!strcmp(reinterpret_cast<const char*>(codeview->pdb_file_name), debugName) &&
        codeview->signature == *debugSignature) {
      matchingModule = module;
      break;
    }
  }
  if (!matchingModule) {
    error("Couldn't find the DLL in the dump.");
  }

  const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(dllheader);
  const IMAGE_SECTION_HEADER* lastSection = section + dllheader->FileHeader.NumberOfSections;

  for (; section < lastSection; ++section) {
    if (section->Characteristics & IMAGE_SCN_CNT_CODE) {
      printf("Checking section: %s\n", section->Name);

      ULONG64 sectionAddress = section->VirtualAddress + matchingModule->BaseOfImage;

      ULONG64 byteOffset = memorylist->BaseRva;
      const MINIDUMP_MEMORY_DESCRIPTOR64* range = memorylist->MemoryRanges;
      const MINIDUMP_MEMORY_DESCRIPTOR64* rangeend = range + memorylist->NumberOfMemoryRanges;
      for ( ; range < rangeend; byteOffset += range->DataSize, ++range ) {
        if (range->StartOfMemoryRange <= sectionAddress &&
            range->StartOfMemoryRange + range->DataSize > sectionAddress) {
          if (range->StartOfMemoryRange + range->DataSize < sectionAddress + section->SizeOfRawData) {
            error("Memory range doesn't contain section");
          }
          bool mismatch = false;

          char* sectionCopy = static_cast<char*>(malloc(section->SizeOfRawData));
          memcpy(sectionCopy, offset(dlldata, section->PointerToRawData), section->SizeOfRawData);

          // Do the relocations
          size_t delta = matchingModule->BaseOfImage - dllheader->OptionalHeader.ImageBase;

          const IMAGE_DATA_DIRECTORY* relocs =
            &dllheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
          if (!relocs->Size) {
            error("No relocations found. Something is wrong.");
          }
          DWORD relocsOffset;
          if (!GetFileOffsetFromRVA(dllheader, relocs->VirtualAddress, &relocsOffset)) {
            error(".relocs section data missing?");
          }
          for (const IMAGE_BASE_RELOCATION* baseRelocation = offset(dlldata, relocsOffset);
               baseRelocation->VirtualAddress;
               baseRelocation = offset(baseRelocation, baseRelocation->SizeOfBlock)) {
            DWORD baseRelocationAddress = baseRelocation->VirtualAddress;

            const WORD* relInfo = reinterpret_cast<const WORD*>(baseRelocation + 1);
            const WORD* relEnd = offset(baseRelocation, baseRelocation->SizeOfBlock);
            for ( ; relInfo < relEnd; ++relInfo) {
              DWORD relocationAddress = baseRelocationAddress + (*relInfo & 0xfff);
              DWORD relocationType = *relInfo >> 12;

              if (relocationAddress < section->VirtualAddress ||
                  relocationAddress >= section->VirtualAddress + section->SizeOfRawData) {
                continue;
              }
              switch (relocationType) {
              case IMAGE_REL_BASED_ABSOLUTE:
                break; // nothing to do

              case IMAGE_REL_BASED_HIGHLOW: {
                DWORD* addr = offset(sectionCopy, relocationAddress - section->VirtualAddress);
                *addr += delta;
                break;
              }

              default:
                error("Unexpected relocation type: %i\n", relocationType);
              }
            }
          }

          const char* sectionByte = sectionCopy;
          const char* sectionEnd = sectionByte + section->SizeOfRawData;
          const char* dumpByte = offset(dumpdata, byteOffset + sectionAddress - range->StartOfMemoryRange);
          for ( ; sectionByte < sectionEnd; ++sectionByte, ++dumpByte) {
            if (*sectionByte != *dumpByte) {
              DWORD rva = sectionByte - sectionCopy + section->VirtualAddress;
              printf("Mismatch: rva 0x%x expected byte 0x%x got 0x%x\n",
                     rva, *sectionByte, *dumpByte);
              mismatch = true;
            }
          }
          if (!mismatch) {
            printf("No memory corruption detected\n");
          }
          free(sectionCopy);
          break;
        }
      }
    }
  }
  return 0;
}
