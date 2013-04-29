/* Copyright (c) 2006, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

// Copied from google-breakpad

struct MDGUID {
  uint32_t data1;
  uint16_t data2;
  uint16_t data3;
  uint8_t  data4[8];

  bool operator==(const MDGUID& other) const {
    return memcmp(this, &other, sizeof(this)) == 0;
  }
};

/* (MDRawModule).cv_record can reference MDCVInfoPDB20 or MDCVInfoPDB70.
 * Ref.: http://www.debuginfo.com/articles/debuginfomatch.html
 * MDCVInfoPDB70 is the expected structure type with recent toolchains. */

typedef struct {
  uint32_t signature;
  uint32_t offset;     /* Offset to debug data (expect 0 in minidump) */
} MDCVHeader;

typedef struct {
  uint32_t  cv_signature;
  MDGUID    signature;         /* GUID, identifies PDB file */
  uint32_t  age;               /* Identifies incremental changes to PDB file */
  uint8_t   pdb_file_name[1];  /* Pathname or filename of PDB file,
                                * 0-terminated 8-bit character data (UTF-8?) */
} MDCVInfoPDB70;

#define MD_CVINFOPDB70_SIGNATURE 0x53445352  /* cvSignature = 'SDSR' */
