/*
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

  .section .note.android.ident,"a",%note
  .balign 4
  .type note_android_ident, %object
note_android_ident:
  .long note_data-note_name  // int32_t n_namesz
  .long note_end-note_data  // int32_t n_descsz
  .long 1  // int32_t n_type
note_name:
  .ascii "Android\0"  // char name[]

note_data:
  // int32_t android_api
  .long PLATFORM_SDK_VERSION

  // char ndk_version[64]
ndk_version:
  .asciz ABI_NDK_VERSION
  .org ndk_version+64

  // char ndk_build_number[64]
ndk_build_number:
  .asciz ABI_NDK_BUILD_NUMBER
  .org ndk_build_number+64

note_end:
  .size note_android_ident, .-note_android_ident

#if defined(__aarch64__)
  .pushsection .note.gnu.property, "a"
    .balign 8
    .long 4
    .long 0x10
    .long 0x5        // NT_GNU_PROPERTY_TYPE_0
    .asciz "GNU"
    .long 0xc0000000 // GNU_PROPERTY_AARCH64_FEATURE_1_AND
    .long 4
    .long 0x3        // PAuth and BTI compatible
    .long 0
  .popsection
#endif
