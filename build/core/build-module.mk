# Copyright (C) 2008 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Base rules shared to control the build of all modules.
# This should be included from build-binary.mk
#

$(call assert-defined,LOCAL_MODULE_CLASS LOCAL_BUILD_SCRIPT LOCAL_BUILT_MODULE)

# Check LOCAL_IS_HOST_MODULE and define 'my' as either HOST_ or TARGET_
#
LOCAL_IS_HOST_MODULE := $(strip $(LOCAL_IS_HOST_MODULE))
ifdef LOCAL_IS_HOST_MODULE
  ifneq ($(LOCAL_IS_HOST_MODULE),true)
    $(call __ndk_log,$(LOCAL_PATH): LOCAL_IS_HOST_MODULE must be "true" or empty, not "$(LOCAL_IS_HOST_MODULE)")
  endif
  my := HOST_
else
  my := TARGET_
endif

# Compute 'intermediates' which is the location where we're going to store
# intermediate generated files like object (.o) files.
#
intermediates := $($(my)OBJS)

# LOCAL_INTERMEDIATES lists the targets that are generated by this module
#
LOCAL_INTERMEDIATES := $(LOCAL_BUILT_MODULE)

# LOCAL_BUILD_MODE will be either release or debug
#
ifneq ($(NDK_APP_OPTIM),)
    LOCAL_BUILD_MODE := $(NDK_APP_OPTIM)
else
    LOCAL_BUILD_MODE := release
endif

#
# Ensure that 'make <module>' and 'make clean-<module>' work
#
.PHONY: $(LOCAL_MODULE)
$(LOCAL_MODULE): $(LOCAL_BUILT_MODULE)

cleantarget := clean-$(LOCAL_MODULE)-$(TARGET_ARCH_ABI)
.PHONY: $(cleantarget)
clean: $(cleantarget)

$(cleantarget): PRIVATE_MODULE      := $(LOCAL_MODULE)
$(cleantarget): PRIVATE_TEXT        := [$(TARGET_ARCH_ABI)]
$(cleantarget): PRIVATE_CLEAN_FILES := $(LOCAL_BUILT_MODULE) \
                                       $(intermediates)

$(cleantarget)::
	@echo "Clean: $(PRIVATE_MODULE) $(PRIVATE_TEXT)"
	$(hide) rm -rf $(PRIVATE_CLEAN_FILES)

