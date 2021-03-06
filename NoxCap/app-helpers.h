#pragma once
#include "stdafx.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
extern bool is_app(HANDLE process);
extern wchar_t *get_app_sid(HANDLE process);
extern HANDLE open_app_mutex(const wchar_t *sid, const wchar_t *name);
extern HANDLE open_app_event(const wchar_t *sid, const wchar_t *name);
extern HANDLE open_app_map(const wchar_t *sid, const wchar_t *name);
#ifdef __cplusplus
}
#endif