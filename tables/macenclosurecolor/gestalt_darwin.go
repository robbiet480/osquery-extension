//go:build darwin

package macenclosurecolor

/*
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <stdlib.h>

typedef CFTypeRef (*MGCopyAnswerFn)(CFStringRef);

static MGCopyAnswerFn mg_copy_answer_fn = NULL;

static int load_mg(void) {
    if (mg_copy_answer_fn) return 1;
    void* h = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    if (!h) return 0;
    mg_copy_answer_fn = (MGCopyAnswerFn)dlsym(h, "MGCopyAnswer");
    return mg_copy_answer_fn != NULL ? 1 : 0;
}

// mg_int returns the integer value for key, or -1 if missing/wrong type.
static int mg_int(const char* key) {
    if (!mg_copy_answer_fn) return -1;
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!k) return -1;
    CFTypeRef v = mg_copy_answer_fn(k);
    CFRelease(k);
    if (!v) return -1;
    int result = -1;
    CFTypeID tid = CFGetTypeID(v);
    if (tid == CFNumberGetTypeID()) {
        CFNumberGetValue((CFNumberRef)v, kCFNumberIntType, &result);
    } else if (tid == CFStringGetTypeID()) {
        char buf[64];
        if (CFStringGetCString((CFStringRef)v, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            result = atoi(buf);
        }
    }
    CFRelease(v);
    return result;
}

// mg_string returns a malloc'd UTF-8 copy of the string answer, or NULL.
static char* mg_string(const char* key) {
    if (!mg_copy_answer_fn) return NULL;
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!k) return NULL;
    CFTypeRef v = mg_copy_answer_fn(k);
    CFRelease(k);
    if (!v) return NULL;
    char* result = NULL;
    if (CFGetTypeID(v) == CFStringGetTypeID()) {
        CFIndex len = CFStringGetMaximumSizeForEncoding(
            CFStringGetLength((CFStringRef)v), kCFStringEncodingUTF8) + 1;
        result = (char*)malloc((size_t)len);
        if (result && !CFStringGetCString((CFStringRef)v, result, len, kCFStringEncodingUTF8)) {
            free(result);
            result = NULL;
        }
    }
    CFRelease(v);
    return result;
}
*/
import "C"

import (
	"sync"
	"unsafe"
)

// mobileGestalt is the production Gestalt that calls
// /usr/lib/libMobileGestalt.dylib via cgo. It performs a one-time dlopen +
// dlsym lookup of MGCopyAnswer.
type mobileGestalt struct{}

// loadOnce guards the dlopen/dlsym so the dynamic-loader work happens exactly
// once per process even if the table is queried concurrently. (The C side is
// also idempotent, but the Go-side guard avoids redundant cgo calls and makes
// initialization ordering explicit.)
var loadOnce sync.Once

// newGestalt loads libMobileGestalt.dylib and returns a Gestalt. If loading
// fails, the returned Gestalt still satisfies the interface but every lookup
// reports not-present.
func newGestalt() Gestalt {
	loadOnce.Do(func() { C.load_mg() })
	return mobileGestalt{}
}

func (mobileGestalt) Int(key string) (int, bool) {
	ck := C.CString(key)
	defer C.free(unsafe.Pointer(ck))
	v := C.mg_int(ck)
	if v < 0 {
		return 0, false
	}
	return int(v), true
}

func (mobileGestalt) String(key string) (string, bool) {
	ck := C.CString(key)
	defer C.free(unsafe.Pointer(ck))
	cs := C.mg_string(ck)
	if cs == nil {
		return "", false
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs), true
}
