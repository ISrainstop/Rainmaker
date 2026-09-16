/*
 * csdev :: shotstream.c  --  Continuous screen capture (worker thread + latest-frame pump)
 * ==========================================================================
 * ASCII-only on purpose: modules in this project that hand-roll ABI structs
 * have been mis-tokenised by the compiler when carrying multi-byte comments.
 * ==========================================================================
 */
#include <windows.h>

#include "shotstream.h"
#include "jpeg.h"

#define SHOT_STREAM_MAX (4u * 1024u * 1024u)

static unsigned char *g_buf;
static unsigned int   g_len;
static volatile int   g_active;
static unsigned int   g_interval = 5000;
static HANDLE         g_thread;
static unsigned int   g_job = 0x70000000u;   /* 高位段, 不与 task id 冲突 */
static shot_sink_fn   g_sink;

static DWORD WINAPI shot_worker(LPVOID param)
{
    (void)param;

    while (g_active) {
        unsigned char *t = (unsigned char *)VirtualAlloc(NULL, SHOT_STREAM_MAX,
                                                         MEM_COMMIT | MEM_RESERVE,
                                                         PAGE_READWRITE);
        if (t) {
            unsigned int n = shot_jpeg(t, SHOT_STREAM_MAX);
            if (n > 0) {
                /* swap in the newest frame, drop whatever was pending */
                if (g_buf) VirtualFree(g_buf, 0, MEM_RELEASE);
                g_buf = t;
                g_len = n;
            } else {
                VirtualFree(t, 0, MEM_RELEASE);
            }
        }

        /* interruptible sleep so stop() is responsive */
        {
            unsigned int left = g_interval;
            while (left > 0 && g_active) {
                unsigned int slice = (left > 500u) ? 500u : left;
                Sleep(slice);
                left -= slice;
            }
        }
    }
    return 0;
}

int shotstream_start(unsigned int interval_ms, shot_sink_fn sink)
{
    if (g_active) return 0;
    if (!sink) return 0;

    g_interval = (interval_ms < 1000u) ? 1000u : interval_ms;
    g_sink = sink;
    g_active = 1;
    g_thread = CreateThread(NULL, 0, shot_worker, NULL, 0, NULL);
    if (!g_thread) {
        g_active = 0;
        g_sink = NULL;
        return 0;
    }
    return 1;
}

void shotstream_stop(void)
{
    g_active = 0;
    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    if (g_buf) {
        VirtualFree(g_buf, 0, MEM_RELEASE);
        g_buf = NULL;
        g_len = 0;
    }
    g_sink = NULL;
}

void shotstream_pump(void)
{
    unsigned char *b;
    unsigned int n;

    if (!g_active || !g_buf || g_len == 0 || !g_sink) return;

    /* take ownership away from the worker before handing it to the sink */
    b = g_buf;
    n = g_len;
    g_buf = NULL;
    g_len = 0;

    if (g_sink(g_job++, b, n) != 0) {
        /* sink busy or outbox full: drop this frame (newest frame wins) */
        VirtualFree(b, 0, MEM_RELEASE);
    }
}

int shotstream_active(void)
{
    return g_active ? 1 : 0;
}
