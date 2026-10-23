/**
 * @file src/remote_usb/usbip_executable.h
 * @brief Decides whether a usbip.exe path is safe to launch from a service account.
 *
 * Apollo usually runs as LocalSystem, so the program it launches must come
 * from a place only administrators can change.  Nothing here ever consults
 * PATH, the current directory or the process environment.
 */
#pragma once

#include <string>
#include <string_view>

namespace remote_usb {

struct executable_check {
  bool ok { false };
  /** Why the path was refused; fixed wording, safe to log. */
  std::string detail;
};

/**
 * The only location usbip-win2 is accepted from: <Program Files>\USBip\usbip.exe,
 * with Program Files read from the OS known-folder API (not from environment
 * variables, which a user can change for a child process).  Empty when it
 * cannot be determined.  Windows only: this module is not built elsewhere.
 */
std::string known_usbip_executable_path();

/**
 * Accepts @p path only when all of these hold (Windows):
 *  - an absolute drive-letter path with no %, quotes, "..", ":" streams or "/" separators;
 *  - the file name equals @p expected_file_name (case-insensitive);
 *  - the file exists and its final path (GetFinalPathNameByHandle) equals the
 *    given path, so no link, junction, subst drive or 8.3 alias is involved;
 *  - neither the file nor any directory above it up to the drive root can be
 *    modified by a principal other than SYSTEM, Administrators or TrustedInstaller.
 * Any failure to find out counts as a refusal.
 */
executable_check check_trusted_executable(const std::string &path, std::string_view expected_file_name);

/**
 * One link of the chain above, exposed so tests can exercise it on files they
 * create.  True when the object's owner, or any allow entry that applies to
 * the object itself, belongs to a principal other than SYSTEM, Administrators
 * or TrustedInstaller and grants a right that changes the object (or, for a
 * directory, its children).  A missing or unreadable security descriptor and a
 * null DACL count as writable.  @p is_drive_root narrows the rights to the ones
 * that can replace existing children, because every user may add folders to a
 * drive root.
 */
bool object_writable_by_untrusted(const std::wstring &path, bool is_directory, bool is_drive_root);

}  // namespace remote_usb
