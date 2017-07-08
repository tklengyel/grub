/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2017  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  EFI shim lock verifier.
 *
 */

#include <grub/dl.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/verify.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_EFI_SHIM_LOCK_GUID \
  { 0x605dab50, 0xe046, 0x4300, \
    { 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } \
  }

struct grub_efi_shim_lock_protocol
{
  grub_efi_status_t
  (*verify) (void *buffer,
	     grub_uint32_t size);
};
typedef struct grub_efi_shim_lock_protocol grub_efi_shim_lock_protocol_t;

static grub_efi_guid_t shim_lock_guid = GRUB_EFI_SHIM_LOCK_GUID;
static grub_efi_shim_lock_protocol_t *sl;

static grub_err_t
shim_lock_init (grub_file_t io __attribute__ ((unused)), enum grub_file_type type,
	       void **context __attribute__ ((unused)), enum grub_verify_flags *flags)
{
  *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;

  if (!sl)
    return GRUB_ERR_NONE;

  switch (type & GRUB_FILE_TYPE_MASK)
    {
    case GRUB_FILE_TYPE_LINUX_KERNEL:
    case GRUB_FILE_TYPE_MULTIBOOT_KERNEL:
    case GRUB_FILE_TYPE_BSD_KERNEL:
    case GRUB_FILE_TYPE_XNU_KERNEL:
    case GRUB_FILE_TYPE_PLAN9_KERNEL:
      *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;

    default:
      return GRUB_ERR_NONE;
    }
}

static grub_err_t
shim_lock_write (void *context __attribute__ ((unused)), void *buf, grub_size_t size)
{
  if (sl->verify (buf, size) != GRUB_EFI_SUCCESS)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("bad shim signature"));

  return GRUB_ERR_NONE;
}

static void
shim_lock_close (void *context __attribute__ ((unused)))
{
}

struct grub_file_verifier shim_lock =
  {
    .name = "shim_lock",
    .init = shim_lock_init,
    .write = shim_lock_write,
    .close = shim_lock_close
  };

GRUB_MOD_INIT(shim_lock)
{
  sl = grub_efi_locate_protocol (&shim_lock_guid, 0);
  grub_verifier_register (&shim_lock);
}

GRUB_MOD_FINI(shim_lock)
{
  grub_verifier_unregister (&shim_lock);
}
