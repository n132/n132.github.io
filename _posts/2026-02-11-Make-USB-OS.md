---
title: "Make Bootable USB for Custom Kernel"
date: 2026-02-11 15:25:33
tags: 
layout: post
---
<!---more-->

# Make Bootable USB for Custom Kernel

## Environment

- Host: Dell XPS (2023)

## Prerequisites
- A compiled kernel source tree (with `bzImage` built)
- `grub-mkrescue` installed (`sudo apt install grub-pc-bin grub-efi-amd64-bin xorriso mtools`)
- A USB drive

## 1. Kernel Config Requirements

Ensure these are set in `.config` before building (required for UEFI framebuffer output on XPS):

```
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_DRM=y
CONFIG_DRM_SIMPLEDRM=y
CONFIG_SYSFB=y
CONFIG_SYSFB_SIMPLEFB=y
CONFIG_FB=y
CONFIG_FRAMEBUFFER_CONSOLE=y
CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=y
```

Then resolve dependencies and build:
```bash
make olddefconfig
make -j$(nproc)
```

## 2. Create ISO Directory Structure

e.g., can be found on https://zenodo.org/records/15022146

```bash
mkdir -p iso/boot/grub
cp arch/x86/boot/bzImage iso/boot/bzImage
cp /path/to/initramfs.cpio.gz iso/boot/initramfs.cpio.gz
```

## 3. Create grub.cfg

Write `iso/boot/grub/grub.cfg`:

```
menuentry 'expos' --class os {
    insmod gzio
    insmod part_gpt
    insmod part_msdos
    linux  /boot/bzImage nokaslr no5lvl
    initrd /boot/initramfs.cpio.gz
}
```

## 4. Build ISO

```bash
grub-mkrescue -o expos.iso iso/
```

## 5. Flash to USB

Before run this you have to figure out which device is your USB.

DON'T FLUSH TO YOUR OTHER DEV!

```bash
sudo umount /dev/<sd?>*
sudo dd if=expos.iso of=/dev/<sd?> bs=4M status=progress
sync
sudo eject /dev/<sd?>
```

## 6. Boot on XPS

1. **F12** at boot -> **Disable Secure Boot** (Security -> Secure Boot -> Disabled)
2. **F12** at boot -> Select the USB drive
3. GRUB menu appears -> Select "expos"
