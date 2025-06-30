#!/bin/bash
# Expand the filesystem to the maximum size of the disk (LVM or non-LVM)

# Exit on any error
set -e

# Function to handle errors
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if device exists
device_exists() {
    [ -b "$1" ] || error_exit "Device $1 does not exist"
}

# Function to check if device is LVM
is_lvm_device() {
    sudo pvdisplay | grep -q "${1}"
}

# Function to get filesystem type
get_fs_type() {
    local device=$1
    local fs_type=""
    
    # Try to get filesystem type from mount info
    if fs_type=$(sudo mount | grep "${device}" | awk '{print $5}'); then
        echo "$fs_type"
        return 0
    fi
    
    # Try to get from blkid
    if fs_type=$(sudo blkid -s TYPE -o value "${device}"); then
        echo "$fs_type"
        return 0
    fi
    
    # Try to get from df
    if fs_type=$(sudo df -T | grep "${device}" | awk '{print $2}'); then
        echo "$fs_type"
        return 0
    fi
    
    return 1
}

# Check if required parameters are provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <disk_device> [mount_point]"
    echo "Example: $0 /dev/sda1 /mnt/data"
    exit 1
fi

# Validate the device parameter
device_exists "${1}"

# Declare global variable for mount point
MOUNT_POINT=${2}

check_mount() {
    echo "Checking mount status of ${1}..."
    if ! sudo mount | grep -q "${1}"; then
        error_exit "The disk ${1} is not mounted"
    fi
    MOUNT_POINT=$(sudo mount | grep "${1}" | awk '{print $3}')
    echo "✓ The disk is mounted at ${MOUNT_POINT}"
}

# Check where the disk is mounted
if [ -z "${MOUNT_POINT}" ]; then
    # No mount point provided, detect it automatically
    check_mount ${1}
else
    # Mount point provided, verify it's actually mounted
    echo "Verifying mount point ${MOUNT_POINT} for device ${1}..."
    if ! sudo mount | grep "${1}" | grep -q "${MOUNT_POINT}"; then
        error_exit "Disk ${1} is not mounted at ${MOUNT_POINT}"
    fi
    echo "✓ Using provided mount point: ${MOUNT_POINT}"
fi

# Get the partition number from the device name
PARTITION_NUM=$(echo ${1} | sed 's/.*[^0-9]//')
DISK_DEVICE=$(echo ${1} | sed 's/[0-9]*$//')

# Validate partition number extraction
if [ -z "${PARTITION_NUM}" ] || [ -z "${DISK_DEVICE}" ]; then
    error_exit "Failed to extract partition number from device name ${1}"
fi

echo "Resizing partition ${1} to use all available space..."

# Resize the partition to use all available space
if command_exists growpart; then
    echo "Using growpart to resize partition..."
    if ! sudo growpart "${DISK_DEVICE}" "${PARTITION_NUM}"; then
        error_exit "Failed to resize partition using growpart"
    fi
    echo "✓ Partition resized successfully with growpart"
else
    echo "Using parted to resize partition..."
    if ! sudo parted "${DISK_DEVICE}" resizepart "${PARTITION_NUM}" 100%; then
        error_exit "Failed to resize partition using parted"
    fi
    echo "✓ Partition resized successfully with parted"
fi

# Check if this is an LVM device
if is_lvm_device "${1}"; then
    echo "Detected LVM device - using LVM expansion process..."
    
    # Resize the physical volume
    echo "Resizing physical volume..."
    if ! sudo pvresize "${1}"; then
        error_exit "Failed to resize physical volume"
    fi
    echo "✓ Physical volume resized successfully"

    # Display PV information
    echo "Physical volume information:"
    sudo pvdisplay

    # Extend the logical volume
    echo "Extending logical volume to use all free space..."
    if ! sudo lvextend -l +100%FREE "${MOUNT_POINT}"; then
        error_exit "Failed to extend logical volume"
    fi
    echo "✓ Logical volume extended successfully"

    # Resize the filesystem
    echo "Resizing filesystem..."
    if ! sudo resize2fs "${MOUNT_POINT}"; then
        error_exit "Failed to resize filesystem"
    fi
    echo "✓ Filesystem resized successfully"
    
else
    echo "Detected non-LVM device - using direct filesystem expansion..."
    
    # Get filesystem type
    FS_TYPE=$(get_fs_type "${1}")
    if [ -z "${FS_TYPE}" ]; then
        error_exit "Could not determine filesystem type for ${1}"
    fi
    echo "Detected filesystem type: ${FS_TYPE}"
    
    # Resize filesystem based on type
    case "${FS_TYPE}" in
        ext2|ext3|ext4)
            echo "Resizing ext filesystem..."
            if ! sudo resize2fs "${1}"; then
                error_exit "Failed to resize ext filesystem"
            fi
            ;;
        xfs)
            echo "Resizing XFS filesystem..."
            if ! sudo xfs_growfs "${MOUNT_POINT}"; then
                error_exit "Failed to resize XFS filesystem"
            fi
            ;;
        btrfs)
            echo "Resizing Btrfs filesystem..."
            if ! sudo btrfs filesystem resize max "${MOUNT_POINT}"; then
                error_exit "Failed to resize Btrfs filesystem"
            fi
            ;;
        ntfs)
            echo "Resizing NTFS filesystem..."
            if command_exists ntfsresize; then
                if ! sudo ntfsresize -f "${1}"; then
                    error_exit "Failed to resize NTFS filesystem"
                fi
            else
                error_exit "ntfsresize not available for NTFS filesystem"
            fi
            ;;
        *)
            error_exit "Unsupported filesystem type: ${FS_TYPE}"
            ;;
    esac
    echo "✓ Filesystem resized successfully"
fi

echo "✓ Filesystem expansion completed successfully!"
echo "Mount point: ${MOUNT_POINT}"
echo "Device: ${1}"



