/*
 * DMI Decode
 *
 *   Copyright (C) 2000-2002 Alan Cox <alan@redhat.com>
 *   Copyright (C) 2002-2020 Jean Delvare <jdelvare@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 *
 * Unless specified otherwise, all references are aimed at the "System
 * Management BIOS Reference Specification, Version 3.2.0" document,
 * available from http://www.dmtf.org/standards/smbios.
 *
 * Note to contributors:
 * Please reference every value you add or modify, especially if the
 * information does not come from the above mentioned specification.
 *
 * Additional references:
 *  - Intel AP-485 revision 36
 *    "Intel Processor Identification and the CPUID Instruction"
 *    http://www.intel.com/support/processors/sb/cs-009861.htm
 *  - DMTF Common Information Model
 *    CIM Schema version 2.19.1
 *    http://www.dmtf.org/standards/cim/
 *  - IPMI 2.0 revision 1.0
 *    "Intelligent Platform Management Interface Specification"
 *    http://developer.intel.com/design/servers/ipmi/spec.htm
 *  - AMD publication #25481 revision 2.28
 *    "CPUID Specification"
 *    http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/25481.pdf
 *  - BIOS Integrity Services Application Programming Interface version 1.0
 *    http://www.intel.com/design/archives/wfm/downloads/bisspec.htm
 *  - DMTF DSP0239 version 1.1.0
 *    "Management Component Transport Protocol (MCTP) IDs and Codes"
 *    http://www.dmtf.org/standards/pmci
 *  - "TPM Main, Part 2 TPM Structures"
 *    Specification version 1.2, level 2, revision 116
 *    https://trustedcomputinggroup.org/tpm-main-specification/
 *  - "PC Client Platform TPM Profile (PTP) Specification"
 *    Family "2.0", Level 00, Revision 00.43, January 26, 2015
 *    https://trustedcomputinggroup.org/pc-client-platform-tpm-profile-ptp-specification/
 *  - "RedFish Host Interface Specification" (DMTF DSP0270)
 *    https://www.dmtf.org/sites/default/files/DSP0270_1.0.1.pdf
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef __FreeBSD__
#include <errno.h>
#include <kenv.h>
#endif

#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"
#include "dmidecode.h"
#include "dmiopt.h"
#include "dmioem.h"
#include "dmioutput.h"

#define out_of_spec u"<OUT OF SPEC>"
static const char *bad_index = u"<BAD INDEX>";

#define SUPPORTED_SMBIOS_VER 0x030300

#define FLAG_NO_FILE_OFFSET     (1 << 0)
#define FLAG_STOP_AT_EOT        (1 << 1)

#define SYS_FIRMWARE_DIR "/sys/firmware/dmi/tables"
#define SYS_ENTRY_FILE SYS_FIRMWARE_DIR "/smbios_entry_point"
#define SYS_TABLE_FILE SYS_FIRMWARE_DIR "/DMI"

/*
 * Type-independant Stuff
 */

/* Returns 1 if the buffer contains only printable ASCII characters */
int is_printable(const u8 *data, int len)
{
	int i;

	for (i = 0; i < len; i++)
		if (data[i] < 32 || data[i] >= 127)
			return 0;

	return 1;
}

/* Replace non-ASCII characters with dots */
static void ascii_filter(char *bp, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (bp[i] < 32 || bp[i] >= 127)
			bp[i] = '.';
}

static char *_dmi_string(const struct dmi_header *dm, u8 s, int filter)
{
	char *bp = (char *)dm->data;

	bp += dm->length;
	while (s > 1 && *bp)
	{
		bp += strlen(bp);
		bp++;
		s--;
	}

	if (!*bp)
		return NULL;

	if (filter)
		ascii_filter(bp, strlen(bp));

	return bp;
}

const char *dmi_string(const struct dmi_header *dm, u8 s)
{
	char *bp;

	if (s == 0)
		return u"Not Specified";

	bp = _dmi_string(dm, s, 1);
	if (bp == NULL)
		return bad_index;

	return bp;
}

static const char *dmi_smbios_structure_type(u8 code)
{
	static const char *type[] = {
		u"BIOS", /* 0 */
		u"System",
		u"Base Board",
		u"Chassis",
		u"Processor",
		u"Memory Controller",
		u"Memory Module",
		u"Cache",
		u"Port Connector",
		u"System Slots",
		u"On Board Devices",
		u"OEM Strings",
		u"System Configuration Options",
		u"BIOS Language",
		u"Group Associations",
		u"System Event Log",
		u"Physical Memory Array",
		u"Memory Device",
		u"32-bit Memory Error",
		u"Memory Array Mapped Address",
		u"Memory Device Mapped Address",
		u"Built-in Pointing Device",
		u"Portable Battery",
		u"System Reset",
		u"Hardware Security",
		u"System Power Controls",
		u"Voltage Probe",
		u"Cooling Device",
		u"Temperature Probe",
		u"Electrical Current Probe",
		u"Out-of-band Remote Access",
		u"Boot Integrity Services",
		u"System Boot",
		u"64-bit Memory Error",
		u"Management Device",
		u"Management Device Component",
		u"Management Device Threshold Data",
		u"Memory Channel",
		u"IPMI Device",
		u"Power Supply",
		u"Additional Information",
		u"Onboard Device",
		u"Management Controller Host Interface",
		u"TPM Device", /* 43 */
	};

	if (code >= 128)
		return u"OEM-specific";
	if (code <= 43)
		return type[code];
	return out_of_spec;
}

static int dmi_bcd_range(u8 value, u8 low, u8 high)
{
	if (value > 0x99 || (value & 0x0F) > 0x09)
		return 0;
	if (value < low || value > high)
		return 0;
	return 1;
}

static void dmi_dump(const struct dmi_header *h)
{
	static char raw_data[48];
	int row, i;
	unsigned int off;
	char *s;

	pr_list_start(u"Header and Data", NULL);
	for (row = 0; row < ((h->length - 1) >> 4) + 1; row++)
	{
		off = 0;
		for (i = 0; i < 16 && i < h->length - (row << 4); i++)
			off += sprintf(raw_data + off, i ? u" %02X" : u"%02X",
			       (h->data)[(row << 4) + i]);
		pr_list_item(raw_data);
	}
	pr_list_end();

	if ((h->data)[h->length] || (h->data)[h->length + 1])
	{
		pr_list_start(u"Strings", NULL);
		i = 1;
		while ((s = _dmi_string(h, i++, !(opt.flags & FLAG_DUMP))))
		{
			if (opt.flags & FLAG_DUMP)
			{
				int j, l = strlen(s) + 1;

				for (row = 0; row < ((l - 1) >> 4) + 1; row++)
				{
					off = 0;
					for (j = 0; j < 16 && j < l - (row << 4); j++)
						off += sprintf(raw_data + off,
						       j ? u" %02X" : u"%02X",
						       (unsigned char)s[(row << 4) + j]);
					pr_list_item(raw_data);
				}
				/* String isn't filtered yet so do it now */
				ascii_filter(s, l - 1);
			}
			pr_list_item(u"%s", s);
		}
		pr_list_end();
	}
}

/* shift is 0 if the value is in bytes, 1 if it is in kilobytes */
void dmi_print_memory_size(const char *attr, u64 code, int shift)
{
	unsigned long capacity;
	u16 split[7];
	static const char *unit[8] = {
		u"bytes", u"kB", u"MB", u"GB", u"TB", u"PB", u"EB", u"ZB"
	};
	int i;

	/*
	 * We split the overall size in powers of thousand: EB, PB, TB, GB,
	 * MB, kB and B. In practice, it is expected that only one or two
	 * (consecutive) of these will be non-zero.
	 */
	split[0] = code.l & 0x3FFUL;
	split[1] = (code.l >> 10) & 0x3FFUL;
	split[2] = (code.l >> 20) & 0x3FFUL;
	split[3] = ((code.h << 2) & 0x3FCUL) | (code.l >> 30);
	split[4] = (code.h >> 8) & 0x3FFUL;
	split[5] = (code.h >> 18) & 0x3FFUL;
	split[6] = code.h >> 28;

	/*
	 * Now we find the highest unit with a non-zero value. If the following
	 * is also non-zero, we use that as our base. If the following is zero,
	 * we simply display the highest unit.
	 */
	for (i = 6; i > 0; i--)
	{
		if (split[i])
			break;
	}
	if (i > 0 && split[i - 1])
	{
		i--;
		capacity = split[i] + (split[i + 1] << 10);
	}
	else
		capacity = split[i];

	pr_attr(attr, u"%lu %s", capacity, unit[i + shift]);
}

/*
 * 7.1 BIOS Information (Type 0)
 */

static void dmi_bios_runtime_size(u32 code)
{
	const char *format;

	if (code & 0x000003FF)
	{
		format = u"%u bytes";
	}
	else
	{
		format = u"%u kB";
		code >>= 10;
	}

	pr_attr(u"Runtime Size", format, code);
}

static void dmi_bios_rom_size(u8 code1, u16 code2)
{
	static const char *unit[4] = {
		u"MB", u"GB", out_of_spec, out_of_spec
	};

	if (code1 != 0xFF)
	{
		u64 s = { .l = (code1 + 1) << 6 };
		dmi_print_memory_size(u"ROM Size", s, 1);
	}
	else
		pr_attr(u"ROM Size", u"%u %s", code2 & 0x3FFF, unit[code2 >> 14]);
}

static void dmi_bios_characteristics(u64 code)
{
	/* 7.1.1 */
	static const char *characteristics[] = {
		u"BIOS characteristics not supported", /* 3 */
		u"ISA is supported",
		u"MCA is supported",
		u"EISA is supported",
		u"PCI is supported",
		u"PC Card (PCMCIA) is supported",
		u"PNP is supported",
		u"APM is supported",
		u"BIOS is upgradeable",
		u"BIOS shadowing is allowed",
		u"VLB is supported",
		u"ESCD support is available",
		u"Boot from CD is supported",
		u"Selectable boot is supported",
		u"BIOS ROM is socketed",
		u"Boot from PC Card (PCMCIA) is supported",
		u"EDD is supported",
		u"Japanese floppy for NEC 9800 1.2 MB is supported (int 13h)",
		u"Japanese floppy for Toshiba 1.2 MB is supported (int 13h)",
		u"5.25\"/360 kB floppy services are supported (int 13h)",
		u"5.25\"/1.2 MB floppy services are supported (int 13h)",
		u"3.5\"/720 kB floppy services are supported (int 13h)",
		u"3.5\"/2.88 MB floppy services are supported (int 13h)",
		u"Print screen service is supported (int 5h)",
		u"8042 keyboard services are supported (int 9h)",
		u"Serial services are supported (int 14h)",
		u"Printer services are supported (int 17h)",
		u"CGA/mono video services are supported (int 10h)",
		u"NEC PC-98" /* 31 */
	};
	int i;

	/*
	 * This isn't very clear what this bit is supposed to mean
	 */
	if (code.l & (1 << 3))
	{
		pr_list_item(u"%s", characteristics[0]);
		return;
	}

	for (i = 4; i <= 31; i++)
		if (code.l & (1 << i))
			pr_list_item(u"%s", characteristics[i - 3]);
}

static void dmi_bios_characteristics_x1(u8 code)
{
	/* 7.1.2.1 */
	static const char *characteristics[] = {
		u"ACPI is supported", /* 0 */
		u"USB legacy is supported",
		u"AGP is supported",
		u"I2O boot is supported",
		u"LS-120 boot is supported",
		u"ATAPI Zip drive boot is supported",
		u"IEEE 1394 boot is supported",
		u"Smart battery is supported" /* 7 */
	};
	int i;

	for (i = 0; i <= 7; i++)
		if (code & (1 << i))
			pr_list_item(u"%s", characteristics[i]);
}

static void dmi_bios_characteristics_x2(u8 code)
{
	/* 37.1.2.2 */
	static const char *characteristics[] = {
		u"BIOS boot specification is supported", /* 0 */
		u"Function key-initiated network boot is supported",
		u"Targeted content distribution is supported",
		u"UEFI is supported",
		u"System is a virtual machine" /* 4 */
	};
	int i;

	for (i = 0; i <= 4; i++)
		if (code & (1 << i))
			pr_list_item(u"%s", characteristics[i]);
}

/*
 * 7.2 System Information (Type 1)
 */

static void dmi_system_uuid(void (*print_cb)(const char *name, const char *format, ...),
			    const char *attr, const u8 *p, u16 ver)
{
	int only0xFF = 1, only0x00 = 1;
	int i;

	for (i = 0; i < 16 && (only0x00 || only0xFF); i++)
	{
		if (p[i] != 0x00) only0x00 = 0;
		if (p[i] != 0xFF) only0xFF = 0;
	}

	if (only0xFF)
	{
		if (print_cb)
			print_cb(attr, u"Not Present");
		else
			printf(u"Not Present\n");
		return;
	}
	if (only0x00)
	{
		if (print_cb)
			print_cb(attr, u"Not Settable");
		else
			printf(u"Not Settable\n");
		return;
	}

	/*
	 * As of version 2.6 of the SMBIOS specification, the first 3
	 * fields of the UUID are supposed to be encoded on little-endian.
	 * The specification says that this is the defacto standard,
	 * however I've seen systems following RFC 4122 instead and use
	 * network byte order, so I am reluctant to apply the byte-swapping
	 * for older versions.
	 */
	if (ver >= 0x0206)
	{
		if (print_cb)
			print_cb(attr,
				u"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
				p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		else
			printf(u"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
				p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
				p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
	}
	else
	{
		if (print_cb)
			print_cb(attr,
				u"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
				p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		else
			printf(u"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
				p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
	}
}

static const char *dmi_system_wake_up_type(u8 code)
{
	/* 7.2.2 */
	static const char *type[] = {
		u"Reserved", /* 0x00 */
		u"Other",
		u"Unknown",
		u"APM Timer",
		u"Modem Ring",
		u"LAN Remote",
		u"Power Switch",
		u"PCI PME#",
		u"AC Power Restored" /* 0x08 */
	};

	if (code <= 0x08)
		return type[code];
	return out_of_spec;
}

/*
 * 7.3 Base Board Information (Type 2)
 */

static void dmi_base_board_features(u8 code)
{
	/* 7.3.1 */
	static const char *features[] = {
		u"Board is a hosting board", /* 0 */
		u"Board requires at least one daughter board",
		u"Board is removable",
		u"Board is replaceable",
		u"Board is hot swappable" /* 4 */
	};

	if ((code & 0x1F) == 0)
		pr_list_start(u"Features", u"%s", u"None");
	else
	{
		int i;

		pr_list_start(u"Features", NULL);
		for (i = 0; i <= 4; i++)
			if (code & (1 << i))
				pr_list_item(u"%s", features[i]);
	}
	pr_list_end();
}

static const char *dmi_base_board_type(u8 code)
{
	/* 7.3.2 */
	static const char *type[] = {
		u"Unknown", /* 0x01 */
		u"Other",
		u"Server Blade",
		u"Connectivity Switch",
		u"System Management Module",
		u"Processor Module",
		u"I/O Module",
		u"Memory Module",
		u"Daughter Board",
		u"Motherboard",
		u"Processor+Memory Module",
		u"Processor+I/O Module",
		u"Interconnect Board" /* 0x0D */
	};

	if (code >= 0x01 && code <= 0x0D)
		return type[code - 0x01];
	return out_of_spec;
}

static void dmi_base_board_handles(u8 count, const u8 *p)
{
	int i;

	pr_list_start(u"Contained Object Handles", u"%u", count);
	for (i = 0; i < count; i++)
		pr_list_item(u"0x%04X", WORD(p + sizeof(u16) * i));
	pr_list_end();
}

/*
 * 7.4 Chassis Information (Type 3)
 */

static const char *dmi_chassis_type(u8 code)
{
	/* 7.4.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Desktop",
		u"Low Profile Desktop",
		u"Pizza Box",
		u"Mini Tower",
		u"Tower",
		u"Portable",
		u"Laptop",
		u"Notebook",
		u"Hand Held",
		u"Docking Station",
		u"All In One",
		u"Sub Notebook",
		u"Space-saving",
		u"Lunch Box",
		u"Main Server Chassis", /* CIM_Chassis.ChassisPackageType says u"Main System Chassis" */
		u"Expansion Chassis",
		u"Sub Chassis",
		u"Bus Expansion Chassis",
		u"Peripheral Chassis",
		u"RAID Chassis",
		u"Rack Mount Chassis",
		u"Sealed-case PC",
		u"Multi-system",
		u"CompactPCI",
		u"AdvancedTCA",
		u"Blade",
		u"Blade Enclosing",
		u"Tablet",
		u"Convertible",
		u"Detachable",
		u"IoT Gateway",
		u"Embedded PC",
		u"Mini PC",
		u"Stick PC" /* 0x24 */
	};

	code &= 0x7F; /* bits 6:0 are chassis type, 7th bit is the lock bit */

	if (code >= 0x01 && code <= 0x24)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_chassis_lock(u8 code)
{
	static const char *lock[] = {
		u"Not Present", /* 0x00 */
		u"Present" /* 0x01 */
	};

	return lock[code];
}

static const char *dmi_chassis_state(u8 code)
{
	/* 7.4.2 */
	static const char *state[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Safe",
		u"Warning",
		u"Critical",
		u"Non-recoverable" /* 0x06 */
	};

	if (code >= 0x01 && code <= 0x06)
		return state[code - 0x01];
	return out_of_spec;
}

static const char *dmi_chassis_security_status(u8 code)
{
	/* 7.4.3 */
	static const char *status[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"None",
		u"External Interface Locked Out",
		u"External Interface Enabled" /* 0x05 */
	};

	if (code >= 0x01 && code <= 0x05)
		return status[code - 0x01];
	return out_of_spec;
}

static void dmi_chassis_height(u8 code)
{
	if (code == 0x00)
		pr_attr(u"Height", u"Unspecified");
	else
		pr_attr(u"Height", u"%u U", code);
}

static void dmi_chassis_power_cords(u8 code)
{
	if (code == 0x00)
		pr_attr(u"Number Of Power Cords", u"Unspecified");
	else
		pr_attr(u"Number Of Power Cords", u"%u", code);
}

static void dmi_chassis_elements(u8 count, u8 len, const u8 *p)
{
	int i;

	pr_list_start(u"Contained Elements", u"%u", count);
	for (i = 0; i < count; i++)
	{
		if (len >= 0x03)
		{
			const char *type;

			type = (p[i * len] & 0x80) ?
				dmi_smbios_structure_type(p[i * len] & 0x7F) :
				dmi_base_board_type(p[i * len] & 0x7F);

			if (p[1 + i * len] == p[2 + i * len])
				pr_list_item(u"%s (%u)", type, p[1 + i * len]);
			else
				pr_list_item(u"%s (%u-%u)", type, p[1 + i * len],
					     p[2 + i * len]);
		}
	}
	pr_list_end();
}

/*
 * 7.5 Processor Information (Type 4)
 */

static const char *dmi_processor_type(u8 code)
{
	/* 7.5.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Central Processor",
		u"Math Processor",
		u"DSP Processor",
		u"Video Processor" /* 0x06 */
	};

	if (code >= 0x01 && code <= 0x06)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_processor_family(const struct dmi_header *h, u16 ver)
{
	const u8 *data = h->data;
	unsigned int i, low, high;
	u16 code;

	/* 7.5.2 */
	static struct {
		int value;
		const char *name;
	} family2[] = {
		{ 0x01, u"Other" },
		{ 0x02, u"Unknown" },
		{ 0x03, u"8086" },
		{ 0x04, u"80286" },
		{ 0x05, u"80386" },
		{ 0x06, u"80486" },
		{ 0x07, u"8087" },
		{ 0x08, u"80287" },
		{ 0x09, u"80387" },
		{ 0x0A, u"80487" },
		{ 0x0B, u"Pentium" },
		{ 0x0C, u"Pentium Pro" },
		{ 0x0D, u"Pentium II" },
		{ 0x0E, u"Pentium MMX" },
		{ 0x0F, u"Celeron" },
		{ 0x10, u"Pentium II Xeon" },
		{ 0x11, u"Pentium III" },
		{ 0x12, u"M1" },
		{ 0x13, u"M2" },
		{ 0x14, u"Celeron M" },
		{ 0x15, u"Pentium 4 HT" },

		{ 0x18, u"Duron" },
		{ 0x19, u"K5" },
		{ 0x1A, u"K6" },
		{ 0x1B, u"K6-2" },
		{ 0x1C, u"K6-3" },
		{ 0x1D, u"Athlon" },
		{ 0x1E, u"AMD29000" },
		{ 0x1F, u"K6-2+" },
		{ 0x20, u"Power PC" },
		{ 0x21, u"Power PC 601" },
		{ 0x22, u"Power PC 603" },
		{ 0x23, u"Power PC 603+" },
		{ 0x24, u"Power PC 604" },
		{ 0x25, u"Power PC 620" },
		{ 0x26, u"Power PC x704" },
		{ 0x27, u"Power PC 750" },
		{ 0x28, u"Core Duo" },
		{ 0x29, u"Core Duo Mobile" },
		{ 0x2A, u"Core Solo Mobile" },
		{ 0x2B, u"Atom" },
		{ 0x2C, u"Core M" },
		{ 0x2D, u"Core m3" },
		{ 0x2E, u"Core m5" },
		{ 0x2F, u"Core m7" },
		{ 0x30, u"Alpha" },
		{ 0x31, u"Alpha 21064" },
		{ 0x32, u"Alpha 21066" },
		{ 0x33, u"Alpha 21164" },
		{ 0x34, u"Alpha 21164PC" },
		{ 0x35, u"Alpha 21164a" },
		{ 0x36, u"Alpha 21264" },
		{ 0x37, u"Alpha 21364" },
		{ 0x38, u"Turion II Ultra Dual-Core Mobile M" },
		{ 0x39, u"Turion II Dual-Core Mobile M" },
		{ 0x3A, u"Athlon II Dual-Core M" },
		{ 0x3B, u"Opteron 6100" },
		{ 0x3C, u"Opteron 4100" },
		{ 0x3D, u"Opteron 6200" },
		{ 0x3E, u"Opteron 4200" },
		{ 0x3F, u"FX" },
		{ 0x40, u"MIPS" },
		{ 0x41, u"MIPS R4000" },
		{ 0x42, u"MIPS R4200" },
		{ 0x43, u"MIPS R4400" },
		{ 0x44, u"MIPS R4600" },
		{ 0x45, u"MIPS R10000" },
		{ 0x46, u"C-Series" },
		{ 0x47, u"E-Series" },
		{ 0x48, u"A-Series" },
		{ 0x49, u"G-Series" },
		{ 0x4A, u"Z-Series" },
		{ 0x4B, u"R-Series" },
		{ 0x4C, u"Opteron 4300" },
		{ 0x4D, u"Opteron 6300" },
		{ 0x4E, u"Opteron 3300" },
		{ 0x4F, u"FirePro" },
		{ 0x50, u"SPARC" },
		{ 0x51, u"SuperSPARC" },
		{ 0x52, u"MicroSPARC II" },
		{ 0x53, u"MicroSPARC IIep" },
		{ 0x54, u"UltraSPARC" },
		{ 0x55, u"UltraSPARC II" },
		{ 0x56, u"UltraSPARC IIi" },
		{ 0x57, u"UltraSPARC III" },
		{ 0x58, u"UltraSPARC IIIi" },

		{ 0x60, u"68040" },
		{ 0x61, u"68xxx" },
		{ 0x62, u"68000" },
		{ 0x63, u"68010" },
		{ 0x64, u"68020" },
		{ 0x65, u"68030" },
		{ 0x66, u"Athlon X4" },
		{ 0x67, u"Opteron X1000" },
		{ 0x68, u"Opteron X2000" },
		{ 0x69, u"Opteron A-Series" },
		{ 0x6A, u"Opteron X3000" },
		{ 0x6B, u"Zen" },

		{ 0x70, u"Hobbit" },

		{ 0x78, u"Crusoe TM5000" },
		{ 0x79, u"Crusoe TM3000" },
		{ 0x7A, u"Efficeon TM8000" },

		{ 0x80, u"Weitek" },

		{ 0x82, u"Itanium" },
		{ 0x83, u"Athlon 64" },
		{ 0x84, u"Opteron" },
		{ 0x85, u"Sempron" },
		{ 0x86, u"Turion 64" },
		{ 0x87, u"Dual-Core Opteron" },
		{ 0x88, u"Athlon 64 X2" },
		{ 0x89, u"Turion 64 X2" },
		{ 0x8A, u"Quad-Core Opteron" },
		{ 0x8B, u"Third-Generation Opteron" },
		{ 0x8C, u"Phenom FX" },
		{ 0x8D, u"Phenom X4" },
		{ 0x8E, u"Phenom X2" },
		{ 0x8F, u"Athlon X2" },
		{ 0x90, u"PA-RISC" },
		{ 0x91, u"PA-RISC 8500" },
		{ 0x92, u"PA-RISC 8000" },
		{ 0x93, u"PA-RISC 7300LC" },
		{ 0x94, u"PA-RISC 7200" },
		{ 0x95, u"PA-RISC 7100LC" },
		{ 0x96, u"PA-RISC 7100" },

		{ 0xA0, u"V30" },
		{ 0xA1, u"Quad-Core Xeon 3200" },
		{ 0xA2, u"Dual-Core Xeon 3000" },
		{ 0xA3, u"Quad-Core Xeon 5300" },
		{ 0xA4, u"Dual-Core Xeon 5100" },
		{ 0xA5, u"Dual-Core Xeon 5000" },
		{ 0xA6, u"Dual-Core Xeon LV" },
		{ 0xA7, u"Dual-Core Xeon ULV" },
		{ 0xA8, u"Dual-Core Xeon 7100" },
		{ 0xA9, u"Quad-Core Xeon 5400" },
		{ 0xAA, u"Quad-Core Xeon" },
		{ 0xAB, u"Dual-Core Xeon 5200" },
		{ 0xAC, u"Dual-Core Xeon 7200" },
		{ 0xAD, u"Quad-Core Xeon 7300" },
		{ 0xAE, u"Quad-Core Xeon 7400" },
		{ 0xAF, u"Multi-Core Xeon 7400" },
		{ 0xB0, u"Pentium III Xeon" },
		{ 0xB1, u"Pentium III Speedstep" },
		{ 0xB2, u"Pentium 4" },
		{ 0xB3, u"Xeon" },
		{ 0xB4, u"AS400" },
		{ 0xB5, u"Xeon MP" },
		{ 0xB6, u"Athlon XP" },
		{ 0xB7, u"Athlon MP" },
		{ 0xB8, u"Itanium 2" },
		{ 0xB9, u"Pentium M" },
		{ 0xBA, u"Celeron D" },
		{ 0xBB, u"Pentium D" },
		{ 0xBC, u"Pentium EE" },
		{ 0xBD, u"Core Solo" },
		/* 0xBE handled as a special case */
		{ 0xBF, u"Core 2 Duo" },
		{ 0xC0, u"Core 2 Solo" },
		{ 0xC1, u"Core 2 Extreme" },
		{ 0xC2, u"Core 2 Quad" },
		{ 0xC3, u"Core 2 Extreme Mobile" },
		{ 0xC4, u"Core 2 Duo Mobile" },
		{ 0xC5, u"Core 2 Solo Mobile" },
		{ 0xC6, u"Core i7" },
		{ 0xC7, u"Dual-Core Celeron" },
		{ 0xC8, u"IBM390" },
		{ 0xC9, u"G4" },
		{ 0xCA, u"G5" },
		{ 0xCB, u"ESA/390 G6" },
		{ 0xCC, u"z/Architecture" },
		{ 0xCD, u"Core i5" },
		{ 0xCE, u"Core i3" },
		{ 0xCF, u"Core i9" },

		{ 0xD2, u"C7-M" },
		{ 0xD3, u"C7-D" },
		{ 0xD4, u"C7" },
		{ 0xD5, u"Eden" },
		{ 0xD6, u"Multi-Core Xeon" },
		{ 0xD7, u"Dual-Core Xeon 3xxx" },
		{ 0xD8, u"Quad-Core Xeon 3xxx" },
		{ 0xD9, u"Nano" },
		{ 0xDA, u"Dual-Core Xeon 5xxx" },
		{ 0xDB, u"Quad-Core Xeon 5xxx" },

		{ 0xDD, u"Dual-Core Xeon 7xxx" },
		{ 0xDE, u"Quad-Core Xeon 7xxx" },
		{ 0xDF, u"Multi-Core Xeon 7xxx" },
		{ 0xE0, u"Multi-Core Xeon 3400" },

		{ 0xE4, u"Opteron 3000" },
		{ 0xE5, u"Sempron II" },
		{ 0xE6, u"Embedded Opteron Quad-Core" },
		{ 0xE7, u"Phenom Triple-Core" },
		{ 0xE8, u"Turion Ultra Dual-Core Mobile" },
		{ 0xE9, u"Turion Dual-Core Mobile" },
		{ 0xEA, u"Athlon Dual-Core" },
		{ 0xEB, u"Sempron SI" },
		{ 0xEC, u"Phenom II" },
		{ 0xED, u"Athlon II" },
		{ 0xEE, u"Six-Core Opteron" },
		{ 0xEF, u"Sempron M" },

		{ 0xFA, u"i860" },
		{ 0xFB, u"i960" },

		{ 0x100, u"ARMv7" },
		{ 0x101, u"ARMv8" },
		{ 0x104, u"SH-3" },
		{ 0x105, u"SH-4" },
		{ 0x118, u"ARM" },
		{ 0x119, u"StrongARM" },
		{ 0x12C, u"6x86" },
		{ 0x12D, u"MediaGX" },
		{ 0x12E, u"MII" },
		{ 0x140, u"WinChip" },
		{ 0x15E, u"DSP" },
		{ 0x1F4, u"Video Processor" },

		{ 0x200, u"RV32" },
		{ 0x201, u"RV64" },
		{ 0x202, u"RV128" },
	};
	/*
	 * Note to developers: when adding entries to this list, check if
	 * function dmi_processor_id below needs updating too.
	 */

	/* Special case for ambiguous value 0x30 (SMBIOS 2.0 only) */
	if (ver == 0x0200 && data[0x06] == 0x30 && h->length >= 0x08)
	{
		const char *manufacturer = dmi_string(h, data[0x07]);

		if (strstr(manufacturer, u"Intel") != NULL
		 || strncasecmp(manufacturer, u"Intel", 5) == 0)
			return u"Pentium Pro";
	}

	code = (data[0x06] == 0xFE && h->length >= 0x2A) ?
		WORD(data + 0x28) : data[0x06];

	/* Special case for ambiguous value 0xBE */
	if (code == 0xBE)
	{
		if (h->length >= 0x08)
		{
			const char *manufacturer = dmi_string(h, data[0x07]);

			/* Best bet based on manufacturer string */
			if (strstr(manufacturer, u"Intel") != NULL
			 || strncasecmp(manufacturer, u"Intel", 5) == 0)
				return u"Core 2";
			if (strstr(manufacturer, u"AMD") != NULL
			 || strncasecmp(manufacturer, u"AMD", 3) == 0)
				return u"K7";
		}

		return u"Core 2 or K7";
	}

	/* Perform a binary search */
	low = 0;
	high = ARRAY_SIZE(family2) - 1;

	while (1)
	{
		i = (low + high) / 2;
		if (family2[i].value == code)
			return family2[i].name;
		if (low == high) /* Not found */
			return out_of_spec;

		if (code < family2[i].value)
			high = i;
		else
			low = i + 1;
	}
}

static void dmi_processor_id(const struct dmi_header *h)
{
	/* Intel AP-485 revision 36, table 2-4 */
	static const char *flags[32] = {
		u"FPU (Floating-point unit on-chip)", /* 0 */
		u"VME (Virtual mode extension)",
		u"DE (Debugging extension)",
		u"PSE (Page size extension)",
		u"TSC (Time stamp counter)",
		u"MSR (Model specific registers)",
		u"PAE (Physical address extension)",
		u"MCE (Machine check exception)",
		u"CX8 (CMPXCHG8 instruction supported)",
		u"APIC (On-chip APIC hardware supported)",
		NULL, /* 10 */
		u"SEP (Fast system call)",
		u"MTRR (Memory type range registers)",
		u"PGE (Page global enable)",
		u"MCA (Machine check architecture)",
		u"CMOV (Conditional move instruction supported)",
		u"PAT (Page attribute table)",
		u"PSE-36 (36-bit page size extension)",
		u"PSN (Processor serial number present and enabled)",
		u"CLFSH (CLFLUSH instruction supported)",
		NULL, /* 20 */
		u"DS (Debug store)",
		u"ACPI (ACPI supported)",
		u"MMX (MMX technology supported)",
		u"FXSR (FXSAVE and FXSTOR instructions supported)",
		u"SSE (Streaming SIMD extensions)",
		u"SSE2 (Streaming SIMD extensions 2)",
		u"SS (Self-snoop)",
		u"HTT (Multi-threading)",
		u"TM (Thermal monitor supported)",
		NULL, /* 30 */
		u"PBE (Pending break enabled)" /* 31 */
	};
	const u8 *data = h->data;
	const u8 *p = data + 0x08;
	u32 eax, edx;
	int sig = 0;
	u16 type;

	type = (data[0x06] == 0xFE && h->length >= 0x2A) ?
		WORD(data + 0x28) : data[0x06];

	/*
	 * This might help learn about new processors supporting the
	 * CPUID instruction or another form of identification.
	 */
	pr_attr(u"ID", u"%02X %02X %02X %02X %02X %02X %02X %02X",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

	if (type == 0x05) /* 80386 */
	{
		u16 dx = WORD(p);
		/*
		 * 80386 have a different signature.
		 */
		pr_attr(u"Signature",
			u"Type %u, Family %u, Major Stepping %u, Minor Stepping %u",
			dx >> 12, (dx >> 8) & 0xF,
			(dx >> 4) & 0xF, dx & 0xF);
		return;
	}
	if (type == 0x06) /* 80486 */
	{
		u16 dx = WORD(p);
		/*
		 * Not all 80486 CPU support the CPUID instruction, we have to find
		 * whether the one we have here does or not. Note that this trick
		 * works only because we know that 80486 must be little-endian.
		 */
		if ((dx & 0x0F00) == 0x0400
		 && ((dx & 0x00F0) == 0x0040 || (dx & 0x00F0) >= 0x0070)
		 && ((dx & 0x000F) >= 0x0003))
			sig = 1;
		else
		{
			pr_attr(u"Signature",
				u"Type %u, Family %u, Model %u, Stepping %u",
				(dx >> 12) & 0x3, (dx >> 8) & 0xF,
				(dx >> 4) & 0xF, dx & 0xF);
			return;
		}
	}
	else if ((type >= 0x100 && type <= 0x101) /* ARM */
	      || (type >= 0x118 && type <= 0x119)) /* ARM */
	{
		u32 midr = DWORD(p);
		/*
		 * The format of this field was not defined for ARM processors
		 * before version 3.1.0 of the SMBIOS specification, so we
		 * silently skip it if it reads all zeroes.
		 */
		if (midr == 0)
			return;
		pr_attr(u"Signature",
			u"Implementor 0x%02x, Variant 0x%x, Architecture %u, Part 0x%03x, Revision %u",
			midr >> 24, (midr >> 20) & 0xF,
			(midr >> 16) & 0xF, (midr >> 4) & 0xFFF, midr & 0xF);
		return;
	}
	else if ((type >= 0x0B && type <= 0x15) /* Intel, Cyrix */
	      || (type >= 0x28 && type <= 0x2F) /* Intel */
	      || (type >= 0xA1 && type <= 0xB3) /* Intel */
	      || type == 0xB5 /* Intel */
	      || (type >= 0xB9 && type <= 0xC7) /* Intel */
	      || (type >= 0xCD && type <= 0xCF) /* Intel */
	      || (type >= 0xD2 && type <= 0xDB) /* VIA, Intel */
	      || (type >= 0xDD && type <= 0xE0)) /* Intel */
		sig = 1;
	else if ((type >= 0x18 && type <= 0x1D) /* AMD */
	      || type == 0x1F /* AMD */
	      || (type >= 0x38 && type <= 0x3F) /* AMD */
	      || (type >= 0x46 && type <= 0x4F) /* AMD */
	      || (type >= 0x66 && type <= 0x6B) /* AMD */
	      || (type >= 0x83 && type <= 0x8F) /* AMD */
	      || (type >= 0xB6 && type <= 0xB7) /* AMD */
	      || (type >= 0xE4 && type <= 0xEF)) /* AMD */
		sig = 2;
	else if (type == 0x01 || type == 0x02)
	{
		const char *version = dmi_string(h, data[0x10]);
		/*
		 * Some X86-class CPU have family u"Other" or u"Unknown". In this case,
		 * we use the version string to determine if they are known to
		 * support the CPUID instruction.
		 */
		if (strncmp(version, u"Pentium III MMX", 15) == 0
		 || strncmp(version, u"Intel(R) Core(TM)2", 18) == 0
		 || strncmp(version, u"Intel(R) Pentium(R)", 19) == 0
		 || strcmp(version, u"Genuine Intel(R) CPU U1400") == 0)
			sig = 1;
		else if (strncmp(version, u"AMD Athlon(TM)", 14) == 0
		      || strncmp(version, u"AMD Opteron(tm)", 15) == 0
		      || strncmp(version, u"Dual-Core AMD Opteron(tm)", 25) == 0)
			sig = 2;
		else
			return;
	}
	else /* neither X86 nor ARM */
		return;

	/*
	 * Extra flags are now returned in the ECX register when one calls
	 * the CPUID instruction. Their meaning is explained in table 3-5, but
	 * DMI doesn't support this yet.
	 */
	eax = DWORD(p);
	edx = DWORD(p + 4);
	switch (sig)
	{
		case 1: /* Intel */
			pr_attr(u"Signature",
				u"Type %u, Family %u, Model %u, Stepping %u",
				(eax >> 12) & 0x3,
				((eax >> 20) & 0xFF) + ((eax >> 8) & 0x0F),
				((eax >> 12) & 0xF0) + ((eax >> 4) & 0x0F),
				eax & 0xF);
			break;
		case 2: /* AMD, publication #25481 revision 2.28 */
			pr_attr(u"Signature", u"Family %u, Model %u, Stepping %u",
				((eax >> 8) & 0xF) + (((eax >> 8) & 0xF) == 0xF ? (eax >> 20) & 0xFF : 0),
				((eax >> 4) & 0xF) | (((eax >> 8) & 0xF) == 0xF ? (eax >> 12) & 0xF0 : 0),
				eax & 0xF);
			break;
	}

	edx = DWORD(p + 4);
	if ((edx & 0xBFEFFBFF) == 0)
		pr_list_start(u"Flags", u"None");
	else
	{
		int i;

		pr_list_start(u"Flags", NULL);
		for (i = 0; i <= 31; i++)
			if (flags[i] != NULL && edx & (1 << i))
				pr_list_item(u"%s", flags[i]);
	}
	pr_list_end();
}

static void dmi_processor_voltage(const char *attr, u8 code)
{
	/* 7.5.4 */
	static const char *voltage[] = {
		u"5.0 V", /* 0 */
		u"3.3 V",
		u"2.9 V" /* 2 */
	};
	int i;

	if (code & 0x80)
		pr_attr(attr, u"%.1f V", (float)(code & 0x7f) / 10);
	else if ((code & 0x07) == 0x00)
		pr_attr(attr, u"Unknown");
	else
	{
		char voltage_str[18];
		int off = 0;

		for (i = 0; i <= 2; i++)
		{
			if (code & (1 << i))
			{
				/* Insert space if not the first value */
				off += sprintf(voltage_str + off,
					       off ? u" %s" :u"%s",
					       voltage[i]);
			}
		}
		if (off)
			pr_attr(attr, voltage_str);
	}
}

static void dmi_processor_frequency(const char *attr, const u8 *p)
{
	u16 code = WORD(p);

	if (code)
	{
		if (attr)
			pr_attr(attr, u"%u MHz", code);
		else
			printf(u"%u MHz\n", code);
	}
	else
	{
		if (attr)
			pr_attr(attr, u"Unknown");
		else
			printf(u"Unknown\n");
	}
}

/* code is assumed to be a 3-bit value */
static const char *dmi_processor_status(u8 code)
{
	static const char *status[] = {
		u"Unknown", /* 0x00 */
		u"Enabled",
		u"Disabled By User",
		u"Disabled By BIOS",
		u"Idle", /* 0x04 */
		out_of_spec,
		out_of_spec,
		u"Other" /* 0x07 */
	};

	return status[code];
}

static const char *dmi_processor_upgrade(u8 code)
{
	/* 7.5.5 */
	static const char *upgrade[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Daughter Board",
		u"ZIF Socket",
		u"Replaceable Piggy Back",
		u"None",
		u"LIF Socket",
		u"Slot 1",
		u"Slot 2",
		u"370-pin Socket",
		u"Slot A",
		u"Slot M",
		u"Socket 423",
		u"Socket A (Socket 462)",
		u"Socket 478",
		u"Socket 754",
		u"Socket 940",
		u"Socket 939",
		u"Socket mPGA604",
		u"Socket LGA771",
		u"Socket LGA775",
		u"Socket S1",
		u"Socket AM2",
		u"Socket F (1207)",
		u"Socket LGA1366",
		u"Socket G34",
		u"Socket AM3",
		u"Socket C32",
		u"Socket LGA1156",
		u"Socket LGA1567",
		u"Socket PGA988A",
		u"Socket BGA1288",
		u"Socket rPGA988B",
		u"Socket BGA1023",
		u"Socket BGA1224",
		u"Socket BGA1155",
		u"Socket LGA1356",
		u"Socket LGA2011",
		u"Socket FS1",
		u"Socket FS2",
		u"Socket FM1",
		u"Socket FM2",
		u"Socket LGA2011-3",
		u"Socket LGA1356-3",
		u"Socket LGA1150",
		u"Socket BGA1168",
		u"Socket BGA1234",
		u"Socket BGA1364",
		u"Socket AM4",
		u"Socket LGA1151",
		u"Socket BGA1356",
		u"Socket BGA1440",
		u"Socket BGA1515",
		u"Socket LGA3647-1",
		u"Socket SP3",
		u"Socket SP3r2",
		u"Socket LGA2066",
		u"Socket BGA1392",
		u"Socket BGA1510",
		u"Socket BGA1528",
		u"Socket LGA4189",
		u"Socket LGA1200" /* 0x3E */
	};

	if (code >= 0x01 && code <= 0x3E)
		return upgrade[code - 0x01];
	return out_of_spec;
}

static void dmi_processor_cache(const char *attr, u16 code, const char *level,
				u16 ver)
{
	if (code == 0xFFFF)
	{
		if (ver >= 0x0203)
			pr_attr(attr, u"Not Provided");
		else
			pr_attr(attr, u"No %s Cache", level);
	}
	else
		pr_attr(attr, u"0x%04X", code);
}

static void dmi_processor_characteristics(const char *attr, u16 code)
{
	/* 7.5.9 */
	static const char *characteristics[] = {
		u"64-bit capable", /* 2 */
		u"Multi-Core",
		u"Hardware Thread",
		u"Execute Protection",
		u"Enhanced Virtualization",
		u"Power/Performance Control",
		u"128-bit Capable",
		u"Arm64 SoC ID" /* 9 */
	};

	if ((code & 0x00FC) == 0)
		pr_attr(attr, u"None");
	else
	{
		int i;

		pr_list_start(attr, NULL);
		for (i = 2; i <= 9; i++)
			if (code & (1 << i))
				pr_list_item(u"%s", characteristics[i - 2]);
		pr_list_end();
	}
}

/*
 * 7.6 Memory Controller Information (Type 5)
 */

static const char *dmi_memory_controller_ed_method(u8 code)
{
	/* 7.6.1 */
	static const char *method[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"None",
		u"8-bit Parity",
		u"32-bit ECC",
		u"64-bit ECC",
		u"128-bit ECC",
		u"CRC" /* 0x08 */
	};

	if (code >= 0x01 && code <= 0x08)
		return method[code - 0x01];
	return out_of_spec;
}

static void dmi_memory_controller_ec_capabilities(const char *attr, u8 code)
{
	/* 7.6.2 */
	static const char *capabilities[] = {
		u"Other", /* 0 */
		u"Unknown",
		u"None",
		u"Single-bit Error Correcting",
		u"Double-bit Error Correcting",
		u"Error Scrubbing" /* 5 */
	};

	if ((code & 0x3F) == 0)
		pr_attr(attr, u"None");
	else
	{
		int i;

		pr_list_start(attr, NULL);
		for (i = 0; i <= 5; i++)
			if (code & (1 << i))
				pr_list_item(u"%s", capabilities[i]);
		pr_list_end();
	}
}

static const char *dmi_memory_controller_interleave(u8 code)
{
	/* 7.6.3 */
	static const char *interleave[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"One-way Interleave",
		u"Two-way Interleave",
		u"Four-way Interleave",
		u"Eight-way Interleave",
		u"Sixteen-way Interleave" /* 0x07 */
	};

	if (code >= 0x01 && code <= 0x07)
		return interleave[code - 0x01];
	return out_of_spec;
}

static void dmi_memory_controller_speeds(const char *attr, u16 code)
{
	/* 7.6.4 */
	const char *speeds[] = {
		u"Other", /* 0 */
		u"Unknown",
		u"70 ns",
		u"60 ns",
		u"50 ns" /* 4 */
	};

	if ((code & 0x001F) == 0)
		pr_attr(attr, u"None");
	else
	{
		int i;

		pr_list_start(attr, NULL);
		for (i = 0; i <= 4; i++)
			if (code & (1 << i))
				pr_list_item(u"%s", speeds[i]);
		pr_list_end();
	}
}

static void dmi_memory_controller_slots(u8 count, const u8 *p)
{
	int i;

	pr_list_start(u"Associated Memory Slots", u"%u", count);
	for (i = 0; i < count; i++)
		pr_list_item(u"0x%04X", WORD(p + sizeof(u16) * i));
	pr_list_end();
}

/*
 * 7.7 Memory Module Information (Type 6)
 */

static void dmi_memory_module_types(const char *attr, u16 code, int flat)
{
	/* 7.7.1 */
	static const char *types[] = {
		u"Other", /* 0 */
		u"Unknown",
		u"Standard",
		u"FPM",
		u"EDO",
		u"Parity",
		u"ECC",
		u"SIMM",
		u"DIMM",
		u"Burst EDO",
		u"SDRAM" /* 10 */
	};

	if ((code & 0x07FF) == 0)
		pr_attr(attr, u"None");
	else if (flat)
	{
		char type_str[68];
		int i, off = 0;

		for (i = 0; i <= 10; i++)
		{
			if (code & (1 << i))
			{
				/* Insert space if not the first value */
				off += sprintf(type_str + off,
					       off ? u" %s" :u"%s",
					       types[i]);
			}
		}
		if (off)
			pr_attr(attr, type_str);
	}
	else
	{
		int i;

		pr_list_start(attr, NULL);
		for (i = 0; i <= 10; i++)
			if (code & (1 << i))
				pr_list_item(u"%s", types[i]);
		pr_list_end();
	}
}

static void dmi_memory_module_connections(u8 code)
{
	if (code == 0xFF)
		pr_attr(u"Bank Connections", u"None");
	else if ((code & 0xF0) == 0xF0)
		pr_attr(u"Bank Connections", u"%u", code & 0x0F);
	else if ((code & 0x0F) == 0x0F)
		pr_attr(u"Bank Connections", u"%u", code >> 4);
	else
		pr_attr(u"Bank Connections", u"%u %u", code >> 4, code & 0x0F);
}

static void dmi_memory_module_speed(const char *attr, u8 code)
{
	if (code == 0)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"%u ns", code);
}

static void dmi_memory_module_size(const char *attr, u8 code)
{
	const char *connection;

	/* 7.7.2 */
	if (code & 0x80)
		connection = u" (Double-bank Connection)";
	else
		connection = u" (Single-bank Connection)";

	switch (code & 0x7F)
	{
		case 0x7D:
			pr_attr(attr, u"Not Determinable%s", connection);
			break;
		case 0x7E:
			pr_attr(attr, u"Disabled%s", connection);
			break;
		case 0x7F:
			pr_attr(attr, u"Not Installed");
			return;
		default:
			pr_attr(attr, u"%u MB%s", 1 << (code & 0x7F),
				connection);
	}
}

static void dmi_memory_module_error(u8 code)
{
	static const char *status[] = {
		u"OK", /* 0x00 */
		u"Uncorrectable Errors",
		u"Correctable Errors",
		u"Correctable and Uncorrectable Errors" /* 0x03 */
	};

	if (code & (1 << 2))
		pr_attr(u"Error Status", u"See Event Log");
	else
		pr_attr(u"Error Status", u"%s", status[code & 0x03]);
}

/*
 * 7.8 Cache Information (Type 7)
 */

static const char *dmi_cache_mode(u8 code)
{
	static const char *mode[] = {
		u"Write Through", /* 0x00 */
		u"Write Back",
		u"Varies With Memory Address",
		u"Unknown" /* 0x03 */
	};

	return mode[code];
}

/* code is assumed to be a 2-bit value */
static const char *dmi_cache_location(u8 code)
{
	static const char *location[4] = {
		u"Internal", /* 0x00 */
		u"External",
		out_of_spec, /* 0x02 */
		u"Unknown" /* 0x03 */
	};

	return location[code];
}

static void dmi_cache_size_2(const char *attr, u32 code)
{
	u64 size;

	if (code & 0x80000000)
	{
		code &= 0x7FFFFFFFLU;
		size.l = code << 6;
		size.h = code >> 26;
	}
	else
	{
		size.l = code;
		size.h = 0;
	}

	/* Use a more convenient unit for large cache size */
	dmi_print_memory_size(attr, size, 1);
}

static void dmi_cache_size(const char *attr, u16 code)
{
	dmi_cache_size_2(attr,
			 (((u32)code & 0x8000LU) << 16) | (code & 0x7FFFLU));
}

static void dmi_cache_types(const char *attr, u16 code, int flat)
{
	/* 7.8.2 */
	static const char *types[] = {
		u"Other", /* 0 */
		u"Unknown",
		u"Non-burst",
		u"Burst",
		u"Pipeline Burst",
		u"Synchronous",
		u"Asynchronous" /* 6 */
	};

	if ((code & 0x007F) == 0)
		pr_attr(attr, u"None");
	else if (flat)
	{
		char type_str[70];
		int i, off = 0;

		for (i = 0; i <= 6; i++)
		{
			if (code & (1 << i))
			{
				/* Insert space if not the first value */
				off += sprintf(type_str + off,
					       off ? u" %s" :u"%s",
					       types[i]);
			}
		}
		if (off)
			pr_attr(attr, type_str);
	}
	else
	{
		int i;

		pr_list_start(attr, NULL);
		for (i = 0; i <= 6; i++)
			if (code & (1 << i))
				pr_list_item(u"%s", types[i]);
		pr_list_end();
	}
}

static const char *dmi_cache_ec_type(u8 code)
{
	/* 7.8.3 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"None",
		u"Parity",
		u"Single-bit ECC",
		u"Multi-bit ECC" /* 0x06 */
	};

	if (code >= 0x01 && code <= 0x06)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_cache_type(u8 code)
{
	/* 7.8.4 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Instruction",
		u"Data",
		u"Unified" /* 0x05 */
	};

	if (code >= 0x01 && code <= 0x05)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_cache_associativity(u8 code)
{
	/* 7.8.5 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Direct Mapped",
		u"2-way Set-associative",
		u"4-way Set-associative",
		u"Fully Associative",
		u"8-way Set-associative",
		u"16-way Set-associative",
		u"12-way Set-associative",
		u"24-way Set-associative",
		u"32-way Set-associative",
		u"48-way Set-associative",
		u"64-way Set-associative",
		u"20-way Set-associative" /* 0x0E */
	};

	if (code >= 0x01 && code <= 0x0E)
		return type[code - 0x01];
	return out_of_spec;
}

/*
 * 7.9 Port Connector Information (Type 8)
 */

static const char *dmi_port_connector_type(u8 code)
{
	/* 7.9.2 */
	static const char *type[] = {
		u"None", /* 0x00 */
		u"Centronics",
		u"Mini Centronics",
		u"Proprietary",
		u"DB-25 male",
		u"DB-25 female",
		u"DB-15 male",
		u"DB-15 female",
		u"DB-9 male",
		u"DB-9 female",
		u"RJ-11",
		u"RJ-45",
		u"50 Pin MiniSCSI",
		u"Mini DIN",
		u"Micro DIN",
		u"PS/2",
		u"Infrared",
		u"HP-HIL",
		u"Access Bus (USB)",
		u"SSA SCSI",
		u"Circular DIN-8 male",
		u"Circular DIN-8 female",
		u"On Board IDE",
		u"On Board Floppy",
		u"9 Pin Dual Inline (pin 10 cut)",
		u"25 Pin Dual Inline (pin 26 cut)",
		u"50 Pin Dual Inline",
		u"68 Pin Dual Inline",
		u"On Board Sound Input From CD-ROM",
		u"Mini Centronics Type-14",
		u"Mini Centronics Type-26",
		u"Mini Jack (headphones)",
		u"BNC",
		u"IEEE 1394",
		u"SAS/SATA Plug Receptacle",
		u"USB Type-C Receptacle" /* 0x23 */
	};
	static const char *type_0xA0[] = {
		u"PC-98", /* 0xA0 */
		u"PC-98 Hireso",
		u"PC-H98",
		u"PC-98 Note",
		u"PC-98 Full" /* 0xA4 */
	};

	if (code <= 0x23)
		return type[code];
	if (code >= 0xA0 && code <= 0xA4)
		return type_0xA0[code - 0xA0];
	if (code == 0xFF)
		return u"Other";
	return out_of_spec;
}

static const char *dmi_port_type(u8 code)
{
	/* 7.9.3 */
	static const char *type[] = {
		u"None", /* 0x00 */
		u"Parallel Port XT/AT Compatible",
		u"Parallel Port PS/2",
		u"Parallel Port ECP",
		u"Parallel Port EPP",
		u"Parallel Port ECP/EPP",
		u"Serial Port XT/AT Compatible",
		u"Serial Port 16450 Compatible",
		u"Serial Port 16550 Compatible",
		u"Serial Port 16550A Compatible",
		u"SCSI Port",
		u"MIDI Port",
		u"Joystick Port",
		u"Keyboard Port",
		u"Mouse Port",
		u"SSA SCSI",
		u"USB",
		u"Firewire (IEEE P1394)",
		u"PCMCIA Type I",
		u"PCMCIA Type II",
		u"PCMCIA Type III",
		u"Cardbus",
		u"Access Bus Port",
		u"SCSI II",
		u"SCSI Wide",
		u"PC-98",
		u"PC-98 Hireso",
		u"PC-H98",
		u"Video Port",
		u"Audio Port",
		u"Modem Port",
		u"Network Port",
		u"SATA",
		u"SAS" /* 0x21 */
	};
	static const char *type_0xA0[] = {
		u"8251 Compatible", /* 0xA0 */
		u"8251 FIFO Compatible" /* 0xA1 */
	};

	if (code <= 0x21)
		return type[code];
	if (code >= 0xA0 && code <= 0xA1)
		return type_0xA0[code - 0xA0];
	if (code == 0xFF)
		return u"Other";
	return out_of_spec;
}

/*
 * 7.10 System Slots (Type 9)
 */

static const char *dmi_slot_type(u8 code)
{
	/* 7.10.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"ISA",
		u"MCA",
		u"EISA",
		u"PCI",
		u"PC Card (PCMCIA)",
		u"VLB",
		u"Proprietary",
		u"Processor Card",
		u"Proprietary Memory Card",
		u"I/O Riser Card",
		u"NuBus",
		u"PCI-66",
		u"AGP",
		u"AGP 2x",
		u"AGP 4x",
		u"PCI-X",
		u"AGP 8x",
		u"M.2 Socket 1-DP",
		u"M.2 Socket 1-SD",
		u"M.2 Socket 2",
		u"M.2 Socket 3",
		u"MXM Type I",
		u"MXM Type II",
		u"MXM Type III",
		u"MXM Type III-HE",
		u"MXM Type IV",
		u"MXM 3.0 Type A",
		u"MXM 3.0 Type B",
		u"PCI Express 2 SFF-8639 (U.2)",
		u"PCI Express 3 SFF-8639 (U.2)",
		u"PCI Express Mini 52-pin with bottom-side keep-outs",
		u"PCI Express Mini 52-pin without bottom-side keep-outs",
		u"PCI Express Mini 76-pin",
		u"PCI Express 4 SFF-8639 (U.2)",
		u"PCI Express 5 SFF-8639 (U.2)",
		u"OCP NIC 3.0 Small Form Factor (SFF)",
		u"OCP NIC 3.0 Large Form Factor (LFF)",
		u"OCP NIC Prior to 3.0" /* 0x28 */
	};
	static const char *type_0x30[] = {
		u"CXL FLexbus 1.0" /* 0x30 */
	};
	static const char *type_0xA0[] = {
		u"PC-98/C20", /* 0xA0 */
		u"PC-98/C24",
		u"PC-98/E",
		u"PC-98/Local Bus",
		u"PC-98/Card",
		u"PCI Express",
		u"PCI Express x1",
		u"PCI Express x2",
		u"PCI Express x4",
		u"PCI Express x8",
		u"PCI Express x16",
		u"PCI Express 2",
		u"PCI Express 2 x1",
		u"PCI Express 2 x2",
		u"PCI Express 2 x4",
		u"PCI Express 2 x8",
		u"PCI Express 2 x16",
		u"PCI Express 3",
		u"PCI Express 3 x1",
		u"PCI Express 3 x2",
		u"PCI Express 3 x4",
		u"PCI Express 3 x8",
		u"PCI Express 3 x16",
		out_of_spec, /* 0xB7 */
		u"PCI Express 4",
		u"PCI Express 4 x1",
		u"PCI Express 4 x2",
		u"PCI Express 4 x4",
		u"PCI Express 4 x8",
		u"PCI Express 4 x16",
		u"PCI Express 5",
		u"PCI Express 5 x1",
		u"PCI Express 5 x2",
		u"PCI Express 5 x4",
		u"PCI Express 5 x8",
		u"PCI Express 5 x16",
		u"PCI Express 6+",
		u"EDSFF E1",
		u"EDSFF E3" /* 0xC6 */
	};
	/*
	 * Note to developers: when adding entries to these lists, check if
	 * function dmi_slot_id below needs updating too.
	 */

	if (code >= 0x01 && code <= 0x28)
		return type[code - 0x01];
	if (code == 0x30)
		return type_0x30[code - 0x30];
	if (code >= 0xA0 && code <= 0xC6)
		return type_0xA0[code - 0xA0];
	return out_of_spec;
}

static const char *dmi_slot_bus_width(u8 code)
{
	/* 7.10.2 */
	static const char *width[] = {
		u"", /* 0x01, u"Other" */
		u"", /* u"Unknown" */
		u"8-bit ",
		u"16-bit ",
		u"32-bit ",
		u"64-bit ",
		u"128-bit ",
		u"x1 ",
		u"x2 ",
		u"x4 ",
		u"x8 ",
		u"x12 ",
		u"x16 ",
		u"x32 " /* 0x0E */
	};

	if (code >= 0x01 && code <= 0x0E)
		return width[code - 0x01];
	return out_of_spec;
}

static const char *dmi_slot_current_usage(u8 code)
{
	/* 7.10.3 */
	static const char *usage[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Available",
		u"In Use",
		u"Unavailable" /* 0x05 */
	};

	if (code >= 0x01 && code <= 0x05)
		return usage[code - 0x01];
	return out_of_spec;
}

static const char *dmi_slot_length(u8 code)
{
	/* 7.10.4 */
	static const char *length[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Short",
		u"Long",
		u"2.5\" drive form factor",
		u"3.5\" drive form factor" /* 0x06 */
	};

	if (code >= 0x01 && code <= 0x06)
		return length[code - 0x01];
	return out_of_spec;
}

static void dmi_slot_id(u8 code1, u8 code2, u8 type)
{
	/* 7.10.5 */
	switch (type)
	{
		case 0x04: /* MCA */
			pr_attr(u"ID", u"%u", code1);
			break;
		case 0x05: /* EISA */
			pr_attr(u"ID", u"%u", code1);
			break;
		case 0x06: /* PCI */
		case 0x0E: /* PCI */
		case 0x0F: /* AGP */
		case 0x10: /* AGP */
		case 0x11: /* AGP */
		case 0x12: /* PCI-X */
		case 0x13: /* AGP */
		case 0x1F: /* PCI Express 2 */
		case 0x20: /* PCI Express 3 */
		case 0x21: /* PCI Express Mini */
		case 0x22: /* PCI Express Mini */
		case 0x23: /* PCI Express Mini */
		case 0xA5: /* PCI Express */
		case 0xA6: /* PCI Express */
		case 0xA7: /* PCI Express */
		case 0xA8: /* PCI Express */
		case 0xA9: /* PCI Express */
		case 0xAA: /* PCI Express */
		case 0xAB: /* PCI Express 2 */
		case 0xAC: /* PCI Express 2 */
		case 0xAD: /* PCI Express 2 */
		case 0xAE: /* PCI Express 2 */
		case 0xAF: /* PCI Express 2 */
		case 0xB0: /* PCI Express 2 */
		case 0xB1: /* PCI Express 3 */
		case 0xB2: /* PCI Express 3 */
		case 0xB3: /* PCI Express 3 */
		case 0xB4: /* PCI Express 3 */
		case 0xB5: /* PCI Express 3 */
		case 0xB6: /* PCI Express 3 */
		case 0xB8: /* PCI Express 4 */
		case 0xB9: /* PCI Express 4 */
		case 0xBA: /* PCI Express 4 */
		case 0xBB: /* PCI Express 4 */
		case 0xBC: /* PCI Express 4 */
		case 0xBD: /* PCI Express 4 */
			pr_attr(u"ID", u"%u", code1);
			break;
		case 0x07: /* PCMCIA */
			pr_attr(u"ID", u"Adapter %u, Socket %u", code1, code2);
			break;
	}
}

static void dmi_slot_characteristics(const char *attr, u8 code1, u8 code2)
{
	/* 7.10.6 */
	static const char *characteristics1[] = {
		u"5.0 V is provided", /* 1 */
		u"3.3 V is provided",
		u"Opening is shared",
		u"PC Card-16 is supported",
		u"Cardbus is supported",
		u"Zoom Video is supported",
		u"Modem ring resume is supported" /* 7 */
	};
	/* 7.10.7 */
	static const char *characteristics2[] = {
		u"PME signal is supported", /* 0 */
		u"Hot-plug devices are supported",
		u"SMBus signal is supported",
		u"PCIe slot bifurcation is supported",
		u"Async/surprise removal is supported",
		u"Flexbus slot, CXL 1.0 capable",
		u"Flexbus slot, CXL 2.0 capable" /* 6 */
	};

	if (code1 & (1 << 0))
		pr_attr(attr, u"Unknown");
	else if ((code1 & 0xFE) == 0 && (code2 & 0x07) == 0)
		pr_attr(attr, u"None");
	else
	{
		int i;

		pr_list_start(attr, NULL);
		for (i = 1; i <= 7; i++)
			if (code1 & (1 << i))
				pr_list_item(u"%s", characteristics1[i - 1]);
		for (i = 0; i <= 6; i++)
			if (code2 & (1 << i))
				pr_list_item(u"%s", characteristics2[i]);
		pr_list_end();
	}
}

static void dmi_slot_segment_bus_func(u16 code1, u8 code2, u8 code3)
{
	/* 7.10.8 */
	if (!(code1 == 0xFFFF && code2 == 0xFF && code3 == 0xFF))
		pr_attr(u"Bus Address", u"%04x:%02x:%02x.%x",
			code1, code2, code3 >> 3, code3 & 0x7);
}

static void dmi_slot_peers(u8 n, const u8 *data)
{
	char attr[16];
	int i;

	for (i = 1; i <= n; i++, data += 5)
	{
		sprintf(attr, u"Peer Device %hhu", (u8)i);
		pr_attr(attr, u"%04x:%02x:%02x.%x (Width %u)",
			WORD(data), data[2], data[3] >> 3, data[3] & 0x07,
			data[4]);
	}
}

/*
 * 7.11 On Board Devices Information (Type 10)
 */

static const char *dmi_on_board_devices_type(u8 code)
{
	/* 7.11.1 and 7.42.2 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Video",
		u"SCSI Controller",
		u"Ethernet",
		u"Token Ring",
		u"Sound",
		u"PATA Controller",
		u"SATA Controller",
		u"SAS Controller" /* 0x0A */
	};

	if (code >= 0x01 && code <= 0x0A)
		return type[code - 0x01];
	return out_of_spec;
}

static void dmi_on_board_devices(const struct dmi_header *h)
{
	u8 *p = h->data + 4;
	u8 count = (h->length - 0x04) / 2;
	int i;

	for (i = 0; i < count; i++)
	{
		if (count == 1)
			pr_handle_name(u"On Board Device Information");
		else
			pr_handle_name(u"On Board Device %d Information",
				       i + 1);
		pr_attr(u"Type", u"%s",
			dmi_on_board_devices_type(p[2 * i] & 0x7F));
		pr_attr(u"Status", u"%s",
			p[2 * i] & 0x80 ? u"Enabled" : u"Disabled");
		pr_attr(u"Description", u"%s", dmi_string(h, p[2 * i + 1]));
	}
}

/*
 * 7.12 OEM Strings (Type 11)
 */

static void dmi_oem_strings(const struct dmi_header *h)
{
	char attr[11];
	u8 *p = h->data + 4;
	u8 count = p[0x00];
	int i;

	for (i = 1; i <= count; i++)
	{
		sprintf(attr, u"String %hhu", (u8)i);
		pr_attr(attr, u"%s",dmi_string(h, i));
	}
}

/*
 * 7.13 System Configuration Options (Type 12)
 */

static void dmi_system_configuration_options(const struct dmi_header *h)
{
	char attr[11];
	u8 *p = h->data + 4;
	u8 count = p[0x00];
	int i;

	for (i = 1; i <= count; i++)
	{
		sprintf(attr, u"Option %hhu", (u8)i);
		pr_attr(attr, u"%s",dmi_string(h, i));
	}
}

/*
 * 7.14 BIOS Language Information (Type 13)
 */

static void dmi_bios_languages(const struct dmi_header *h)
{
	u8 *p = h->data + 4;
	u8 count = p[0x00];
	int i;

	for (i = 1; i <= count; i++)
		pr_list_item(u"%s", dmi_string(h, i));
}

static const char *dmi_bios_language_format(u8 code)
{
	if (code & 0x01)
		return u"Abbreviated";
	else
		return u"Long";
}

/*
 * 7.15 Group Associations (Type 14)
 */

static void dmi_group_associations_items(u8 count, const u8 *p)
{
	int i;

	for (i = 0; i < count; i++)
	{
		pr_list_item(u"0x%04X (%s)",
			WORD(p + 3 * i + 1),
			dmi_smbios_structure_type(p[3 * i]));
	}
}

/*
 * 7.16 System Event Log (Type 15)
 */

static const char *dmi_event_log_method(u8 code)
{
	static const char *method[] = {
		u"Indexed I/O, one 8-bit index port, one 8-bit data port", /* 0x00 */
		u"Indexed I/O, two 8-bit index ports, one 8-bit data port",
		u"Indexed I/O, one 16-bit index port, one 8-bit data port",
		u"Memory-mapped physical 32-bit address",
		u"General-purpose non-volatile data functions" /* 0x04 */
	};

	if (code <= 0x04)
		return method[code];
	if (code >= 0x80)
		return u"OEM-specific";
	return out_of_spec;
}

static void dmi_event_log_status(u8 code)
{
	static const char *valid[] = {
		u"Invalid", /* 0 */
		u"Valid" /* 1 */
	};
	static const char *full[] = {
		u"Not Full", /* 0 */
		u"Full" /* 1 */
	};

	pr_attr(u"Status", u"%s, %s",
		valid[(code >> 0) & 1], full[(code >> 1) & 1]);
}

static void dmi_event_log_address(u8 method, const u8 *p)
{
	/* 7.16.3 */
	switch (method)
	{
		case 0x00:
		case 0x01:
		case 0x02:
			pr_attr(u"Access Address", u"Index 0x%04X, Data 0x%04X",
				WORD(p), WORD(p + 2));
			break;
		case 0x03:
			pr_attr(u"Access Address", u"0x%08X", DWORD(p));
			break;
		case 0x04:
			pr_attr(u"Access Address", u"0x%04X", WORD(p));
			break;
		default:
			pr_attr(u"Access Address", u"Unknown");
	}
}

static const char *dmi_event_log_header_type(u8 code)
{
	static const char *type[] = {
		u"No Header", /* 0x00 */
		u"Type 1" /* 0x01 */
	};

	if (code <= 0x01)
		return type[code];
	if (code >= 0x80)
		return u"OEM-specific";
	return out_of_spec;
}

static const char *dmi_event_log_descriptor_type(u8 code)
{
	/* 7.16.6.1 */
	static const char *type[] = {
		NULL, /* 0x00 */
		u"Single-bit ECC memory error",
		u"Multi-bit ECC memory error",
		u"Parity memory error",
		u"Bus timeout",
		u"I/O channel block",
		u"Software NMI",
		u"POST memory resize",
		u"POST error",
		u"PCI parity error",
		u"PCI system error",
		u"CPU failure",
		u"EISA failsafe timer timeout",
		u"Correctable memory log disabled",
		u"Logging disabled",
		NULL, /* 0x0F */
		u"System limit exceeded",
		u"Asynchronous hardware timer expired",
		u"System configuration information",
		u"Hard disk information",
		u"System reconfigured",
		u"Uncorrectable CPU-complex error",
		u"Log area reset/cleared",
		u"System boot" /* 0x17 */
	};

	if (code <= 0x17 && type[code] != NULL)
		return type[code];
	if (code >= 0x80 && code <= 0xFE)
		return u"OEM-specific";
	if (code == 0xFF)
		return u"End of log";
	return out_of_spec;
}

static const char *dmi_event_log_descriptor_format(u8 code)
{
	/* 7.16.6.2 */
	static const char *format[] = {
		u"None", /* 0x00 */
		u"Handle",
		u"Multiple-event",
		u"Multiple-event handle",
		u"POST results bitmap",
		u"System management",
		u"Multiple-event system management" /* 0x06 */
	};

	if (code <= 0x06)
		return format[code];
	if (code >= 0x80)
		return u"OEM-specific";
	return out_of_spec;
}

static void dmi_event_log_descriptors(u8 count, u8 len, const u8 *p)
{
	/* 7.16.1 */
	char attr[16];
	int i;

	for (i = 0; i < count; i++)
	{
		if (len >= 0x02)
		{
			sprintf(attr, u"Descriptor %d", i + 1);
			pr_attr(attr, u"%s",
				dmi_event_log_descriptor_type(p[i * len]));
			sprintf(attr, u"Data Format %d", i + 1);
			pr_attr(attr, u"%s",
				dmi_event_log_descriptor_format(p[i * len + 1]));
		}
	}
}

/*
 * 7.17 Physical Memory Array (Type 16)
 */

static const char *dmi_memory_array_location(u8 code)
{
	/* 7.17.1 */
	static const char *location[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"System Board Or Motherboard",
		u"ISA Add-on Card",
		u"EISA Add-on Card",
		u"PCI Add-on Card",
		u"MCA Add-on Card",
		u"PCMCIA Add-on Card",
		u"Proprietary Add-on Card",
		u"NuBus" /* 0x0A */
	};
	static const char *location_0xA0[] = {
		u"PC-98/C20 Add-on Card", /* 0xA0 */
		u"PC-98/C24 Add-on Card",
		u"PC-98/E Add-on Card",
		u"PC-98/Local Bus Add-on Card",
		u"CXL Flexbus 1.0" /* 0xA4 */
	};

	if (code >= 0x01 && code <= 0x0A)
		return location[code - 0x01];
	if (code >= 0xA0 && code <= 0xA4)
		return location_0xA0[code - 0xA0];
	return out_of_spec;
}

static const char *dmi_memory_array_use(u8 code)
{
	/* 7.17.2 */
	static const char *use[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"System Memory",
		u"Video Memory",
		u"Flash Memory",
		u"Non-volatile RAM",
		u"Cache Memory" /* 0x07 */
	};

	if (code >= 0x01 && code <= 0x07)
		return use[code - 0x01];
	return out_of_spec;
}

static const char *dmi_memory_array_ec_type(u8 code)
{
	/* 7.17.3 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"None",
		u"Parity",
		u"Single-bit ECC",
		u"Multi-bit ECC",
		u"CRC" /* 0x07 */
	};

	if (code >= 0x01 && code <= 0x07)
		return type[code - 0x01];
	return out_of_spec;
}

static void dmi_memory_array_error_handle(u16 code)
{
	if (code == 0xFFFE)
		pr_attr(u"Error Information Handle", u"Not Provided");
	else if (code == 0xFFFF)
		pr_attr(u"Error Information Handle", u"No Error");
	else
		pr_attr(u"Error Information Handle", u"0x%04X", code);
}

/*
 * 7.18 Memory Device (Type 17)
 */

static void dmi_memory_device_width(const char *attr, u16 code)
{
	/*
	 * If no memory module is present, width may be 0
	 */
	if (code == 0xFFFF || code == 0)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"%u bits", code);
}

static void dmi_memory_device_size(u16 code)
{
	if (code == 0)
		pr_attr(u"Size", u"No Module Installed");
	else if (code == 0xFFFF)
		pr_attr(u"Size", u"Unknown");
	else
	{
		u64 s = { .l = code & 0x7FFF };
		if (!(code & 0x8000))
			s.l <<= 10;
		dmi_print_memory_size(u"Size", s, 1);
	}
}

static void dmi_memory_device_extended_size(u32 code)
{
	code &= 0x7FFFFFFFUL;

	/*
	 * Use the greatest unit for which the exact value can be displayed
	 * as an integer without rounding
	 */
	if (code & 0x3FFUL)
		pr_attr(u"Size", u"%lu MB", (unsigned long)code);
	else if (code & 0xFFC00UL)
		pr_attr(u"Size", u"%lu GB", (unsigned long)code >> 10);
	else
		pr_attr(u"Size", u"%lu TB", (unsigned long)code >> 20);
}

static void dmi_memory_voltage_value(const char *attr, u16 code)
{
	if (code == 0)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, code % 100 ? u"%g V" : u"%.1f V",
			(float)code / 1000);
}

static const char *dmi_memory_device_form_factor(u8 code)
{
	/* 7.18.1 */
	static const char *form_factor[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"SIMM",
		u"SIP",
		u"Chip",
		u"DIP",
		u"ZIP",
		u"Proprietary Card",
		u"DIMM",
		u"TSOP",
		u"Row Of Chips",
		u"RIMM",
		u"SODIMM",
		u"SRIMM",
		u"FB-DIMM",
		u"Die" /* 0x10 */
	};

	if (code >= 0x01 && code <= 0x10)
		return form_factor[code - 0x01];
	return out_of_spec;
}

static void dmi_memory_device_set(u8 code)
{
	if (code == 0)
		pr_attr(u"Set", u"None");
	else if (code == 0xFF)
		pr_attr(u"Set", u"Unknown");
	else
		pr_attr(u"Set", u"%u", code);
}

static const char *dmi_memory_device_type(u8 code)
{
	/* 7.18.2 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"DRAM",
		u"EDRAM",
		u"VRAM",
		u"SRAM",
		u"RAM",
		u"ROM",
		u"Flash",
		u"EEPROM",
		u"FEPROM",
		u"EPROM",
		u"CDRAM",
		u"3DRAM",
		u"SDRAM",
		u"SGRAM",
		u"RDRAM",
		u"DDR",
		u"DDR2",
		u"DDR2 FB-DIMM",
		u"Reserved",
		u"Reserved",
		u"Reserved",
		u"DDR3",
		u"FBD2",
		u"DDR4",
		u"LPDDR",
		u"LPDDR2",
		u"LPDDR3",
		u"LPDDR4",
		u"Logical non-volatile device",
		u"HBM",
		u"HBM2",
		u"DDR5",
		u"LPDDR5" /* 0x23 */
	};

	if (code >= 0x01 && code <= 0x23)
		return type[code - 0x01];
	return out_of_spec;
}

static void dmi_memory_device_type_detail(u16 code)
{
	/* 7.18.3 */
	static const char *detail[] = {
		u"Other", /* 1 */
		u"Unknown",
		u"Fast-paged",
		u"Static Column",
		u"Pseudo-static",
		u"RAMBus",
		u"Synchronous",
		u"CMOS",
		u"EDO",
		u"Window DRAM",
		u"Cache DRAM",
		u"Non-Volatile",
		u"Registered (Buffered)",
		u"Unbuffered (Unregistered)",
		u"LRDIMM"  /* 15 */
	};
	char list[172];		/* Update length if you touch the array above */

	if ((code & 0xFFFE) == 0)
		pr_attr(u"Type Detail", u"None");
	else
	{
		int i, off = 0;

		list[0] = '\0';
		for (i = 1; i <= 15; i++)
			if (code & (1 << i))
				off += sprintf(list + off, off ? u" %s" : u"%s",
					       detail[i - 1]);
		pr_attr(u"Type Detail", list);
	}
}

static void dmi_memory_device_speed(const char *attr, u16 code1, u32 code2)
{
	if (code1 == 0xFFFF)
	{
		if (code2 == 0)
			pr_attr(attr, u"Unknown");
		else
			pr_attr(attr, u"%lu MT/s", code2);
	}
	else
	{
		if (code1 == 0)
			pr_attr(attr, u"Unknown");
		else
			pr_attr(attr, u"%u MT/s", code1);
	}
}

static void dmi_memory_technology(u8 code)
{
	/* 7.18.6 */
	static const char * const technology[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"DRAM",
		u"NVDIMM-N",
		u"NVDIMM-F",
		u"NVDIMM-P",
		u"Intel Optane DC persistent memory" /* 0x07 */
	};
	if (code >= 0x01 && code <= 0x07)
		pr_attr(u"Memory Technology", u"%s", technology[code - 0x01]);
	else
		pr_attr(u"Memory Technology", u"%s", out_of_spec);
}

static void dmi_memory_operating_mode_capability(u16 code)
{
	/* 7.18.7 */
	static const char * const mode[] = {
		u"Other", /* 1 */
		u"Unknown",
		u"Volatile memory",
		u"Byte-accessible persistent memory",
		u"Block-accessible persistent memory" /* 5 */
	};
	char list[99];		/* Update length if you touch the array above */

	if ((code & 0xFFFE) == 0)
		pr_attr(u"Memory Operating Mode Capability", u"None");
	else {
		int i, off = 0;

		list[0] = '\0';
		for (i = 1; i <= 5; i++)
			if (code & (1 << i))
				off += sprintf(list + off, off ? u" %s" : u"%s",
					       mode[i - 1]);
		pr_attr(u"Memory Operating Mode Capability", list);
	}
}

static void dmi_memory_manufacturer_id(const char *attr, u16 code)
{
	/* 7.18.8 */
	/* 7.18.10 */
	/* LSB is 7-bit Odd Parity number of continuation codes */
	if (code == 0)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"Bank %d, Hex 0x%02X",
			(code & 0x7F) + 1, code >> 8);
}

static void dmi_memory_product_id(const char *attr, u16 code)
{
	/* 7.18.9 */
	/* 7.18.11 */
	if (code == 0)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"0x%04X", code);
}

static void dmi_memory_size(const char *attr, u64 code)
{
	/* 7.18.12 */
	/* 7.18.13 */
	if (code.h == 0xFFFFFFFF && code.l == 0xFFFFFFFF)
		pr_attr(attr, u"Unknown");
	else if (code.h == 0x0 && code.l == 0x0)
		pr_attr(attr, u"None");
	else
		dmi_print_memory_size(attr, code, 0);
}

/*
 * 7.19 32-bit Memory Error Information (Type 18)
 */

static const char *dmi_memory_error_type(u8 code)
{
	/* 7.19.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"OK",
		u"Bad Read",
		u"Parity Error",
		u"Single-bit Error",
		u"Double-bit Error",
		u"Multi-bit Error",
		u"Nibble Error",
		u"Checksum Error",
		u"CRC Error",
		u"Corrected Single-bit Error",
		u"Corrected Error",
		u"Uncorrectable Error" /* 0x0E */
	};

	if (code >= 0x01 && code <= 0x0E)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_memory_error_granularity(u8 code)
{
	/* 7.19.2 */
	static const char *granularity[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Device Level",
		u"Memory Partition Level" /* 0x04 */
	};

	if (code >= 0x01 && code <= 0x04)
		return granularity[code - 0x01];
	return out_of_spec;
}

static const char *dmi_memory_error_operation(u8 code)
{
	/* 7.19.3 */
	static const char *operation[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Read",
		u"Write",
		u"Partial Write" /* 0x05 */
	};

	if (code >= 0x01 && code <= 0x05)
		return operation[code - 0x01];
	return out_of_spec;
}

static void dmi_memory_error_syndrome(u32 code)
{
	if (code == 0x00000000)
		pr_attr(u"Vendor Syndrome", u"Unknown");
	else
		pr_attr(u"Vendor Syndrome", u"0x%08X", code);
}

static void dmi_32bit_memory_error_address(const char *attr, u32 code)
{
	if (code == 0x80000000)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"0x%08X", code);
}

/*
 * 7.20 Memory Array Mapped Address (Type 19)
 */

static void dmi_mapped_address_size(u32 code)
{
	if (code == 0)
		pr_attr(u"Range Size", u"Invalid");
	else
	{
		u64 size;

		size.h = 0;
		size.l = code;
		dmi_print_memory_size(u"Range Size", size, 1);
	}
}

static void dmi_mapped_address_extended_size(u64 start, u64 end)
{
	if (start.h == end.h && start.l == end.l)
		pr_attr(u"Range Size", u"Invalid");
	else
		dmi_print_memory_size(u"Range Size", u64_range(start, end), 0);
}

/*
 * 7.21 Memory Device Mapped Address (Type 20)
 */

static void dmi_mapped_address_row_position(u8 code)
{
	if (code == 0)
		pr_attr(u"Partition Row Position", u"%s", out_of_spec);
	else if (code == 0xFF)
		pr_attr(u"Partition Row Position", u"Unknown");
	else
		pr_attr(u"Partition Row Position", u"%u", code);
}

static void dmi_mapped_address_interleave_position(u8 code)
{
	if (code != 0)
	{
		if (code == 0xFF)
			pr_attr(u"Interleave Position", u"Unknown");
		else
			pr_attr(u"Interleave Position", u"%u", code);
	}
}

static void dmi_mapped_address_interleaved_data_depth(u8 code)
{
	if (code != 0)
	{
		if (code == 0xFF)
			pr_attr(u"Interleaved Data Depth", u"Unknown");
		else
			pr_attr(u"Interleaved Data Depth", u"%u", code);
	}
}

/*
 * 7.22 Built-in Pointing Device (Type 21)
 */

static const char *dmi_pointing_device_type(u8 code)
{
	/* 7.22.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Mouse",
		u"Track Ball",
		u"Track Point",
		u"Glide Point",
		u"Touch Pad",
		u"Touch Screen",
		u"Optical Sensor" /* 0x09 */
	};

	if (code >= 0x01 && code <= 0x09)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_pointing_device_interface(u8 code)
{
	/* 7.22.2 */
	static const char *interface[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Serial",
		u"PS/2",
		u"Infrared",
		u"HIP-HIL",
		u"Bus Mouse",
		u"ADB (Apple Desktop Bus)" /* 0x08 */
	};
	static const char *interface_0xA0[] = {
		u"Bus Mouse DB-9", /* 0xA0 */
		u"Bus Mouse Micro DIN",
		u"USB" /* 0xA2 */
	};

	if (code >= 0x01 && code <= 0x08)
		return interface[code - 0x01];
	if (code >= 0xA0 && code <= 0xA2)
		return interface_0xA0[code - 0xA0];
	return out_of_spec;
}

/*
 * 7.23 Portable Battery (Type 22)
 */

static const char *dmi_battery_chemistry(u8 code)
{
	/* 7.23.1 */
	static const char *chemistry[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Lead Acid",
		u"Nickel Cadmium",
		u"Nickel Metal Hydride",
		u"Lithium Ion",
		u"Zinc Air",
		u"Lithium Polymer" /* 0x08 */
	};

	if (code >= 0x01 && code <= 0x08)
		return chemistry[code - 0x01];
	return out_of_spec;
}

static void dmi_battery_capacity(u16 code, u8 multiplier)
{
	if (code == 0)
		pr_attr(u"Design Capacity", u"Unknown");
	else
		pr_attr(u"Design Capacity", u"%u mWh", code * multiplier);
}

static void dmi_battery_voltage(u16 code)
{
	if (code == 0)
		pr_attr(u"Design Voltage", u"Unknown");
	else
		pr_attr(u"Design Voltage", u"%u mV", code);
}

static void dmi_battery_maximum_error(u8 code)
{
	if (code == 0xFF)
		pr_attr(u"Maximum Error", u"Unknown");
	else
		pr_attr(u"Maximum Error", u"%u%%", code);
}

/*
 * 7.24 System Reset (Type 23)
 */

/* code is assumed to be a 2-bit value */
static const char *dmi_system_reset_boot_option(u8 code)
{
	static const char *option[] = {
		out_of_spec, /* 0x0 */
		u"Operating System", /* 0x1 */
		u"System Utilities",
		u"Do Not Reboot" /* 0x3 */
	};

	return option[code];
}

static void dmi_system_reset_count(const char *attr, u16 code)
{
	if (code == 0xFFFF)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"%u", code);
}

static void dmi_system_reset_timer(const char *attr, u16 code)
{
	if (code == 0xFFFF)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"%u min", code);
}

/*
 * 7.25 Hardware Security (Type 24)
 */

static const char *dmi_hardware_security_status(u8 code)
{
	static const char *status[] = {
		u"Disabled", /* 0x00 */
		u"Enabled",
		u"Not Implemented",
		u"Unknown" /* 0x03 */
	};

	return status[code];
}

/*
 * 7.26 System Power Controls (Type 25)
 */

static void dmi_power_controls_power_on(const u8 *p)
{
	char time[15];
	int off = 0;

	/* 7.26.1 */
	if (dmi_bcd_range(p[0], 0x01, 0x12))
		off += sprintf(time + off, u"%02X", p[0]);
	else
		off += sprintf(time + off, u"*");
	if (dmi_bcd_range(p[1], 0x01, 0x31))
		off += sprintf(time + off, u"-%02X", p[1]);
	else
		off += sprintf(time + off, u"-*");
	if (dmi_bcd_range(p[2], 0x00, 0x23))
		off += sprintf(time + off, u" %02X", p[2]);
	else
		off += sprintf(time + off, u" *");
	if (dmi_bcd_range(p[3], 0x00, 0x59))
		off += sprintf(time + off, u":%02X", p[3]);
	else
		off += sprintf(time + off, u":*");
	if (dmi_bcd_range(p[4], 0x00, 0x59))
		off += sprintf(time + off, u":%02X", p[4]);
	else
		off += sprintf(time + off, u":*");

	pr_attr(u"Next Scheduled Power-on", time);
}

/*
 * 7.27 Voltage Probe (Type 26)
 */

static const char *dmi_voltage_probe_location(u8 code)
{
	/* 7.27.1 */
	static const char *location[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Processor",
		u"Disk",
		u"Peripheral Bay",
		u"System Management Module",
		u"Motherboard",
		u"Memory Module",
		u"Processor Module",
		u"Power Unit",
		u"Add-in Card" /* 0x0B */
	};

	if (code >= 0x01 && code <= 0x0B)
		return location[code - 0x01];
	return out_of_spec;
}

static const char *dmi_probe_status(u8 code)
{
	/* 7.27.1 */
	static const char *status[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"OK",
		u"Non-critical",
		u"Critical",
		u"Non-recoverable" /* 0x06 */
	};

	if (code >= 0x01 && code <= 0x06)
		return status[code - 0x01];
	return out_of_spec;
}

static void dmi_voltage_probe_value(const char *attr, u16 code)
{
	if (code == 0x8000)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"%.3f V", (float)(i16)code / 1000);
}

static void dmi_voltage_probe_resolution(u16 code)
{
	if (code == 0x8000)
		pr_attr(u"Resolution", u"Unknown");
	else
		pr_attr(u"Resolution", u"%.1f mV", (float)code / 10);
}

static void dmi_probe_accuracy(u16 code)
{
	if (code == 0x8000)
		pr_attr(u"Accuracy", u"Unknown");
	else
		pr_attr(u"Accuracy", u"%.2f%%", (float)code / 100);
}

/*
 * 7.28 Cooling Device (Type 27)
 */

static const char *dmi_cooling_device_type(u8 code)
{
	/* 7.28.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Fan",
		u"Centrifugal Blower",
		u"Chip Fan",
		u"Cabinet Fan",
		u"Power Supply Fan",
		u"Heat Pipe",
		u"Integrated Refrigeration" /* 0x09 */
	};
	static const char *type_0x10[] = {
		u"Active Cooling", /* 0x10 */
		u"Passive Cooling" /* 0x11 */
	};

	if (code >= 0x01 && code <= 0x09)
		return type[code - 0x01];
	if (code >= 0x10 && code <= 0x11)
		return type_0x10[code - 0x10];
	return out_of_spec;
}

static void dmi_cooling_device_speed(u16 code)
{
	if (code == 0x8000)
		pr_attr(u"Nominal Speed", u"Unknown Or Non-rotating");
	else
		pr_attr(u"Nominal Speed", u"%u rpm", code);
}

/*
 * 7.29 Temperature Probe (Type 28)
 */

static const char *dmi_temperature_probe_location(u8 code)
{
	/* 7.29.1 */
	static const char *location[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Processor",
		u"Disk",
		u"Peripheral Bay",
		u"System Management Module",
		u"Motherboard",
		u"Memory Module",
		u"Processor Module",
		u"Power Unit",
		u"Add-in Card",
		u"Front Panel Board",
		u"Back Panel Board",
		u"Power System Board",
		u"Drive Back Plane" /* 0x0F */
	};

	if (code >= 0x01 && code <= 0x0F)
		return location[code - 0x01];
	return out_of_spec;
}

static void dmi_temperature_probe_value(const char *attr, u16 code)
{
	if (code == 0x8000)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"%.1f deg C", (float)(i16)code / 10);
}

static void dmi_temperature_probe_resolution(u16 code)
{
	if (code == 0x8000)
		pr_attr(u"Resolution", u"Unknown");
	else
		pr_attr(u"Resolution", u"%.3f deg C", (float)code / 1000);
}

/*
 * 7.30 Electrical Current Probe (Type 29)
 */

static void dmi_current_probe_value(const char *attr, u16 code)
{
	if (code == 0x8000)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"%.3f A", (float)(i16)code / 1000);
}

static void dmi_current_probe_resolution(u16 code)
{
	if (code == 0x8000)
		pr_attr(u"Resolution", u"Unknown");
	else
		pr_attr(u"Resolution", u"%.1f mA", (float)code / 10);
}

/*
 * 7.33 System Boot Information (Type 32)
 */

static const char *dmi_system_boot_status(u8 code)
{
	static const char *status[] = {
		u"No errors detected", /* 0 */
		u"No bootable media",
		u"Operating system failed to load",
		u"Firmware-detected hardware failure",
		u"Operating system-detected hardware failure",
		u"User-requested boot",
		u"System security violation",
		u"Previously-requested image",
		u"System watchdog timer expired" /* 8 */
	};

	if (code <= 8)
		return status[code];
	if (code >= 128 && code <= 191)
		return u"OEM-specific";
	if (code >= 192)
		return u"Product-specific";
	return out_of_spec;
}

/*
 * 7.34 64-bit Memory Error Information (Type 33)
 */

static void dmi_64bit_memory_error_address(const char *attr, u64 code)
{
	if (code.h == 0x80000000 && code.l == 0x00000000)
		pr_attr(attr, u"Unknown");
	else
		pr_attr(attr, u"0x%08X%08X", code.h, code.l);
}

/*
 * 7.35 Management Device (Type 34)
 */

/*
 * Several boards have a bug where some type 34 structures have their
 * length incorrectly set to 0x10 instead of 0x0B. This causes the
 * first 5 characters of the device name to be trimmed. It's easy to
 * check and fix, so do it, but warn.
 */
static void dmi_fixup_type_34(struct dmi_header *h, int display)
{
	u8 *p = h->data;

	/* Make sure the hidden data is ASCII only */
	if (h->length == 0x10
	 && is_printable(p + 0x0B, 0x10 - 0x0B))
	{
		if (!(opt.flags & FLAG_QUIET) && display)
			printf(u"Invalid entry length (%u). Fixed up to %u.\n",
				0x10, 0x0B);
		h->length = 0x0B;
	}
}

static const char *dmi_management_device_type(u8 code)
{
	/* 7.35.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"LM75",
		u"LM78",
		u"LM79",
		u"LM80",
		u"LM81",
		u"ADM9240",
		u"DS1780",
		u"MAX1617",
		u"GL518SM",
		u"W83781D",
		u"HT82H791" /* 0x0D */
	};

	if (code >= 0x01 && code <= 0x0D)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_management_device_address_type(u8 code)
{
	/* 7.35.2 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"I/O Port",
		u"Memory",
		u"SMBus" /* 0x05 */
	};

	if (code >= 0x01 && code <= 0x05)
		return type[code - 0x01];
	return out_of_spec;
}

/*
 * 7.38 Memory Channel (Type 37)
 */

static const char *dmi_memory_channel_type(u8 code)
{
	/* 7.38.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"RamBus",
		u"SyncLink" /* 0x04 */
	};

	if (code >= 0x01 && code <= 0x04)
		return type[code - 0x01];
	return out_of_spec;
}

static void dmi_memory_channel_devices(u8 count, const u8 *p)
{
	char attr[18];
	int i;

	for (i = 1; i <= count; i++)
	{
		sprintf(attr, u"Device %hhu Load", (u8)i);
		pr_attr(attr, u"%u", p[3 * i]);
		if (!(opt.flags & FLAG_QUIET))
		{
			sprintf(attr, u"Device %hhu Handle", (u8)i);
			pr_attr(attr, u"0x%04X", WORD(p + 3 * i + 1));
		}
	}
}

/*
 * 7.39 IPMI Device Information (Type 38)
 */

static const char *dmi_ipmi_interface_type(u8 code)
{
	/* 7.39.1 and IPMI 2.0, appendix C1, table C1-2 */
	static const char *type[] = {
		u"Unknown", /* 0x00 */
		u"KCS (Keyboard Control Style)",
		u"SMIC (Server Management Interface Chip)",
		u"BT (Block Transfer)",
		u"SSIF (SMBus System Interface)" /* 0x04 */
	};

	if (code <= 0x04)
		return type[code];
	return out_of_spec;
}

static void dmi_ipmi_base_address(u8 type, const u8 *p, u8 lsb)
{
	if (type == 0x04) /* SSIF */
	{
		pr_attr(u"Base Address", u"0x%02X (SMBus)", (*p) >> 1);
	}
	else
	{
		u64 address = QWORD(p);
		pr_attr(u"Base Address", u"0x%08X%08X (%s)",
			address.h, (address.l & ~1) | lsb,
			address.l & 1 ? u"I/O" : u"Memory-mapped");
	}
}

/* code is assumed to be a 2-bit value */
static const char *dmi_ipmi_register_spacing(u8 code)
{
	/* IPMI 2.0, appendix C1, table C1-1 */
	static const char *spacing[] = {
		u"Successive Byte Boundaries", /* 0x00 */
		u"32-bit Boundaries",
		u"16-byte Boundaries", /* 0x02 */
		out_of_spec /* 0x03 */
	};

	return spacing[code];
}

/*
 * 7.40 System Power Supply (Type 39)
 */

static void dmi_power_supply_power(u16 code)
{
	if (code == 0x8000)
		pr_attr(u"Max Power Capacity", u"Unknown");
	else
		pr_attr(u"Max Power Capacity", u"%u W", (unsigned int)code);
}

static const char *dmi_power_supply_type(u8 code)
{
	/* 7.40.1 */
	static const char *type[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Linear",
		u"Switching",
		u"Battery",
		u"UPS",
		u"Converter",
		u"Regulator" /* 0x08 */
	};

	if (code >= 0x01 && code <= 0x08)
		return type[code - 0x01];
	return out_of_spec;
}

static const char *dmi_power_supply_status(u8 code)
{
	/* 7.40.1 */
	static const char *status[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"OK",
		u"Non-critical",
		u"Critical" /* 0x05 */
	};

	if (code >= 0x01 && code <= 0x05)
		return status[code - 0x01];
	return out_of_spec;
}

static const char *dmi_power_supply_range_switching(u8 code)
{
	/* 7.40.1 */
	static const char *switching[] = {
		u"Other", /* 0x01 */
		u"Unknown",
		u"Manual",
		u"Auto-switch",
		u"Wide Range",
		u"N/A" /* 0x06 */
	};

	if (code >= 0x01 && code <= 0x06)
		return switching[code - 0x01];
	return out_of_spec;
}

/*
 * 7.41 Additional Information (Type 40)
 *
 * Proper support of this entry type would require redesigning a large part of
 * the code, so I am waiting to see actual implementations of it to decide
 * whether it's worth the effort.
 */

static void dmi_additional_info(const struct dmi_header *h)
{
	u8 *p = h->data + 4;
	u8 count = *p++;
	u8 length;
	int i, offset = 5;

	for (i = 0; i < count; i++)
	{
		pr_handle_name(u"Additional Information %d", i + 1);

		/* Check for short entries */
		if (h->length < offset + 1) break;
		length = p[0x00];
		if (length < 0x05 || h->length < offset + length) break;

		pr_attr(u"Referenced Handle", u"0x%04x",
			WORD(p + 0x01));
		pr_attr(u"Referenced Offset", u"0x%02x",
			p[0x03]);
		pr_attr(u"String", u"%s",
			dmi_string(h, p[0x04]));

		switch (length - 0x05)
		{
			case 1:
				pr_attr(u"Value", u"0x%02x", p[0x05]);
				break;
			case 2:
				pr_attr(u"Value", u"0x%04x", WORD(p + 0x05));
				break;
			case 4:
				pr_attr(u"Value", u"0x%08x", DWORD(p + 0x05));
				break;
			default:
				pr_attr(u"Value", u"Unexpected size");
				break;
		}

		p += length;
		offset += length;
	}
}

/*
 * 7.43 Management Controller Host Interface (Type 42)
 */

static const char *dmi_management_controller_host_type(u8 code)
{
	/* DMTF DSP0239 (MCTP) version 1.1.0 */
	static const char *type[] = {
		u"KCS: Keyboard Controller Style", /* 0x02 */
		u"8250 UART Register Compatible",
		u"16450 UART Register Compatible",
		u"16550/16550A UART Register Compatible",
		u"16650/16650A UART Register Compatible",
		u"16750/16750A UART Register Compatible",
		u"16850/16850A UART Register Compatible" /* 0x08 */
	};

	if (code >= 0x02 && code <= 0x08)
		return type[code - 0x02];
	if (code <= 0x3F)
		return u"MCTP";
	if (code == 0x40)
		return u"Network";
	if (code == 0xF0)
		return u"OEM";
	return out_of_spec;
}

/*
 * 7.43.2: Protocol Record Types
 */
static const char *dmi_protocol_record_type(u8 type)
{
	const char *protocol[] = {
		u"Reserved",		/* 0x0 */
		u"Reserved",
		u"IPMI",
		u"MCTP",
		u"Redfish over IP",	/* 0x4 */
	};

	if (type <= 0x4)
		return protocol[type];
	if (type == 0xF0)
		return u"OEM";
	return out_of_spec;
}

/*
 * DSP0270: 8.6: Protocol IP Assignment types
 */
static const char *dmi_protocol_assignment_type(u8 type)
{
	const char *assignment[] = {
		u"Unknown",		/* 0x0 */
		u"Static",
		u"DHCP",
		u"AutoConf",
		u"Host Selected",	/* 0x4 */
	};

	if (type <= 0x4)
		return assignment[type];
	return out_of_spec;
}

/*
 * DSP0270: 8.6: Protocol IP Address type
 */
static const char *dmi_address_type(u8 type)
{
	const char *addressformat[] = {
		u"Unknown",	/* 0x0 */
		u"IPv4",
		u"IPv6",		/* 0x2 */
	};

	if (type <= 0x2)
		return addressformat[type];
	return out_of_spec;
}

/*
 *  DSP0270: 8.6 Protocol Address decode
 */
static const char *dmi_address_decode(u8 *data, char *storage, u8 addrtype)
{
	if (addrtype == 0x1) /* IPv4 */
		return inet_ntop(AF_INET, data, storage, 64);
	if (addrtype == 0x2) /* IPv6 */
		return inet_ntop(AF_INET6, data, storage, 64);
	return out_of_spec;
}

/*
 * DSP0270: 8.5: Parse the protocol record format
 */
static void dmi_parse_protocol_record(u8 *rec)
{
	u8 rid;
	u8 rlen;
	u8 *rdata;
	char buf[64];
	u8 assign_val;
	u8 addrtype;
	u8 hlen;
	const char *addrstr;
	const char *hname;
	char attr[38];

	/* DSP0270: 8.5: Protocol Identifier */
	rid = rec[0x0];
	/* DSP0270: 8.5: Protocol Record Length */
	rlen = rec[0x1];
	/* DSP0270: 8.5: Protocol Record Data */
	rdata = &rec[0x2];

	pr_attr(u"Protocol ID", u"%02x (%s)", rid,
		dmi_protocol_record_type(rid));

	/*
	 * Don't decode anything other than Redfish for now
	 * Note 0x4 is Redfish over IP in 7.43.2
	 * and DSP0270: 8.5
	 */
	if (rid != 0x4)
		return;

	/*
	 * Ensure that the protocol record is of sufficient length
	 * For RedFish that means rlen must be at least 91 bytes
	 * other protcols will need different length checks
	 */
	if (rlen < 91)
		return;

	/*
	 * DSP0270: 8.6: Redfish Over IP Service UUID
	 * Note: ver is hardcoded to 0x311 here just for
	 * convenience.  It could get passed from the SMBIOS
	 * header, but that's a lot of passing of pointers just
	 * to get that info, and the only thing it is used for is
	 * to determine the endianness of the field.  Since we only
	 * do this parsing on versions of SMBIOS after 3.1.1, and the
	 * endianness of the field is always little after version 2.6.0
	 * we can just pick a sufficiently recent version here.
	 */
	dmi_system_uuid(pr_subattr, u"Service UUID", &rdata[0], 0x311);

	/*
	 * DSP0270: 8.6: Redfish Over IP Host IP Assignment Type
	 * Note, using decimal indices here, as the DSP0270
	 * uses decimal, so as to make it more comparable
	 */
	assign_val = rdata[16];
	pr_subattr(u"Host IP Assignment Type", u"%s",
		dmi_protocol_assignment_type(assign_val));

	/* DSP0270: 8.6: Redfish Over IP Host Address format */
	addrtype = rdata[17];
	addrstr = dmi_address_type(addrtype);
	pr_subattr(u"Host IP Address Format", u"%s",
		addrstr);

	/* DSP0270: 8.6 IP Assignment types */
	/* We only use the Host IP Address and Mask if the assignment type is static */
	if (assign_val == 0x1 || assign_val == 0x3)
	{
		/* DSP0270: 8.6: the Host IPv[4|6] Address */
		sprintf(attr, u"%s Address", addrstr);
		pr_subattr(attr, u"%s",
			dmi_address_decode(&rdata[18], buf, addrtype));

		/* DSP0270: 8.6: Prints the Host IPv[4|6] Mask */
		sprintf(attr, u"%s Mask", addrstr);
		pr_subattr(attr, u"%s",
			dmi_address_decode(&rdata[34], buf, addrtype));
	}

	/* DSP0270: 8.6: Get the Redfish Service IP Discovery Type */
	assign_val = rdata[50];
	/* Redfish Service IP Discovery type mirrors Host IP Assignment type */
	pr_subattr(u"Redfish Service IP Discovery Type", u"%s",
		dmi_protocol_assignment_type(assign_val));

	/* DSP0270: 8.6: Get the Redfish Service IP Address Format */
	addrtype = rdata[51];
	addrstr = dmi_address_type(addrtype);
	pr_subattr(u"Redfish Service IP Address Format", u"%s",
		addrstr);

	if (assign_val == 0x1 || assign_val == 0x3)
	{
		u16 port;
		u32 vlan;

		/* DSP0270: 8.6: Prints the Redfish IPv[4|6] Service Address */
		sprintf(attr, u"%s Redfish Service Address", addrstr);
		pr_subattr(attr, u"%s",
			dmi_address_decode(&rdata[52], buf,
			addrtype));

		/* DSP0270: 8.6: Prints the Redfish IPv[4|6] Service Mask */
		sprintf(attr, u"%s Redfish Service Mask", addrstr);
		pr_subattr(attr, u"%s",
			dmi_address_decode(&rdata[68], buf,
			addrtype));

		/* DSP0270: 8.6: Redfish vlan and port info */
		port = WORD(&rdata[84]);
		vlan = DWORD(&rdata[86]);
		pr_subattr(u"Redfish Service Port", u"%hu", port);
		pr_subattr(u"Redfish Service Vlan", u"%u", vlan);
	}

	/* DSP0270: 8.6: Redfish host length and name */
	hlen = rdata[90];

	/*
	 * DSP0270: 8.6: The length of the host string + 91 (the minimum
	 * size of a protocol record) cannot exceed the record length
	 * (rec[0x1])
	 */
	hname = (const char *)&rdata[91];
	if (hlen + 91 > rlen)
	{
		hname = out_of_spec;
		hlen = strlen(out_of_spec);
	}
	pr_subattr(u"Redfish Service Hostname", u"%.*s", hlen, hname);
}

/*
 * DSP0270: 8.3: Device type ennumeration
 */
static const char *dmi_parse_device_type(u8 type)
{
	const char *devname[] = {
		u"USB",		/* 0x2 */
		u"PCI/PCIe",	/* 0x3 */
	};

	if (type >= 0x2 && type <= 0x3)
		return devname[type - 0x2];
	if (type >= 0x80)
		return u"OEM";
	return out_of_spec;
}

static void dmi_parse_controller_structure(const struct dmi_header *h)
{
	int i;
	u8 *data = h->data;
	/* Host interface type */
	u8 type;
	/* Host Interface specific data length */
	u8 len;
	u8 count;
	u32 total_read;

	/*
	 * Minimum length of this struct is 0xB bytes
	 */
	if (h->length < 0xB)
		return;

	/*
	 * Also need to ensure that the interface specific data length
	 * plus the size of the structure to that point don't exceed
	 * the defined length of the structure, or we will overrun its
	 * bounds
	 */
	len = data[0x5];
	total_read = len + 0x6;

	if (total_read > h->length)
		return;

	type = data[0x4];
	pr_attr(u"Host Interface Type", u"%s",
		dmi_management_controller_host_type(type));

	/*
	 * The following decodes are code for Network interface host types only
	 * As defined in DSP0270
	 */
	if (type != 0x40)
		return;

	if (len != 0)
	{
		/* DSP0270: 8.3 Table 2: Device Type */
		type = data[0x6];

		pr_attr(u"Device Type", u"%s",
			dmi_parse_device_type(type));
		if (type == 0x2 && len >= 5)
		{
			/* USB Device Type - need at least 6 bytes */
			u8 *usbdata = &data[0x7];
			/* USB Device Descriptor: idVendor */
			pr_attr(u"idVendor", u"0x%04x",
				WORD(&usbdata[0x0]));
			/* USB Device Descriptor: idProduct */
			pr_attr(u"idProduct", u"0x%04x",
				WORD(&usbdata[0x2]));
			/*
			 * USB Serial number is here, but its useless, don't
			 * bother decoding it
			 */
		}
		else if (type == 0x3 && len >= 9)
		{
			/* PCI Device Type - Need at least 8 bytes */
			u8 *pcidata = &data[0x7];
			/* PCI Device Descriptor: VendorID */
			pr_attr(u"VendorID", u"0x%04x",
				WORD(&pcidata[0x0]));
			/* PCI Device Descriptor: DeviceID */
			pr_attr(u"DeviceID", u"0x%04x",
				WORD(&pcidata[0x2]));
			/* PCI Device Descriptor: PCI SubvendorID */
			pr_attr(u"SubVendorID", u"0x%04x",
				WORD(&pcidata[0x4]));
			/* PCI Device Descriptor: PCI SubdeviceID */
			pr_attr(u"SubDeviceID", u"0x%04x",
				WORD(&pcidata[0x6]));
		}
		else if (type == 0x4 && len >= 5)
		{
			/* OEM Device Type - Need at least 4 bytes */
			u8 *oemdata = &data[0x7];
			/* OEM Device Descriptor: IANA */
			pr_attr(u"Vendor ID", u"0x%02x:0x%02x:0x%02x:0x%02x",
				oemdata[0x0], oemdata[0x1],
				oemdata[0x2], oemdata[0x3]);
		}
		/* Don't mess with unknown types for now */
	}

	/*
	 * DSP0270: 8.2 and 8.5: Protocol record count and protocol records
	 * Move to the Protocol Count.
	 */
	data = &data[total_read];

	/*
	 * We've validated up to 0x6 + len bytes, but we need to validate
	 * the next byte below, the count value.
	 */
	total_read++;
	if (total_read > h->length)
	{
		printf(u"Total read length %d exceeds total structure length %d (handle 0x%04hx)\n",
			total_read, h->length, h->handle);
		return;
	}

	/* Get the protocol records count */
	count = data[0x0];
	if (count)
	{
		u8 *rec = &data[0x1];
		for (i = 0; i < count; i++)
		{
			/*
			 * Need to ensure that this record doesn't overrun
			 * the total length of the type 42 struct.  Note the +2
			 * is added for the two leading bytes of a protocol
			 * record representing the type and length bytes.
			 */
			total_read += rec[1] + 2;
			if (total_read > h->length)
			{
				printf(u"Total read length %d exceeds total structure length %d (handle 0x%04hx, record %d)\n",
					total_read, h->length, h->handle, i + 1);
				return;
			}

			dmi_parse_protocol_record(rec);

			/*
			 * DSP0270: 8.6
			 * Each record is rec[1] bytes long, starting at the
			 * data byte immediately following the length field.
			 * That means we need to add the byte for the rec id,
			 * the byte for the length field, and the value of the
			 * length field itself.
			 */
			rec += rec[1] + 2;
		}
	}
}

/*
 * 7.44 TPM Device (Type 43)
 */

static void dmi_tpm_vendor_id(const u8 *p)
{
	char vendor_id[5];
	int i;

	/* ASCII filtering */
	for (i = 0; i < 4 && p[i] != 0; i++)
	{
		if (p[i] < 32 || p[i] >= 127)
			vendor_id[i] = '.';
		else
			vendor_id[i] = p[i];
	}

	/* Terminate the string */
	vendor_id[i] = '\0';

	pr_attr(u"Vendor ID", u"%s", vendor_id);
}

static void dmi_tpm_characteristics(u64 code)
{
	/* 7.1.1 */
	static const char *characteristics[] = {
		u"TPM Device characteristics not supported", /* 2 */
		u"Family configurable via firmware update",
		u"Family configurable via platform software support",
		u"Family configurable via OEM proprietary mechanism" /* 5 */
	};
	int i;

	/*
	 * This isn't very clear what this bit is supposed to mean
	 */
	if (code.l & (1 << 2))
	{
		pr_list_item(u"%s", characteristics[0]);
		return;
	}

	for (i = 3; i <= 5; i++)
		if (code.l & (1 << i))
			pr_list_item(u"%s", characteristics[i - 2]);
}

/*
 * Main
 */

static void dmi_decode(const struct dmi_header *h, u16 ver)
{
	const u8 *data = h->data;

	/*
	 * Note: DMI types 37 and 42 are untested
	 */
	switch (h->type)
	{
		case 0: /* 7.1 BIOS Information */
			pr_handle_name(u"BIOS Information");
			if (h->length < 0x12) break;
			pr_attr(u"Vendor", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Version", u"%s",
				dmi_string(h, data[0x05]));
			pr_attr(u"Release Date", u"%s",
				dmi_string(h, data[0x08]));
			/*
			 * On IA-64, the BIOS base address will read 0 because
			 * there is no BIOS. Skip the base address and the
			 * runtime size in this case.
			 */
			if (WORD(data + 0x06) != 0)
			{
				pr_attr(u"Address", u"0x%04X0",
					WORD(data + 0x06));
				dmi_bios_runtime_size((0x10000 - WORD(data + 0x06)) << 4);
			}
			dmi_bios_rom_size(data[0x09], h->length < 0x1A ? 16 : WORD(data + 0x18));
			pr_list_start(u"Characteristics", NULL);
			dmi_bios_characteristics(QWORD(data + 0x0A));
			pr_list_end();
			if (h->length < 0x13) break;
			dmi_bios_characteristics_x1(data[0x12]);
			if (h->length < 0x14) break;
			dmi_bios_characteristics_x2(data[0x13]);
			if (h->length < 0x18) break;
			if (data[0x14] != 0xFF && data[0x15] != 0xFF)
				pr_attr(u"BIOS Revision", u"%u.%u",
					data[0x14], data[0x15]);
			if (data[0x16] != 0xFF && data[0x17] != 0xFF)
				pr_attr(u"Firmware Revision", u"%u.%u",
					data[0x16], data[0x17]);
			break;

		case 1: /* 7.2 System Information */
			pr_handle_name(u"System Information");
			if (h->length < 0x08) break;
			pr_attr(u"Manufacturer", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Product Name", u"%s",
				dmi_string(h, data[0x05]));
			pr_attr(u"Version", u"%s",
				dmi_string(h, data[0x06]));
			pr_attr(u"Serial Number", u"%s",
				dmi_string(h, data[0x07]));
			if (h->length < 0x19) break;
			dmi_system_uuid(pr_attr, u"UUID", data + 0x08, ver);
			pr_attr(u"Wake-up Type", u"%s",
				dmi_system_wake_up_type(data[0x18]));
			if (h->length < 0x1B) break;
			pr_attr(u"SKU Number", u"%s",
				dmi_string(h, data[0x19]));
			pr_attr(u"Family", u"%s",
				dmi_string(h, data[0x1A]));
			break;

		case 2: /* 7.3 Base Board Information */
			pr_handle_name(u"Base Board Information");
			if (h->length < 0x08) break;
			pr_attr(u"Manufacturer", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Product Name", u"%s",
				dmi_string(h, data[0x05]));
			pr_attr(u"Version", u"%s",
				dmi_string(h, data[0x06]));
			pr_attr(u"Serial Number", u"%s",
				dmi_string(h, data[0x07]));
			if (h->length < 0x09) break;
			pr_attr(u"Asset Tag", u"%s",
				dmi_string(h, data[0x08]));
			if (h->length < 0x0A) break;
			dmi_base_board_features(data[0x09]);
			if (h->length < 0x0E) break;
			pr_attr(u"Location In Chassis", u"%s",
				dmi_string(h, data[0x0A]));
			if (!(opt.flags & FLAG_QUIET))
				pr_attr(u"Chassis Handle", u"0x%04X",
					WORD(data + 0x0B));
			pr_attr(u"Type", u"%s",
				dmi_base_board_type(data[0x0D]));
			if (h->length < 0x0F) break;
			if (h->length < 0x0F + data[0x0E] * sizeof(u16)) break;
			if (!(opt.flags & FLAG_QUIET))
				dmi_base_board_handles(data[0x0E], data + 0x0F);
			break;

		case 3: /* 7.4 Chassis Information */
			pr_handle_name(u"Chassis Information");
			if (h->length < 0x09) break;
			pr_attr(u"Manufacturer", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Type", u"%s",
				dmi_chassis_type(data[0x05]));
			pr_attr(u"Lock", u"%s",
				dmi_chassis_lock(data[0x05] >> 7));
			pr_attr(u"Version", u"%s",
				dmi_string(h, data[0x06]));
			pr_attr(u"Serial Number", u"%s",
				dmi_string(h, data[0x07]));
			pr_attr(u"Asset Tag", u"%s",
				dmi_string(h, data[0x08]));
			if (h->length < 0x0D) break;
			pr_attr(u"Boot-up State", u"%s",
				dmi_chassis_state(data[0x09]));
			pr_attr(u"Power Supply State", u"%s",
				dmi_chassis_state(data[0x0A]));
			pr_attr(u"Thermal State", u"%s",
				dmi_chassis_state(data[0x0B]));
			pr_attr(u"Security Status", u"%s",
				dmi_chassis_security_status(data[0x0C]));
			if (h->length < 0x11) break;
			pr_attr(u"OEM Information", u"0x%08X",
				DWORD(data + 0x0D));
			if (h->length < 0x13) break;
			dmi_chassis_height(data[0x11]);
			dmi_chassis_power_cords(data[0x12]);
			if (h->length < 0x15) break;
			if (h->length < 0x15 + data[0x13] * data[0x14]) break;
			dmi_chassis_elements(data[0x13], data[0x14], data + 0x15);
			if (h->length < 0x16 + data[0x13] * data[0x14]) break;
			pr_attr(u"SKU Number", u"%s",
				dmi_string(h, data[0x15 + data[0x13] * data[0x14]]));
			break;

		case 4: /* 7.5 Processor Information */
			pr_handle_name(u"Processor Information");
			if (h->length < 0x1A) break;
			pr_attr(u"Socket Designation", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Type", u"%s",
				dmi_processor_type(data[0x05]));
			pr_attr(u"Family", u"%s",
				dmi_processor_family(h, ver));
			pr_attr(u"Manufacturer", u"%s",
				dmi_string(h, data[0x07]));
			dmi_processor_id(h);
			pr_attr(u"Version", u"%s",
				dmi_string(h, data[0x10]));
			dmi_processor_voltage(u"Voltage", data[0x11]);
			dmi_processor_frequency(u"External Clock", data + 0x12);
			dmi_processor_frequency(u"Max Speed", data + 0x14);
			dmi_processor_frequency(u"Current Speed", data + 0x16);
			if (data[0x18] & (1 << 6))
				pr_attr(u"Status", u"Populated, %s",
					dmi_processor_status(data[0x18] & 0x07));
			else
				pr_attr(u"Status", u"Unpopulated");
			pr_attr(u"Upgrade", u"%s",
				dmi_processor_upgrade(data[0x19]));
			if (h->length < 0x20) break;
			if (!(opt.flags & FLAG_QUIET))
			{
				dmi_processor_cache(u"L1 Cache Handle",
						    WORD(data + 0x1A), u"L1", ver);
				dmi_processor_cache(u"L2 Cache Handle",
						    WORD(data + 0x1C), u"L2", ver);
				dmi_processor_cache(u"L3 Cache Handle",
						    WORD(data + 0x1E), u"L3", ver);
			}
			if (h->length < 0x23) break;
			pr_attr(u"Serial Number", u"%s",
				dmi_string(h, data[0x20]));
			pr_attr(u"Asset Tag", u"%s",
				dmi_string(h, data[0x21]));
			pr_attr(u"Part Number", u"%s",
				dmi_string(h, data[0x22]));
			if (h->length < 0x28) break;
			if (data[0x23] != 0)
				pr_attr(u"Core Count", u"%u",
					h->length >= 0x2C && data[0x23] == 0xFF ?
					WORD(data + 0x2A) : data[0x23]);
			if (data[0x24] != 0)
				pr_attr(u"Core Enabled", u"%u",
					h->length >= 0x2E && data[0x24] == 0xFF ?
					WORD(data + 0x2C) : data[0x24]);
			if (data[0x25] != 0)
				pr_attr(u"Thread Count", u"%u",
					h->length >= 0x30 && data[0x25] == 0xFF ?
					WORD(data + 0x2E) : data[0x25]);
			dmi_processor_characteristics(u"Characteristics",
						      WORD(data + 0x26));
			break;

		case 5: /* 7.6 Memory Controller Information */
			pr_handle_name(u"Memory Controller Information");
			if (h->length < 0x0F) break;
			pr_attr(u"Error Detecting Method", u"%s",
				dmi_memory_controller_ed_method(data[0x04]));
			dmi_memory_controller_ec_capabilities(u"Error Correcting Capabilities",
							      data[0x05]);
			pr_attr(u"Supported Interleave", u"%s",
				dmi_memory_controller_interleave(data[0x06]));
			pr_attr(u"Current Interleave", u"%s",
				dmi_memory_controller_interleave(data[0x07]));
			pr_attr(u"Maximum Memory Module Size", u"%u MB",
				1 << data[0x08]);
			pr_attr(u"Maximum Total Memory Size", u"%u MB",
				data[0x0E] * (1 << data[0x08]));
			dmi_memory_controller_speeds(u"Supported Speeds",
						     WORD(data + 0x09));
			dmi_memory_module_types(u"Supported Memory Types",
						WORD(data + 0x0B), 0);
			dmi_processor_voltage(u"Memory Module Voltage", data[0x0D]);
			if (h->length < 0x0F + data[0x0E] * sizeof(u16)) break;
			dmi_memory_controller_slots(data[0x0E], data + 0x0F);
			if (h->length < 0x10 + data[0x0E] * sizeof(u16)) break;
			dmi_memory_controller_ec_capabilities(u"Enabled Error Correcting Capabilities",
							      data[0x0F + data[0x0E] * sizeof(u16)]);
			break;

		case 6: /* 7.7 Memory Module Information */
			pr_handle_name(u"Memory Module Information");
			if (h->length < 0x0C) break;
			pr_attr(u"Socket Designation", u"%s",
				dmi_string(h, data[0x04]));
			dmi_memory_module_connections(data[0x05]);
			dmi_memory_module_speed(u"Current Speed", data[0x06]);
			dmi_memory_module_types(u"Type", WORD(data + 0x07), 1);
			dmi_memory_module_size(u"Installed Size", data[0x09]);
			dmi_memory_module_size(u"Enabled Size", data[0x0A]);
			dmi_memory_module_error(data[0x0B]);
			break;

		case 7: /* 7.8 Cache Information */
			pr_handle_name(u"Cache Information");
			if (h->length < 0x0F) break;
			pr_attr(u"Socket Designation", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Configuration", u"%s, %s, Level %u",
				WORD(data + 0x05) & 0x0080 ? u"Enabled" : u"Disabled",
				WORD(data + 0x05) & 0x0008 ? u"Socketed" : u"Not Socketed",
				(WORD(data + 0x05) & 0x0007) + 1);
			pr_attr(u"Operational Mode", u"%s",
				dmi_cache_mode((WORD(data + 0x05) >> 8) & 0x0003));
			pr_attr(u"Location", u"%s",
				dmi_cache_location((WORD(data + 0x05) >> 5) & 0x0003));
			if (h->length >= 0x1B)
				dmi_cache_size_2(u"Installed Size", DWORD(data + 0x17));
			else
				dmi_cache_size(u"Installed Size", WORD(data + 0x09));
			if (h->length >= 0x17)
				dmi_cache_size_2(u"Maximum Size", DWORD(data + 0x13));
			else
				dmi_cache_size(u"Maximum Size", WORD(data + 0x07));
			dmi_cache_types(u"Supported SRAM Types", WORD(data + 0x0B), 0);
			dmi_cache_types(u"Installed SRAM Type", WORD(data + 0x0D), 1);
			if (h->length < 0x13) break;
			dmi_memory_module_speed(u"Speed", data[0x0F]);
			pr_attr(u"Error Correction Type", u"%s",
				dmi_cache_ec_type(data[0x10]));
			pr_attr(u"System Type", u"%s",
				dmi_cache_type(data[0x11]));
			pr_attr(u"Associativity", u"%s",
				dmi_cache_associativity(data[0x12]));
			break;

		case 8: /* 7.9 Port Connector Information */
			pr_handle_name(u"Port Connector Information");
			if (h->length < 0x09) break;
			pr_attr(u"Internal Reference Designator", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Internal Connector Type", u"%s",
				dmi_port_connector_type(data[0x05]));
			pr_attr(u"External Reference Designator", u"%s",
				dmi_string(h, data[0x06]));
			pr_attr(u"External Connector Type", u"%s",
				dmi_port_connector_type(data[0x07]));
			pr_attr(u"Port Type", u"%s",
				dmi_port_type(data[0x08]));
			break;

		case 9: /* 7.10 System Slots */
			pr_handle_name(u"System Slot Information");
			if (h->length < 0x0C) break;
			pr_attr(u"Designation", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Type", u"%s%s",
				dmi_slot_bus_width(data[0x06]),
				dmi_slot_type(data[0x05]));
			pr_attr(u"Current Usage", u"%s",
				dmi_slot_current_usage(data[0x07]));
			pr_attr(u"Length", u"%s",
				dmi_slot_length(data[0x08]));
			dmi_slot_id(data[0x09], data[0x0A], data[0x05]);
			if (h->length < 0x0D)
				dmi_slot_characteristics(u"Characteristics", data[0x0B], 0x00);
			else
				dmi_slot_characteristics(u"Characteristics", data[0x0B], data[0x0C]);
			if (h->length < 0x11) break;
			dmi_slot_segment_bus_func(WORD(data + 0x0D), data[0x0F], data[0x10]);
			if (h->length < 0x13) break;
			pr_attr(u"Data Bus Width", u"%u", data[0x11]);
			pr_attr(u"Peer Devices", u"%u", data[0x12]);
			if (h->length - 0x13 >= data[0x12] * 5)
				dmi_slot_peers(data[0x12], data + 0x13);
			break;

		case 10: /* 7.11 On Board Devices Information */
			dmi_on_board_devices(h);
			break;

		case 11: /* 7.12 OEM Strings */
			pr_handle_name(u"OEM Strings");
			if (h->length < 0x05) break;
			dmi_oem_strings(h);
			break;

		case 12: /* 7.13 System Configuration Options */
			pr_handle_name(u"System Configuration Options");
			if (h->length < 0x05) break;
			dmi_system_configuration_options(h);
			break;

		case 13: /* 7.14 BIOS Language Information */
			pr_handle_name(u"BIOS Language Information");
			if (h->length < 0x16) break;
			if (ver >= 0x0201)
			{
				pr_attr(u"Language Description Format", u"%s",
					dmi_bios_language_format(data[0x05]));
			}
			pr_list_start(u"Installable Languages", u"%u", data[0x04]);
			dmi_bios_languages(h);
			pr_list_end();
			pr_attr(u"Currently Installed Language", u"%s",
				dmi_string(h, data[0x15]));
			break;

		case 14: /* 7.15 Group Associations */
			pr_handle_name(u"Group Associations");
			if (h->length < 0x05) break;
			pr_attr(u"Name", u"%s",
				dmi_string(h, data[0x04]));
			pr_list_start(u"Items", u"%u",
				(h->length - 0x05) / 3);
			dmi_group_associations_items((h->length - 0x05) / 3, data + 0x05);
			pr_list_end();
			break;

		case 15: /* 7.16 System Event Log */
			pr_handle_name(u"System Event Log");
			if (h->length < 0x14) break;
			pr_attr(u"Area Length", u"%u bytes",
				WORD(data + 0x04));
			pr_attr(u"Header Start Offset", u"0x%04X",
				WORD(data + 0x06));
			if (WORD(data + 0x08) - WORD(data + 0x06))
				pr_attr(u"Header Length", u"%u byte%s",
					WORD(data + 0x08) - WORD(data + 0x06),
					WORD(data + 0x08) - WORD(data + 0x06) > 1 ? u"s" : u"");
			pr_attr(u"Data Start Offset", u"0x%04X",
				WORD(data + 0x08));
			pr_attr(u"Access Method", u"%s",
				dmi_event_log_method(data[0x0A]));
			dmi_event_log_address(data[0x0A], data + 0x10);
			dmi_event_log_status(data[0x0B]);
			pr_attr(u"Change Token", u"0x%08X",
				DWORD(data + 0x0C));
			if (h->length < 0x17) break;
			pr_attr(u"Header Format", u"%s",
				dmi_event_log_header_type(data[0x14]));
			pr_attr(u"Supported Log Type Descriptors", u"%u",
				data[0x15]);
			if (h->length < 0x17 + data[0x15] * data[0x16]) break;
			dmi_event_log_descriptors(data[0x15], data[0x16], data + 0x17);
			break;

		case 16: /* 7.17 Physical Memory Array */
			pr_handle_name(u"Physical Memory Array");
			if (h->length < 0x0F) break;
			pr_attr(u"Location", u"%s",
				dmi_memory_array_location(data[0x04]));
			pr_attr(u"Use", u"%s",
				dmi_memory_array_use(data[0x05]));
			pr_attr(u"Error Correction Type", u"%s",
				dmi_memory_array_ec_type(data[0x06]));
			if (DWORD(data + 0x07) == 0x80000000)
			{
				if (h->length < 0x17)
					pr_attr(u"Maximum Capacity", u"Unknown");
				else
					dmi_print_memory_size(u"Maximum Capacity",
							      QWORD(data + 0x0F), 0);
			}
			else
			{
				u64 capacity;

				capacity.h = 0;
				capacity.l = DWORD(data + 0x07);
				dmi_print_memory_size(u"Maximum Capacity",
						      capacity, 1);
			}
			if (!(opt.flags & FLAG_QUIET))
				dmi_memory_array_error_handle(WORD(data + 0x0B));
			pr_attr(u"Number Of Devices", u"%u",
				WORD(data + 0x0D));
			break;

		case 17: /* 7.18 Memory Device */
			pr_handle_name(u"Memory Device");
			if (h->length < 0x15) break;
			if (!(opt.flags & FLAG_QUIET))
			{
				pr_attr(u"Array Handle", u"0x%04X",
					WORD(data + 0x04));
				dmi_memory_array_error_handle(WORD(data + 0x06));
			}
			dmi_memory_device_width(u"Total Width", WORD(data + 0x08));
			dmi_memory_device_width(u"Data Width", WORD(data + 0x0A));
			if (h->length >= 0x20 && WORD(data + 0x0C) == 0x7FFF)
				dmi_memory_device_extended_size(DWORD(data + 0x1C));
			else
				dmi_memory_device_size(WORD(data + 0x0C));
			pr_attr(u"Form Factor", u"%s",
				dmi_memory_device_form_factor(data[0x0E]));
			dmi_memory_device_set(data[0x0F]);
			pr_attr(u"Locator", u"%s",
				dmi_string(h, data[0x10]));
			pr_attr(u"Bank Locator", u"%s",
				dmi_string(h, data[0x11]));
			pr_attr(u"Type", u"%s",
				dmi_memory_device_type(data[0x12]));
			dmi_memory_device_type_detail(WORD(data + 0x13));
			if (h->length < 0x17) break;
			/* If no module is present, the remaining fields are irrelevant */
			if (WORD(data + 0x0C) == 0)
				break;
			dmi_memory_device_speed(u"Speed", WORD(data + 0x15),
						h->length >= 0x5C ?
						DWORD(data + 0x54) : 0);
			if (h->length < 0x1B) break;
			pr_attr(u"Manufacturer", u"%s",
				dmi_string(h, data[0x17]));
			pr_attr(u"Serial Number", u"%s",
				dmi_string(h, data[0x18]));
			pr_attr(u"Asset Tag", u"%s",
				dmi_string(h, data[0x19]));
			pr_attr(u"Part Number", u"%s",
				dmi_string(h, data[0x1A]));
			if (h->length < 0x1C) break;
			if ((data[0x1B] & 0x0F) == 0)
				pr_attr(u"Rank", u"Unknown");
			else
				pr_attr(u"Rank", u"%u", data[0x1B] & 0x0F);
			if (h->length < 0x22) break;
			dmi_memory_device_speed(u"Configured Memory Speed",
						WORD(data + 0x20),
						h->length >= 0x5C ?
						DWORD(data + 0x58) : 0);
			if (h->length < 0x28) break;
			dmi_memory_voltage_value(u"Minimum Voltage",
						 WORD(data + 0x22));
			dmi_memory_voltage_value(u"Maximum Voltage",
						 WORD(data + 0x24));
			dmi_memory_voltage_value(u"Configured Voltage",
						 WORD(data + 0x26));
			if (h->length < 0x34) break;
			dmi_memory_technology(data[0x28]);
			dmi_memory_operating_mode_capability(WORD(data + 0x29));
			pr_attr(u"Firmware Version", u"%s",
				dmi_string(h, data[0x2B]));
			dmi_memory_manufacturer_id(u"Module Manufacturer ID",
						   WORD(data + 0x2C));
			dmi_memory_product_id(u"Module Product ID",
					      WORD(data + 0x2E));
			dmi_memory_manufacturer_id(u"Memory Subsystem Controller Manufacturer ID",
						   WORD(data + 0x30));
			dmi_memory_product_id(u"Memory Subsystem Controller Product ID",
					      WORD(data + 0x32));
			if (h->length < 0x3C) break;
			dmi_memory_size(u"Non-Volatile Size", QWORD(data + 0x34));
			if (h->length < 0x44) break;
			dmi_memory_size(u"Volatile Size", QWORD(data + 0x3C));
			if (h->length < 0x4C) break;
			dmi_memory_size(u"Cache Size", QWORD(data + 0x44));
			if (h->length < 0x54) break;
			dmi_memory_size(u"Logical Size", QWORD(data + 0x4C));
			break;

		case 18: /* 7.19 32-bit Memory Error Information */
			pr_handle_name(u"32-bit Memory Error Information");
			if (h->length < 0x17) break;
			pr_attr(u"Type", u"%s",
				dmi_memory_error_type(data[0x04]));
			pr_attr(u"Granularity", u"%s",
				dmi_memory_error_granularity(data[0x05]));
			pr_attr(u"Operation", u"%s",
				dmi_memory_error_operation(data[0x06]));
			dmi_memory_error_syndrome(DWORD(data + 0x07));
			dmi_32bit_memory_error_address(u"Memory Array Address",
						       DWORD(data + 0x0B));
			dmi_32bit_memory_error_address(u"Device Address",
						       DWORD(data + 0x0F));
			dmi_32bit_memory_error_address(u"Resolution",
						       DWORD(data + 0x13));
			break;

		case 19: /* 7.20 Memory Array Mapped Address */
			pr_handle_name(u"Memory Array Mapped Address");
			if (h->length < 0x0F) break;
			if (h->length >= 0x1F && DWORD(data + 0x04) == 0xFFFFFFFF)
			{
				u64 start, end;

				start = QWORD(data + 0x0F);
				end = QWORD(data + 0x17);

				pr_attr(u"Starting Address", u"0x%08X%08Xk",
					start.h, start.l);
				pr_attr(u"Ending Address", u"0x%08X%08Xk",
					end.h, end.l);
				dmi_mapped_address_extended_size(start, end);
			}
			else
			{
				pr_attr(u"Starting Address", u"0x%08X%03X",
					DWORD(data + 0x04) >> 2,
					(DWORD(data + 0x04) & 0x3) << 10);
				pr_attr(u"Ending Address", u"0x%08X%03X",
					DWORD(data + 0x08) >> 2,
					((DWORD(data + 0x08) & 0x3) << 10) + 0x3FF);
				dmi_mapped_address_size(DWORD(data + 0x08) - DWORD(data + 0x04) + 1);
			}
			if (!(opt.flags & FLAG_QUIET))
				pr_attr(u"Physical Array Handle", u"0x%04X",
					WORD(data + 0x0C));
			pr_attr(u"Partition Width", u"%u",
				data[0x0E]);
			break;

		case 20: /* 7.21 Memory Device Mapped Address */
			pr_handle_name(u"Memory Device Mapped Address");
			if (h->length < 0x13) break;
			if (h->length >= 0x23 && DWORD(data + 0x04) == 0xFFFFFFFF)
			{
				u64 start, end;

				start = QWORD(data + 0x13);
				end = QWORD(data + 0x1B);

				pr_attr(u"Starting Address", u"0x%08X%08Xk",
					start.h, start.l);
				pr_attr(u"Ending Address", u"0x%08X%08Xk",
					end.h, end.l);
				dmi_mapped_address_extended_size(start, end);
			}
			else
			{
				pr_attr(u"Starting Address", u"0x%08X%03X",
					DWORD(data + 0x04) >> 2,
					(DWORD(data + 0x04) & 0x3) << 10);
				pr_attr(u"Ending Address", u"0x%08X%03X",
					DWORD(data + 0x08) >> 2,
					((DWORD(data + 0x08) & 0x3) << 10) + 0x3FF);
				dmi_mapped_address_size(DWORD(data + 0x08) - DWORD(data + 0x04) + 1);
			}
			if (!(opt.flags & FLAG_QUIET))
			{
				pr_attr(u"Physical Device Handle", u"0x%04X",
					WORD(data + 0x0C));
				pr_attr(u"Memory Array Mapped Address Handle", u"0x%04X",
					WORD(data + 0x0E));
			}
			dmi_mapped_address_row_position(data[0x10]);
			dmi_mapped_address_interleave_position(data[0x11]);
			dmi_mapped_address_interleaved_data_depth(data[0x12]);
			break;

		case 21: /* 7.22 Built-in Pointing Device */
			pr_handle_name(u"Built-in Pointing Device");
			if (h->length < 0x07) break;
			pr_attr(u"Type", u"%s",
				dmi_pointing_device_type(data[0x04]));
			pr_attr(u"Interface", u"%s",
				dmi_pointing_device_interface(data[0x05]));
			pr_attr(u"Buttons", u"%u",
				data[0x06]);
			break;

		case 22: /* 7.23 Portable Battery */
			pr_handle_name(u"Portable Battery");
			if (h->length < 0x10) break;
			pr_attr(u"Location", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Manufacturer", u"%s",
				dmi_string(h, data[0x05]));
			if (data[0x06] || h->length < 0x1A)
				pr_attr(u"Manufacture Date", u"%s",
					dmi_string(h, data[0x06]));
			if (data[0x07] || h->length < 0x1A)
				pr_attr(u"Serial Number", u"%s",
					dmi_string(h, data[0x07]));
			pr_attr(u"Name", u"%s",
				dmi_string(h, data[0x08]));
			if (data[0x09] != 0x02 || h->length < 0x1A)
				pr_attr(u"Chemistry", u"%s",
					dmi_battery_chemistry(data[0x09]));
			if (h->length < 0x16)
				dmi_battery_capacity(WORD(data + 0x0A), 1);
			else
				dmi_battery_capacity(WORD(data + 0x0A), data[0x15]);
			dmi_battery_voltage(WORD(data + 0x0C));
			pr_attr(u"SBDS Version", u"%s",
				dmi_string(h, data[0x0E]));
			dmi_battery_maximum_error(data[0x0F]);
			if (h->length < 0x1A) break;
			if (data[0x07] == 0)
				pr_attr(u"SBDS Serial Number", u"%04X",
					WORD(data + 0x10));
			if (data[0x06] == 0)
				pr_attr(u"SBDS Manufacture Date", u"%u-%02u-%02u",
					1980 + (WORD(data + 0x12) >> 9),
					(WORD(data + 0x12) >> 5) & 0x0F,
					WORD(data + 0x12) & 0x1F);
			if (data[0x09] == 0x02)
				pr_attr(u"SBDS Chemistry", u"%s",
					dmi_string(h, data[0x14]));
			pr_attr(u"OEM-specific Information", u"0x%08X",
				DWORD(data + 0x16));
			break;

		case 23: /* 7.24 System Reset */
			pr_handle_name(u"System Reset");
			if (h->length < 0x0D) break;
			pr_attr(u"Status", u"%s",
				data[0x04] & (1 << 0) ? u"Enabled" : u"Disabled");
			pr_attr(u"Watchdog Timer", u"%s",
				data[0x04] & (1 << 5) ? u"Present" : u"Not Present");
			if (!(data[0x04] & (1 << 5)))
				break;
			pr_attr(u"Boot Option", u"%s",
				dmi_system_reset_boot_option((data[0x04] >> 1) & 0x3));
			pr_attr(u"Boot Option On Limit", u"%s",
				dmi_system_reset_boot_option((data[0x04] >> 3) & 0x3));
			dmi_system_reset_count(u"Reset Count", WORD(data + 0x05));
			dmi_system_reset_count(u"Reset Limit", WORD(data + 0x07));
			dmi_system_reset_timer(u"Timer Interval", WORD(data + 0x09));
			dmi_system_reset_timer(u"Timeout", WORD(data + 0x0B));
			break;

		case 24: /* 7.25 Hardware Security */
			pr_handle_name(u"Hardware Security");
			if (h->length < 0x05) break;
			pr_attr(u"Power-On Password Status", u"%s",
				dmi_hardware_security_status(data[0x04] >> 6));
			pr_attr(u"Keyboard Password Status", u"%s",
				dmi_hardware_security_status((data[0x04] >> 4) & 0x3));
			pr_attr(u"Administrator Password Status", u"%s",
				dmi_hardware_security_status((data[0x04] >> 2) & 0x3));
			pr_attr(u"Front Panel Reset Status", u"%s",
				dmi_hardware_security_status(data[0x04] & 0x3));
			break;

		case 25: /* 7.26 System Power Controls */
			pr_handle_name(u"System Power Controls");
			if (h->length < 0x09) break;
			dmi_power_controls_power_on(data + 0x04);
			break;

		case 26: /* 7.27 Voltage Probe */
			pr_handle_name(u"Voltage Probe");
			if (h->length < 0x14) break;
			pr_attr(u"Description", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Location", u"%s",
				dmi_voltage_probe_location(data[0x05] & 0x1f));
			pr_attr(u"Status", u"%s",
				dmi_probe_status(data[0x05] >> 5));
			dmi_voltage_probe_value(u"Maximum Value", WORD(data + 0x06));
			dmi_voltage_probe_value(u"Minimum Value", WORD(data + 0x08));
			dmi_voltage_probe_resolution(WORD(data + 0x0A));
			dmi_voltage_probe_value(u"Tolerance", WORD(data + 0x0C));
			dmi_probe_accuracy(WORD(data + 0x0E));
			pr_attr(u"OEM-specific Information", u"0x%08X",
				DWORD(data + 0x10));
			if (h->length < 0x16) break;
			dmi_voltage_probe_value(u"Nominal Value", WORD(data + 0x14));
			break;

		case 27: /* 7.28 Cooling Device */
			pr_handle_name(u"Cooling Device");
			if (h->length < 0x0C) break;
			if (!(opt.flags & FLAG_QUIET) && WORD(data + 0x04) != 0xFFFF)
				pr_attr(u"Temperature Probe Handle", u"0x%04X",
					WORD(data + 0x04));
			pr_attr(u"Type", u"%s",
				dmi_cooling_device_type(data[0x06] & 0x1f));
			pr_attr(u"Status", u"%s",
				dmi_probe_status(data[0x06] >> 5));
			if (data[0x07] != 0x00)
				pr_attr(u"Cooling Unit Group", u"%u",
					data[0x07]);
			pr_attr(u"OEM-specific Information", u"0x%08X",
				DWORD(data + 0x08));
			if (h->length < 0x0E) break;
			dmi_cooling_device_speed(WORD(data + 0x0C));
			if (h->length < 0x0F) break;
			pr_attr(u"Description", u"%s", dmi_string(h, data[0x0E]));
			break;

		case 28: /* 7.29 Temperature Probe */
			pr_handle_name(u"Temperature Probe");
			if (h->length < 0x14) break;
			pr_attr(u"Description", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Location", u"%s",
				dmi_temperature_probe_location(data[0x05] & 0x1F));
			pr_attr(u"Status", u"%s",
				dmi_probe_status(data[0x05] >> 5));
			dmi_temperature_probe_value(u"Maximum Value",
						    WORD(data + 0x06));
			dmi_temperature_probe_value(u"Minimum Value",
						    WORD(data + 0x08));
			dmi_temperature_probe_resolution(WORD(data + 0x0A));
			dmi_temperature_probe_value(u"Tolerance",
						    WORD(data + 0x0C));
			dmi_probe_accuracy(WORD(data + 0x0E));
			pr_attr(u"OEM-specific Information", u"0x%08X",
				DWORD(data + 0x10));
			if (h->length < 0x16) break;
			dmi_temperature_probe_value(u"Nominal Value",
						    WORD(data + 0x14));
			break;

		case 29: /* 7.30 Electrical Current Probe */
			pr_handle_name(u"Electrical Current Probe");
			if (h->length < 0x14) break;
			pr_attr(u"Description", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Location", u"%s",
				dmi_voltage_probe_location(data[5] & 0x1F));
			pr_attr(u"Status", u"%s",
				dmi_probe_status(data[0x05] >> 5));
			dmi_current_probe_value(u"Maximum Value",
						WORD(data + 0x06));
			dmi_current_probe_value(u"Minimum Value",
						WORD(data + 0x08));
			dmi_current_probe_resolution(WORD(data + 0x0A));
			dmi_current_probe_value(u"Tolerance",
						WORD(data + 0x0C));
			dmi_probe_accuracy(WORD(data + 0x0E));
			pr_attr(u"OEM-specific Information", u"0x%08X",
				DWORD(data + 0x10));
			if (h->length < 0x16) break;
			dmi_current_probe_value(u"Nominal Value",
						WORD(data + 0x14));
			break;

		case 30: /* 7.31 Out-of-band Remote Access */
			pr_handle_name(u"Out-of-band Remote Access");
			if (h->length < 0x06) break;
			pr_attr(u"Manufacturer Name", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Inbound Connection", u"%s",
				data[0x05] & (1 << 0) ? u"Enabled" : u"Disabled");
			pr_attr(u"Outbound Connection", u"%s",
				data[0x05] & (1 << 1) ? u"Enabled" : u"Disabled");
			break;

		case 31: /* 7.32 Boot Integrity Services Entry Point */
			pr_handle_name(u"Boot Integrity Services Entry Point");
			if (h->length < 0x1C) break;
			pr_attr(u"Checksum", u"%s",
				checksum(data, h->length) ? u"OK" : u"Invalid");
			pr_attr(u"16-bit Entry Point Address", u"%04X:%04X",
				DWORD(data + 0x08) >> 16,
				DWORD(data + 0x08) & 0xFFFF);
			pr_attr(u"32-bit Entry Point Address", u"0x%08X",
				DWORD(data + 0x0C));
			break;

		case 32: /* 7.33 System Boot Information */
			pr_handle_name(u"System Boot Information");
			if (h->length < 0x0B) break;
			pr_attr(u"Status", u"%s",
				dmi_system_boot_status(data[0x0A]));
			break;

		case 33: /* 7.34 64-bit Memory Error Information */
			pr_handle_name(u"64-bit Memory Error Information");
			if (h->length < 0x1F) break;
			pr_attr(u"Type", u"%s",
				dmi_memory_error_type(data[0x04]));
			pr_attr(u"Granularity", u"%s",
				dmi_memory_error_granularity(data[0x05]));
			pr_attr(u"Operation", u"%s",
				dmi_memory_error_operation(data[0x06]));
			dmi_memory_error_syndrome(DWORD(data + 0x07));
			dmi_64bit_memory_error_address(u"Memory Array Address",
						       QWORD(data + 0x0B));
			dmi_64bit_memory_error_address(u"Device Address",
						       QWORD(data + 0x13));
			dmi_32bit_memory_error_address(u"Resolution",
						       DWORD(data + 0x1B));
			break;

		case 34: /* 7.35 Management Device */
			pr_handle_name(u"Management Device");
			if (h->length < 0x0B) break;
			pr_attr(u"Description", u"%s",
				dmi_string(h, data[0x04]));
			pr_attr(u"Type", u"%s",
				dmi_management_device_type(data[0x05]));
			pr_attr(u"Address", u"0x%08X",
				DWORD(data + 0x06));
			pr_attr(u"Address Type", u"%s",
				dmi_management_device_address_type(data[0x0A]));
			break;

		case 35: /* 7.36 Management Device Component */
			pr_handle_name(u"Management Device Component");
			if (h->length < 0x0B) break;
			pr_attr(u"Description", u"%s",
				dmi_string(h, data[0x04]));
			if (!(opt.flags & FLAG_QUIET))
			{
				pr_attr(u"Management Device Handle", u"0x%04X",
					WORD(data + 0x05));
				pr_attr(u"Component Handle", u"0x%04X",
					WORD(data + 0x07));
				if (WORD(data + 0x09) != 0xFFFF)
					pr_attr(u"Threshold Handle", u"0x%04X",
						WORD(data + 0x09));
			}
			break;

		case 36: /* 7.37 Management Device Threshold Data */
			pr_handle_name(u"Management Device Threshold Data");
			if (h->length < 0x10) break;
			if (WORD(data + 0x04) != 0x8000)
				pr_attr(u"Lower Non-critical Threshold", u"%d",
					(i16)WORD(data + 0x04));
			if (WORD(data + 0x06) != 0x8000)
				pr_attr(u"Upper Non-critical Threshold", u"%d",
					(i16)WORD(data + 0x06));
			if (WORD(data + 0x08) != 0x8000)
				pr_attr(u"Lower Critical Threshold", u"%d",
					(i16)WORD(data + 0x08));
			if (WORD(data + 0x0A) != 0x8000)
				pr_attr(u"Upper Critical Threshold", u"%d",
					(i16)WORD(data + 0x0A));
			if (WORD(data + 0x0C) != 0x8000)
				pr_attr(u"Lower Non-recoverable Threshold", u"%d",
					(i16)WORD(data + 0x0C));
			if (WORD(data + 0x0E) != 0x8000)
				pr_attr(u"Upper Non-recoverable Threshold", u"%d",
					(i16)WORD(data + 0x0E));
			break;

		case 37: /* 7.38 Memory Channel */
			pr_handle_name(u"Memory Channel");
			if (h->length < 0x07) break;
			pr_attr(u"Type", u"%s",
				dmi_memory_channel_type(data[0x04]));
			pr_attr(u"Maximal Load", u"%u",
				data[0x05]);
			pr_attr(u"Devices", u"%u",
				data[0x06]);
			if (h->length < 0x07 + 3 * data[0x06]) break;
			dmi_memory_channel_devices(data[0x06], data + 0x07);
			break;

		case 38: /* 7.39 IPMI Device Information */
			/*
			 * We use the word u"Version" instead of u"Revision", conforming to
			 * the IPMI specification.
			 */
			pr_handle_name(u"IPMI Device Information");
			if (h->length < 0x10) break;
			pr_attr(u"Interface Type", u"%s",
				dmi_ipmi_interface_type(data[0x04]));
			pr_attr(u"Specification Version", u"%u.%u",
				data[0x05] >> 4, data[0x05] & 0x0F);
			pr_attr(u"I2C Slave Address", u"0x%02x",
				data[0x06] >> 1);
			if (data[0x07] != 0xFF)
				pr_attr(u"NV Storage Device Address", u"%u",
					data[0x07]);
			else
				pr_attr(u"NV Storage Device", u"Not Present");
			dmi_ipmi_base_address(data[0x04], data + 0x08,
				h->length < 0x11 ? 0 : (data[0x10] >> 4) & 1);
			if (h->length < 0x12) break;
			if (data[0x04] != 0x04)
			{
				pr_attr(u"Register Spacing", u"%s",
					dmi_ipmi_register_spacing(data[0x10] >> 6));
				if (data[0x10] & (1 << 3))
				{
					pr_attr(u"Interrupt Polarity", u"%s",
						data[0x10] & (1 << 1) ? u"Active High" : u"Active Low");
					pr_attr(u"Interrupt Trigger Mode", u"%s",
						data[0x10] & (1 << 0) ? u"Level" : u"Edge");
				}
			}
			if (data[0x11] != 0x00)
			{
				pr_attr(u"Interrupt Number", u"%u",
					data[0x11]);
			}
			break;

		case 39: /* 7.40 System Power Supply */
			pr_handle_name(u"System Power Supply");
			if (h->length < 0x10) break;
			if (data[0x04] != 0x00)
				pr_attr(u"Power Unit Group", u"%u",
					data[0x04]);
			pr_attr(u"Location", u"%s",
				dmi_string(h, data[0x05]));
			pr_attr(u"Name", u"%s",
				dmi_string(h, data[0x06]));
			pr_attr(u"Manufacturer", u"%s",
				dmi_string(h, data[0x07]));
			pr_attr(u"Serial Number", u"%s",
				dmi_string(h, data[0x08]));
			pr_attr(u"Asset Tag", u"%s",
				dmi_string(h, data[0x09]));
			pr_attr(u"Model Part Number", u"%s",
				dmi_string(h, data[0x0A]));
			pr_attr(u"Revision", u"%s",
				dmi_string(h, data[0x0B]));
			dmi_power_supply_power(WORD(data + 0x0C));
			if (WORD(data + 0x0E) & (1 << 1))
				pr_attr(u"Status", u"Present, %s",
					dmi_power_supply_status((WORD(data + 0x0E) >> 7) & 0x07));
			else
				pr_attr(u"Status", u"Not Present");
			pr_attr(u"Type", u"%s",
				dmi_power_supply_type((WORD(data + 0x0E) >> 10) & 0x0F));
			pr_attr(u"Input Voltage Range Switching", u"%s",
				dmi_power_supply_range_switching((WORD(data + 0x0E) >> 3) & 0x0F));
			pr_attr(u"Plugged", u"%s",
				WORD(data + 0x0E) & (1 << 2) ? u"No" : u"Yes");
			pr_attr(u"Hot Replaceable", u"%s",
				WORD(data + 0x0E) & (1 << 0) ? u"Yes" : u"No");
			if (h->length < 0x16) break;
			if (!(opt.flags & FLAG_QUIET))
			{
				if (WORD(data + 0x10) != 0xFFFF)
					pr_attr(u"Input Voltage Probe Handle", u"0x%04X",
						WORD(data + 0x10));
				if (WORD(data + 0x12) != 0xFFFF)
					pr_attr(u"Cooling Device Handle", u"0x%04X",
						WORD(data + 0x12));
				if (WORD(data + 0x14) != 0xFFFF)
					pr_attr(u"Input Current Probe Handle", u"0x%04X",
						WORD(data + 0x14));
			}
			break;

		case 40: /* 7.41 Additional Information */
			if (h->length < 0x0B) break;
			if (opt.flags & FLAG_QUIET)
				return;
			dmi_additional_info(h);
			break;

		case 41: /* 7.42 Onboard Device Extended Information */
			pr_handle_name(u"Onboard Device");
			if (h->length < 0x0B) break;
			pr_attr(u"Reference Designation", u"%s", dmi_string(h, data[0x04]));
			pr_attr(u"Type", u"%s",
				dmi_on_board_devices_type(data[0x05] & 0x7F));
			pr_attr(u"Status", u"%s",
				data[0x05] & 0x80 ? u"Enabled" : u"Disabled");
			pr_attr(u"Type Instance", u"%u", data[0x06]);
			dmi_slot_segment_bus_func(WORD(data + 0x07), data[0x09], data[0x0A]);
			break;

		case 42: /* 7.43 Management Controller Host Interface */
			pr_handle_name(u"Management Controller Host Interface");
			if (ver < 0x0302)
			{
				if (h->length < 0x05) break;
				pr_attr(u"Interface Type", u"%s",
					dmi_management_controller_host_type(data[0x04]));
				/*
				 * There you have a type-dependent, variable-length
				 * part in the middle of the structure, with no
				 * length specifier, so no easy way to decode the
				 * common, final part of the structure. What a pity.
				 */
				if (h->length < 0x09) break;
				if (data[0x04] == 0xF0)		/* OEM */
				{
					pr_attr(u"Vendor ID", u"0x%02X%02X%02X%02X",
						data[0x05], data[0x06], data[0x07],
						data[0x08]);
				}
			}
			else
				dmi_parse_controller_structure(h);
			break;

		case 43: /* 7.44 TPM Device */
			pr_handle_name(u"TPM Device");
			if (h->length < 0x1B) break;
			dmi_tpm_vendor_id(data + 0x04);
			pr_attr(u"Specification Version", u"%d.%d", data[0x08], data[0x09]);
			switch (data[0x08])
			{
				case 0x01:
					/*
					 * We skip the first 2 bytes, which are
					 * redundant with the above, and uncoded
					 * in a silly way.
					 */
					pr_attr(u"Firmware Revision", u"%u.%u",
						data[0x0C], data[0x0D]);
					break;
				case 0x02:
					pr_attr(u"Firmware Revision", u"%u.%u",
						DWORD(data + 0x0A) >> 16,
						DWORD(data + 0x0A) & 0xFFFF);
					/*
					 * We skip the next 4 bytes, as their
					 * format is not standardized and their
					 * usefulness seems limited anyway.
					 */
					break;
			}
			pr_attr(u"Description", u"%s", dmi_string(h, data[0x12]));
			pr_list_start(u"Characteristics", NULL);
			dmi_tpm_characteristics(QWORD(data + 0x13));
			pr_list_end();
			if (h->length < 0x1F) break;
			pr_attr(u"OEM-specific Information", u"0x%08X",
				DWORD(data + 0x1B));
			break;

		case 126: /* 7.44 Inactive */
			pr_handle_name(u"Inactive");
			break;

		case 127: /* 7.45 End Of Table */
			pr_handle_name(u"End Of Table");
			break;

		default:
			if (dmi_decode_oem(h))
				break;
			if (opt.flags & FLAG_QUIET)
				return;
			pr_handle_name(u"%s Type",
				h->type >= 128 ? u"OEM-specific" : u"Unknown");
			dmi_dump(h);
	}
	pr_sep();
}

static void to_dmi_header(struct dmi_header *h, u8 *data)
{
	h->type = data[0];
	h->length = data[1];
	h->handle = WORD(data + 2);
	h->data = data;
}

static void dmi_table_string(const struct dmi_header *h, const u8 *data, u16 ver)
{
	int key;
	u8 offset = opt.string->offset;

	if (opt.string->type == 11) /* OEM strings */
	{
		if (h->length < 5 || offset > data[4])
		{
			printf(u"No OEM string number %u\n", offset);
			return;
		}

		if (offset)
			printf(u"%s\n", dmi_string(h, offset));
		else
			printf(u"%u\n", data[4]);	/* count */
		return;
	}

	if (offset >= h->length)
		return;

	key = (opt.string->type << 8) | offset;
	switch (key)
	{
		case 0x015: /* -s bios-revision */
			if (data[key - 1] != 0xFF && data[key] != 0xFF)
				printf(u"%u.%u\n", data[key - 1], data[key]);
			break;
		case 0x017: /* -s firmware-revision */
			if (data[key - 1] != 0xFF && data[key] != 0xFF)
				printf(u"%u.%u\n", data[key - 1], data[key]);
			break;
		case 0x108:
			dmi_system_uuid(NULL, NULL, data + offset, ver);
			break;
		case 0x305:
			printf(u"%s\n", dmi_chassis_type(data[offset]));
			break;
		case 0x406:
			printf(u"%s\n", dmi_processor_family(h, ver));
			break;
		case 0x416:
			dmi_processor_frequency(NULL, data + offset);
			break;
		default:
			printf(u"%s\n", dmi_string(h, data[offset]));
	}
}

static void dmi_table_dump(const u8 *buf, u32 len)
{
	if (!(opt.flags & FLAG_QUIET))
		pr_comment(u"Writing %d bytes to %s.", len, opt.dumpfile);
	write_dump(32, len, buf, opt.dumpfile, 0);
}

static void dmi_table_decode(u8 *buf, u32 len, u16 num, u16 ver, u32 flags)
{
	u8 *data;
	int i = 0;

	/* First pass: Save the vendor so that so that we can decode OEM types */
	data = buf;
	while ((i < num || !num)
	    && data + 4 <= buf + len) /* 4 is the length of an SMBIOS structure header */
	{
		u8 *next;
		struct dmi_header h;

		to_dmi_header(&h, data);

		/*
		 * If a short entry is found (less than 4 bytes), not only it
		 * is invalid, but we cannot reliably locate the next entry.
		 * Also stop at end-of-table marker if so instructed.
		 */
		if (h.length < 4 ||
		    (h.type == 127 &&
		     (opt.flags & (FLAG_QUIET | FLAG_STOP_AT_EOT))))
			break;
		i++;

		/* Look for the next handle */
		next = data + h.length;
		while ((unsigned long)(next - buf + 1) < len
		    && (next[0] != 0 || next[1] != 0))
			next++;
		next += 2;

		/* Make sure the whole structure fits in the table */
		if ((unsigned long)(next - buf) > len)
			break;

		/* Assign vendor for vendor-specific decodes later */
		if (h.type == 1 && h.length >= 6)
		{
			dmi_set_vendor(_dmi_string(&h, data[0x04], 0),
				       _dmi_string(&h, data[0x05], 0));
			break;
		}

		data = next;
	}

	/* Second pass: Actually decode the data */
	i = 0;
	data = buf;
	while ((i < num || !num)
	    && data + 4 <= buf + len) /* 4 is the length of an SMBIOS structure header */
	{
		u8 *next;
		struct dmi_header h;
		int display;

		to_dmi_header(&h, data);
		display = ((opt.type == NULL || opt.type[h.type])
			&& (opt.handle == ~0U || opt.handle == h.handle)
			&& !((opt.flags & FLAG_QUIET) && (h.type == 126 || h.type == 127))
			&& !opt.string);

		/*
		 * If a short entry is found (less than 4 bytes), not only it
		 * is invalid, but we cannot reliably locate the next entry.
		 * Better stop at this point, and let the user know his/her
		 * table is broken.
		 */
		if (h.length < 4)
		{
			if (!(opt.flags & FLAG_QUIET))
			{
				printf(u"Invalid entry length (%u). DMI table "
					u"is broken! Stop.\n\n",
					(unsigned int)h.length);
				opt.flags |= FLAG_QUIET;
			}
			break;
		}
		i++;

		/* In quiet mode, stop decoding at end of table marker */
		if ((opt.flags & FLAG_QUIET) && h.type == 127)
			break;

		if (display
		 && (!(opt.flags & FLAG_QUIET) || (opt.flags & FLAG_DUMP)))
			pr_handle(&h);

		/* Look for the next handle */
		next = data + h.length;
		while ((unsigned long)(next - buf + 1) < len
		    && (next[0] != 0 || next[1] != 0))
			next++;
		next += 2;

		/* Make sure the whole structure fits in the table */
		if ((unsigned long)(next - buf) > len)
		{
			if (display && !(opt.flags & FLAG_QUIET))
				pr_struct_err(u"<TRUNCATED>");
			pr_sep();
			data = next;
			break;
		}

		/* Fixup a common mistake */
		if (h.type == 34)
			dmi_fixup_type_34(&h, display);

		if (display)
		{
			if (opt.flags & FLAG_DUMP)
			{
				dmi_dump(&h);
				pr_sep();
			}
			else
				dmi_decode(&h, ver);
		}
		else if (opt.string != NULL
		      && opt.string->type == h.type)
			dmi_table_string(&h, data, ver);

		data = next;

		/* SMBIOS v3 requires stopping at this marker */
		if (h.type == 127 && (flags & FLAG_STOP_AT_EOT))
			break;
	}

	/*
	 * SMBIOS v3 64-bit entry points do not announce a structures count,
	 * and only indicate a maximum size for the table.
	 */
	if (!(opt.flags & FLAG_QUIET))
	{
		if (num && i != num)
			printf(u"Wrong DMI structures count: %d announced, "
				u"only %d decoded.\n", num, i);
		if ((unsigned long)(data - buf) > len
		 || (num && (unsigned long)(data - buf) < len))
			printf(u"Wrong DMI structures length: %u bytes "
				u"announced, structures occupy %lu bytes.\n",
				len, (unsigned long)(data - buf));
	}
}

static void dmi_table(off_t base, u32 len, u16 num, u32 ver, const char *devmem,
		      u32 flags)
{
	u8 *buf;

	if (ver > SUPPORTED_SMBIOS_VER && !(opt.flags & FLAG_QUIET))
	{
		pr_comment(u"SMBIOS implementations newer than version %u.%u.%u are not",
			   SUPPORTED_SMBIOS_VER >> 16,
			   (SUPPORTED_SMBIOS_VER >> 8) & 0xFF,
			   SUPPORTED_SMBIOS_VER & 0xFF);
		pr_comment(u"fully supported by this version of dmidecode.");
	}

	if (!(opt.flags & FLAG_QUIET))
	{
		if (opt.type == NULL)
		{
			if (num)
				pr_info(u"%u structures occupying %u bytes.",
					num, len);
			if (!(opt.flags & FLAG_FROM_DUMP))
				pr_info(u"Table at 0x%08llX.",
					(unsigned long long)base);
		}
		pr_sep();
	}

	if ((flags & FLAG_NO_FILE_OFFSET) || (opt.flags & FLAG_FROM_DUMP))
	{
		/*
		 * When reading from sysfs or from a dump file, the file may be
		 * shorter than announced. For SMBIOS v3 this is expcted, as we
		 * only know the maximum table size, not the actual table size.
		 * For older implementations (and for SMBIOS v3 too), this
		 * would be the result of the kernel truncating the table on
		 * parse error.
		 */
		size_t size = len;
		buf = read_file(flags & FLAG_NO_FILE_OFFSET ? 0 : base,
			&size, devmem);
		if (!(opt.flags & FLAG_QUIET) && num && size != (size_t)len)
		{
			printf(u"Wrong DMI structures length: %u bytes "
				u"announced, only %lu bytes available.\n",
				len, (unsigned long)size);
		}
		len = size;
	}
	else
		buf = mem_chunk(base, len, devmem);

	if (buf == NULL)
	{
		printf(u"Failed to read table, sorry.\n");
#ifndef USE_MMAP
		if (!(flags & FLAG_NO_FILE_OFFSET))
			printf(u"Try compiling dmidecode with -DUSE_MMAP.\n");
#endif
		return;
	}

	if (opt.flags & FLAG_DUMP_BIN)
		dmi_table_dump(buf, len);
	else
		dmi_table_decode(buf, len, num, ver >> 8, flags);

	free(buf);
}


/*
 * Build a crafted entry point with table address hard-coded to 32,
 * as this is where we will put it in the output file. We adjust the
 * DMI checksum appropriately. The SMBIOS checksum needs no adjustment.
 */
static void overwrite_dmi_address(u8 *buf)
{
	buf[0x05] += buf[0x08] + buf[0x09] + buf[0x0A] + buf[0x0B] - 32;
	buf[0x08] = 32;
	buf[0x09] = 0;
	buf[0x0A] = 0;
	buf[0x0B] = 0;
}

/* Same thing for SMBIOS3 entry points */
static void overwrite_smbios3_address(u8 *buf)
{
	buf[0x05] += buf[0x10] + buf[0x11] + buf[0x12] + buf[0x13]
		   + buf[0x14] + buf[0x15] + buf[0x16] + buf[0x17] - 32;
	buf[0x10] = 32;
	buf[0x11] = 0;
	buf[0x12] = 0;
	buf[0x13] = 0;
	buf[0x14] = 0;
	buf[0x15] = 0;
	buf[0x16] = 0;
	buf[0x17] = 0;
}

static int smbios3_decode(u8 *buf, const char *devmem, u32 flags)
{
	u32 ver;
	u64 offset;

	/* Don't let checksum run beyond the buffer */
	if (buf[0x06] > 0x20)
	{
		printf(u"Entry point length too large (%u bytes, expected %u).\n",
			(unsigned int)buf[0x06], 0x18U);
		return 0;
	}

	if (!checksum(buf, buf[0x06]))
		return 0;

	ver = (buf[0x07] << 16) + (buf[0x08] << 8) + buf[0x09];
	if (!(opt.flags & FLAG_QUIET))
		pr_info(u"SMBIOS %u.%u.%u present.",
			buf[0x07], buf[0x08], buf[0x09]);

	offset = QWORD(buf + 0x10);
	if (!(flags & FLAG_NO_FILE_OFFSET) && offset.h && sizeof(off_t) < 8)
	{
		printf(u"64-bit addresses not supported, sorry.\n");
		return 0;
	}

	dmi_table(((off_t)offset.h << 32) | offset.l,
		  DWORD(buf + 0x0C), 0, ver, devmem, flags | FLAG_STOP_AT_EOT);

	if (opt.flags & FLAG_DUMP_BIN)
	{
		u8 crafted[32];

		memcpy(crafted, buf, 32);
		overwrite_smbios3_address(crafted);

		if (!(opt.flags & FLAG_QUIET))
			pr_comment(u"Writing %d bytes to %s.", crafted[0x06],
				   opt.dumpfile);
		write_dump(0, crafted[0x06], crafted, opt.dumpfile, 1);
	}

	return 1;
}

static int smbios_decode(u8 *buf, const char *devmem, u32 flags)
{
	u16 ver;

	/* Don't let checksum run beyond the buffer */
	if (buf[0x05] > 0x20)
	{
		printf(u"Entry point length too large (%u bytes, expected %u).\n",
			(unsigned int)buf[0x05], 0x1FU);
		return 0;
	}

	if (!checksum(buf, buf[0x05])
	 || memcmp(buf + 0x10, u"_DMI_", 5) != 0
	 || !checksum(buf + 0x10, 0x0F))
		return 0;

	ver = (buf[0x06] << 8) + buf[0x07];
	/* Some BIOS report weird SMBIOS version, fix that up */
	switch (ver)
	{
		case 0x021F:
		case 0x0221:
			if (!(opt.flags & FLAG_QUIET))
				printf(u"SMBIOS version fixup (2.%d -> 2.%d).\n",
					ver & 0xFF, 3);
			ver = 0x0203;
			break;
		case 0x0233:
			if (!(opt.flags & FLAG_QUIET))
				printf(u"SMBIOS version fixup (2.%d -> 2.%d).\n",
					51, 6);
			ver = 0x0206;
			break;
	}
	if (!(opt.flags & FLAG_QUIET))
		pr_info(u"SMBIOS %u.%u present.",
			ver >> 8, ver & 0xFF);

	dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C),
		ver << 8, devmem, flags);

	if (opt.flags & FLAG_DUMP_BIN)
	{
		u8 crafted[32];

		memcpy(crafted, buf, 32);
		overwrite_dmi_address(crafted + 0x10);

		if (!(opt.flags & FLAG_QUIET))
			pr_comment(u"Writing %d bytes to %s.", crafted[0x05],
				   opt.dumpfile);
		write_dump(0, crafted[0x05], crafted, opt.dumpfile, 1);
	}

	return 1;
}

static int legacy_decode(u8 *buf, const char *devmem, u32 flags)
{
	if (!checksum(buf, 0x0F))
		return 0;

	if (!(opt.flags & FLAG_QUIET))
		pr_info(u"Legacy DMI %u.%u present.",
			buf[0x0E] >> 4, buf[0x0E] & 0x0F);

	dmi_table(DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
		((buf[0x0E] & 0xF0) << 12) + ((buf[0x0E] & 0x0F) << 8),
		devmem, flags);

	if (opt.flags & FLAG_DUMP_BIN)
	{
		u8 crafted[16];

		memcpy(crafted, buf, 16);
		overwrite_dmi_address(crafted);

		if (!(opt.flags & FLAG_QUIET))
			pr_comment(u"Writing %d bytes to %s.", 0x0F,
				   opt.dumpfile);
		write_dump(0, 0x0F, crafted, opt.dumpfile, 1);
	}

	return 1;
}

/*
 * Probe for EFI interface
 */
#define EFI_NOT_FOUND   (-1)
#define EFI_NO_SMBIOS   (-2)
static int address_from_efi(off_t *address)
{
#if defined(__linux__)
	FILE *efi_systab;
	const char *filename;
	char linebuf[64];
#elif defined(__FreeBSD__)
	char addrstr[KENV_MVALLEN + 1];
#endif
	const char *eptype;
	int ret;

	*address = 0; /* Prevent compiler warning */

#if defined(__linux__)
	/*
	 * Linux up to 2.6.6: /proc/efi/systab
	 * Linux 2.6.7 and up: /sys/firmware/efi/systab
	 */
	if ((efi_systab = fopen(filename = u"/sys/firmware/efi/systab", u"r")) == NULL
	 && (efi_systab = fopen(filename = u"/proc/efi/systab", u"r")) == NULL)
	{
		/* No EFI interface, fallback to memory scan */
		return EFI_NOT_FOUND;
	}
	ret = EFI_NO_SMBIOS;
	while ((fgets(linebuf, sizeof(linebuf) - 1, efi_systab)) != NULL)
	{
		char *addrp = strchr(linebuf, '=');
		*(addrp++) = '\0';
		if (strcmp(linebuf, u"SMBIOS3") == 0
		 || strcmp(linebuf, u"SMBIOS") == 0)
		{
			*address = strtoull(addrp, NULL, 0);
			eptype = linebuf;
			ret = 0;
			break;
		}
	}
	if (fclose(efi_systab) != 0)
		perror(filename);

	if (ret == EFI_NO_SMBIOS)
		printf(u"%s: SMBIOS entry point missing\n", filename);
#elif defined(__FreeBSD__)
	/*
	 * On FreeBSD, SMBIOS anchor base address in UEFI mode is exposed
	 * via kernel environment:
	 * https://svnweb.freebsd.org/base?view=revision&revision=307326
	 */
	ret = kenv(KENV_GET, u"hint.smbios.0.mem", addrstr, sizeof(addrstr));
	if (ret == -1)
	{
		if (errno != ENOENT)
			perror(u"kenv");
		return EFI_NOT_FOUND;
	}

	*address = strtoull(addrstr, NULL, 0);
	eptype = u"SMBIOS";
	ret = 0;
#else
	ret = EFI_NOT_FOUND;
#endif

	if (ret == 0 && !(opt.flags & FLAG_QUIET))
		pr_comment(u"%s entry point at 0x%08llx",
			   eptype, (unsigned long long)*address);

	return ret;
}

int main(int argc, char * const argv[])
{
	int ret = 0;                /* Returned value */
	int found = 0;
	off_t fp;
	size_t size;
	int efi;
	u8 *buf = NULL;

	/* Set default option values */
	opt.devmem = DEFAULT_MEM_DEV;
	opt.flags = 0;
	opt.handle = ~0U;

	if (parse_command_line(argc, argv)<0)
	{
		ret = 2;
		goto exit_free;
	}

	if (opt.flags & FLAG_HELP)
	{
		print_help();
		goto exit_free;
	}

	if (opt.flags & FLAG_VERSION)
	{
		printf(u"%s\n", VERSION);
		goto exit_free;
	}

	if (!(opt.flags & FLAG_QUIET))
		pr_comment(u"dmidecode %s", VERSION);

	/* Read from dump if so instructed */
	if (opt.flags & FLAG_FROM_DUMP)
	{
		if (!(opt.flags & FLAG_QUIET))
			pr_info(u"Reading SMBIOS/DMI data from file %s.",
				opt.dumpfile);
		if ((buf = mem_chunk(0, 0x20, opt.dumpfile)) == NULL)
		{
			ret = 1;
			goto exit_free;
		}

		if (memcmp(buf, u"_SM3_", 5) == 0)
		{
			if (smbios3_decode(buf, opt.dumpfile, 0))
				found++;
		}
		else if (memcmp(buf, u"_SM_", 4) == 0)
		{
			if (smbios_decode(buf, opt.dumpfile, 0))
				found++;
		}
		else if (memcmp(buf, u"_DMI_", 5) == 0)
		{
			if (legacy_decode(buf, opt.dumpfile, 0))
				found++;
		}
		goto done;
	}

	/*
	 * First try reading from sysfs tables.  The entry point file could
	 * contain one of several types of entry points, so read enough for
	 * the largest one, then determine what type it contains.
	 */
	size = 0x20;
	if (!(opt.flags & FLAG_NO_SYSFS)
	 && (buf = read_file(0, &size, SYS_ENTRY_FILE)) != NULL)
	{
		if (!(opt.flags & FLAG_QUIET))
			pr_info(u"Getting SMBIOS data from sysfs.");
		if (size >= 24 && memcmp(buf, u"_SM3_", 5) == 0)
		{
			if (smbios3_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET))
				found++;
		}
		else if (size >= 31 && memcmp(buf, u"_SM_", 4) == 0)
		{
			if (smbios_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET))
				found++;
		}
		else if (size >= 15 && memcmp(buf, u"_DMI_", 5) == 0)
		{
			if (legacy_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET))
				found++;
		}

		if (found)
			goto done;
		if (!(opt.flags & FLAG_QUIET))
			pr_info(u"Failed to get SMBIOS data from sysfs.");
	}

	/* Next try EFI (ia64, Intel-based Mac, arm64) */
	efi = address_from_efi(&fp);
	switch (efi)
	{
		case EFI_NOT_FOUND:
			goto memory_scan;
		case EFI_NO_SMBIOS:
			ret = 1;
			goto exit_free;
	}

	if (!(opt.flags & FLAG_QUIET))
		pr_info(u"Found SMBIOS entry point in EFI, reading table from %s.",
			opt.devmem);
	if ((buf = mem_chunk(fp, 0x20, opt.devmem)) == NULL)
	{
		ret = 1;
		goto exit_free;
	}

	if (memcmp(buf, u"_SM3_", 5) == 0)
	{
		if (smbios3_decode(buf, opt.devmem, 0))
			found++;
	}
	else if (memcmp(buf, u"_SM_", 4) == 0)
	{
		if (smbios_decode(buf, opt.devmem, 0))
			found++;
	}
	goto done;

memory_scan:
#if defined __i386__ || defined __x86_64__
	if (!(opt.flags & FLAG_QUIET))
		pr_info(u"Scanning %s for entry point.", opt.devmem);
	/* Fallback to memory scan (x86, x86_64) */
	if ((buf = mem_chunk(0xF0000, 0x10000, opt.devmem)) == NULL)
	{
		ret = 1;
		goto exit_free;
	}

	/* Look for a 64-bit entry point first */
	for (fp = 0; fp <= 0xFFE0; fp += 16)
	{
		if (memcmp(buf + fp, u"_SM3_", 5) == 0)
		{
			if (smbios3_decode(buf + fp, opt.devmem, 0))
			{
				found++;
				goto done;
			}
		}
	}

	/* If none found, look for a 32-bit entry point */
	for (fp = 0; fp <= 0xFFF0; fp += 16)
	{
		if (memcmp(buf + fp, u"_SM_", 4) == 0 && fp <= 0xFFE0)
		{
			if (smbios_decode(buf + fp, opt.devmem, 0))
			{
				found++;
				goto done;
			}
		}
		else if (memcmp(buf + fp, u"_DMI_", 5) == 0)
		{
			if (legacy_decode(buf + fp, opt.devmem, 0))
			{
				found++;
				goto done;
			}
		}
	}
#endif

done:
	if (!found && !(opt.flags & FLAG_QUIET))
		pr_comment(u"No SMBIOS nor DMI entry point found, sorry.");

	free(buf);
exit_free:
	free(opt.type);

	return ret;
}
