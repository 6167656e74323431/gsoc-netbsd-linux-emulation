/*	$NetBSD: i2cvar.h,v 1.26 2022/10/24 10:17:27 riastradh Exp $	*/

/*
 * Copyright (c) 2003 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Steve C. Woodford and Jason R. Thorpe for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DEV_I2C_I2CVAR_H_
#define	_DEV_I2C_I2CVAR_H_

#include <sys/device.h>
#include <sys/mutex.h>
#include <dev/i2c/i2c_io.h>
#include <prop/proplib.h>

/* Flags passed to i2c routines. */
#define	I2C_F_WRITE	0		/* new transfer is a write */
#define	I2C_F_READ	__BIT(0)	/* new transfer is a read */
#define	I2C_F_LAST	__BIT(1)	/* last byte of read */
#define	I2C_F_STOP	__BIT(2)	/* send stop after byte */
#define	I2C_F_POLL	__BIT(3)	/* poll, don't sleep */
#define	I2C_F_PEC	__BIT(4)	/* smbus packet error checking */
#define	I2C_F_SPEED	__BITS(28,31)	/* I2C transfer speed selector */

#define	I2C_SPEED_SM		0	/* standard mode (100Kb/s) */
#define	I2C_SPEED_FM		1	/* fast mode (400Kb/s) */
#define	I2C_SPEED_FMPLUS	2	/* fast mode+ (1Mb/s) */
#define	I2C_SPEED_HS		3	/* high speed (3.4Mb/s) */

/* i2c bus instance properties */
#define	I2C_PROP_INDIRECT_PROBE_STRATEGY	\
				"i2c-indirect-probe-strategy"
#define	I2C_PROBE_STRATEGY_QUICK_WRITE		\
				"smbus-quick-write"
#define	I2C_PROBE_STRATEGY_RECEIVE_BYTE		\
				"smbus-receive-byte"
#define	I2C_PROBE_STRATEGY_NONE			\
				"none"

#define	I2C_PROP_INDIRECT_DEVICE_PERMITLIST	\
				"i2c-indirect-device-permitlist"
	/* value is a prop_array of prop_strings */

struct ic_intr_list {
	LIST_ENTRY(ic_intr_list) il_next;
	int (*il_intr)(void *);
	void *il_intrarg;
};

/*
 * This structure provides the interface between the i2c framework
 * and the underlying i2c controller.
 *
 * Note that this structure is designed specifically to allow us
 * to either use the autoconfiguration framework or not.  This
 * allows a driver for a board with a private i2c bus use generic
 * i2c client drivers for chips that might be on that board.
 */
typedef struct i2c_controller {
	void	*ic_cookie;		/* controller private */

	/*
	 * These provide synchronization in the presence of
	 * multiple users of the i2c bus.  When a device
	 * driver wishes to perform transfers on the i2c
	 * bus, the driver should acquire the bus.  When
	 * the driver is finished, it should release the
	 * bus.
	 *
	 * The main synchronization logic is handled by the
	 * generic i2c layer, but optional hooks to back-end
	 * drivers are provided in case additional processing
	 * is needed (e.g. enabling the i2c controller).
	 */
	kmutex_t ic_bus_lock;
	int	(*ic_acquire_bus)(void *, int);
	void	(*ic_release_bus)(void *, int);

	/*
	 * The preferred API for clients of the i2c interface
	 * is the scripted API.  This handles i2c controllers
	 * that do not provide raw access to the i2c signals.
	 */
	int	(*ic_exec)(void *, i2c_op_t, i2c_addr_t, const void *, size_t,
		    void *, size_t, int);

	int	(*ic_send_start)(void *, int);
	int	(*ic_send_stop)(void *, int);
	int	(*ic_initiate_xfer)(void *, i2c_addr_t, int);
	int	(*ic_read_byte)(void *, uint8_t *, int);
	int	(*ic_write_byte)(void *, uint8_t, int);

	struct i2c_tag_private	*ic_tag_private;
} *i2c_tag_t;

/* Used to attach the i2c framework to the controller. */
struct i2cbus_attach_args {
	i2c_tag_t iba_tag;		/* the controller */
	prop_array_t iba_child_devices;	/* child devices (direct config) */
};

/* Type of value stored in "ia_cookie" */
enum i2c_cookie_type {
	I2C_COOKIE_NONE,		/* Cookie is not valid */
	I2C_COOKIE_OF,			/* Cookie is an OF node phandle */
	I2C_COOKIE_ACPI,		/* Cookie is an ACPI handle */
};

/* Used to attach devices on the i2c bus. */
struct i2c_attach_args {
	i2c_tag_t	ia_tag;		/* our controller */
	i2c_addr_t	ia_addr;	/* address of device */
	int		ia_type;	/* bus type */
	/* only set if using direct config */
	const char *	ia_name;	/* name of the device */
	int		ia_ncompat;	/* number of pointers in the
					   ia_compat array */
	const char **	ia_compat;	/* chip names */
	prop_dictionary_t ia_prop;	/* dictionary for this device */
	/*
	 * The following is of limited usefulness and should only be used
	 * in rare cases where we really know what we are doing. Example:
	 * a machine dependent i2c driver (located in sys/arch/$arch/dev)
	 * needing to access some firmware properties.
	 * Depending on the firmware in use, an identifier for the device
	 * may be present. Example: on OpenFirmware machines the device
	 * tree OF node - if available. This info is hard to transport
	 * down to MD drivers through the MI i2c bus otherwise.
	 *
	 * On ACPI platforms this is the ACPI_HANDLE of the device.
	 */
	uintptr_t	ia_cookie;	/* OF node in openfirmware machines */
	enum i2c_cookie_type ia_cookietype; /* Value type of cookie */
};

/*
 * API presented to i2c controllers.
 */
int	iicbus_print(void *, const char *);
void	iic_tag_init(i2c_tag_t);
void	iic_tag_fini(i2c_tag_t);

/*
 * API presented to i2c devices.
 */
int	iic_compatible_match(const struct i2c_attach_args *,
			     const struct device_compatible_entry *);
bool	iic_use_direct_match(const struct i2c_attach_args *, const cfdata_t,
			     const struct device_compatible_entry *, int *);
const struct device_compatible_entry *
	iic_compatible_lookup(const struct i2c_attach_args *,
			      const struct device_compatible_entry *);

/*
 * Constants to indicate the quality of a match made by a driver's
 * match routine, from lowest to highest:
 *
 *	-- Address only; no other checks were made.
 *
 *	-- Address + device probed and recognized.
 *
 *	-- Direct-config match by "compatible" string.
 *
 *	-- Direct-config match by specific driver name.
 */
#define	I2C_MATCH_ADDRESS_ONLY		1
#define	I2C_MATCH_ADDRESS_AND_PROBE	2
#define	I2C_MATCH_DIRECT_COMPATIBLE	10
#define	I2C_MATCH_DIRECT_COMPATIBLE_MAX	99
#define	I2C_MATCH_DIRECT_SPECIFIC	100

#ifdef _I2C_PRIVATE
/*
 * Macros used internally by the i2c framework.
 */
#define	iic_send_start(ic, flags)					\
	(*(ic)->ic_send_start)((ic)->ic_cookie, (flags))
#define	iic_send_stop(ic, flags)					\
	(*(ic)->ic_send_stop)((ic)->ic_cookie, (flags))
#define	iic_initiate_xfer(ic, addr, flags)				\
	(*(ic)->ic_initiate_xfer)((ic)->ic_cookie, (addr), (flags))

#define	iic_read_byte(ic, bytep, flags)					\
	(*(ic)->ic_read_byte)((ic)->ic_cookie, (bytep), (flags))
#define	iic_write_byte(ic, byte, flags)					\
	(*(ic)->ic_write_byte)((ic)->ic_cookie, (byte), (flags))
#endif /* _I2C_PRIVATE */

/*
 * Simplified API for clients of the i2c framework.  Definitions
 * in <dev/i2c/i2c_io.h>.
 */
int	iic_acquire_bus(i2c_tag_t, int);
void	iic_release_bus(i2c_tag_t, int);
int	iic_exec(i2c_tag_t, i2c_op_t, i2c_addr_t, const void *,
	    size_t, void *, size_t, int);

int	iic_smbus_write_byte(i2c_tag_t, i2c_addr_t, uint8_t, uint8_t, int);
int	iic_smbus_write_word(i2c_tag_t, i2c_addr_t, uint8_t, uint16_t, int);
int	iic_smbus_read_byte(i2c_tag_t, i2c_addr_t, uint8_t, uint8_t *, int);
int	iic_smbus_read_word(i2c_tag_t, i2c_addr_t, uint8_t, uint16_t *, int);
int	iic_smbus_receive_byte(i2c_tag_t, i2c_addr_t, uint8_t *, int);
int	iic_smbus_send_byte(i2c_tag_t, i2c_addr_t, uint8_t, int);
int	iic_smbus_quick_read(i2c_tag_t, i2c_addr_t, int);
int	iic_smbus_quick_write(i2c_tag_t, i2c_addr_t, int);
int	iic_smbus_block_read(i2c_tag_t, i2c_addr_t, uint8_t, uint8_t *,
	    size_t, int);
int	iic_smbus_block_write(i2c_tag_t, i2c_addr_t, uint8_t, uint8_t *,
	    size_t, int);

#endif /* _DEV_I2C_I2CVAR_H_ */
