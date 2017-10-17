/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <signal.h>
#include "krackips.h"
#include "module/formats.h"
#include "module/netframe.h"
#include "module/hexval.h"
#include "module/pixie.h"
#include "module/sprintf_s.h"

#ifdef WIN32
#include <direct.h> /* for Posix mkdir() */
#else
#include <unistd.h>
#endif

#include "module/pcapfile.h"
#include "module/pcaplive.h"
#include "module/mystring.h"

/**
 * This structure is initialized with 'pcap_init()' at the beginning
 * of the 'main()' function to runtime load the libpcap library.
 */
struct PCAPLIVE pcap;
pcap_if_t *alldevs;

enum {
	FERRET_SNIFF_NONE,
	FERRET_SNIFF_ALL,
	FERRET_SNIFF_MOST,
	FERRET_SNIFF_IVS,
	FERRET_SNIFF_SIFT
};

void SQUIRREL_EVENT(const char *msg, ...)
{
#if 0
	va_list marker;
	va_start(marker, msg);
	vfprintf(stderr, msg, marker);
	va_end(marker);
#endif
}

void FRAMERR(struct NetFrame *frame, const char *msg, ...)
{
	va_list marker;
	va_start(marker, msg);

	fprintf(stderr, "%s(%d): ", frame->filename, frame->frame_number);

	vfprintf(stderr, msg, marker);

	va_end(marker);
}


/**
 * Create an instance of this program, where we stash all our
 * "globals"
 */
void *krackips_create()
{
	struct Krackips *result;

	result = malloc(sizeof(*result));
	memset(result, 0, sizeof(*result));

    result->detect = malloc(sizeof(*result->detect));
    memset(result->detect, 0, sizeof(*result->detect));

	return result;
}

void krackips_destroy(struct Krackips *krackips)
{
	free(krackips);
}



int debug=1;




unsigned control_c_pressed=0;

void control_c_handler(int sig)
{
	control_c_pressed = 1;
}
void sigpipe_handler(int sig){
    
    fprintf(stderr, "\nCaught signal SIGPIPE %d\n\n",sig);
}



/**
 * Verifies that a directory exists, this will create the directory
 * if necessary.
 */
int verify_directory(const char *dirname)
{
	char part[256];
	size_t i;
	struct stat s;

	/* Starting condition: when it starts with a slash */
	i=0;
	if (dirname[i] == '/' || dirname[i] == '\\')
		i++;

	/* move forward until next slash */
again:
	while (dirname[i] != '\0' && dirname[i] != '/' && dirname[i] != '\\')
		i++;
	memcpy(part, dirname, i);
	part[i] = '\0';


	/* Make sure it exists */
	if (stat(part, &s) != 0) {
#ifdef WIN32
		_mkdir(part);
#else
		mkdir(part, 0777);
#endif
	} else if (!(s.st_mode & S_IFDIR)) {
		fprintf(stderr, "%s: not a directory\n", part);
		return -1;
	}

	if (dirname[i] == '\0')
		return 0;
	else {
		while (dirname[i] == '/' || dirname[i] == '\\')
			i++;
		goto again;
	}
}

/**
 * This is a small packet sniffer function that either sniffs
 * all packets, most of them (ignoring common repeats, like beacon
 * frames), just the IVS for WEP cracking, or just the ones that
 * trigger data to be generated.
 *
 * The packets are appended to rotating logfiles in the specified
 * directory.
 */
void sniff_packets(struct Krackips *krackips, const unsigned char *buf, const struct NetFrame *frame)
{
	time_t now;
	struct tm *ptm;


	/* First, test if we are allowed to capture this packet into a file */
	switch (krackips->output.sniff) {
	case FERRET_SNIFF_NONE:
		return;
	case FERRET_SNIFF_ALL:
		break;
	case FERRET_SNIFF_MOST:
		if (frame->flags.found.repeated)
			return;
		break;
	case FERRET_SNIFF_IVS:
		if (!frame->flags.found.ivs)
			return;
		break;
	case FERRET_SNIFF_SIFT:
		if (!krackips->something_new_found)
			return;
		break;
	default:
		return;
	}


	/* If we don't have a file open for sniffing, then open one. Also,
	 * if the linktype changes, we need to close the previous file we
	 * were writing to and open a new one to avoid mixing frames incorrectly.
	 */
	if (krackips->output.pf == NULL || krackips->output.linktype != krackips->linktype) {
		char filename[256];
		char linkname[16];

		if (krackips->output.pf) {
			pcapfile_close(krackips->output.pf);
			krackips->output.pf = NULL;
		}

		switch (krackips->linktype) {
		case 1:
			strcpy_s(linkname, sizeof(linkname), "eth");
			break;
		case 0x69:
			strcpy_s(linkname, sizeof(linkname), "wifi");
			break;
		default:
			sprintf_s(linkname, sizeof(linkname), "%d", krackips->linktype);
			break;
		}



		/* Format the current time */
		now = time(0);
		ptm = localtime(&now);

		if (krackips->output.filename[0]) {
			strcpy_s(filename, sizeof(filename), krackips->output.filename);
		} else {
			/* make sure we have a directory name */
			if (krackips->output.directory[0] == '\0') {
				krackips->output.directory[0] = '.';
				krackips->output.directory[1] = '\0';
			}
			/* Make sure the directory exists */
			if (verify_directory(krackips->output.directory) == -1) {
				/* oops, error creating directory, so just exit */
				return;
			}

			sprintf_s(filename, sizeof(filename), "%s/sniff-%04d-%02d-%02d-%s.pcap",
				krackips->output.directory,
				ptm->tm_year+1900,
				ptm->tm_mon+1,
				ptm->tm_mday,
				linkname
				);
		}

		/*
		 * Normally, we append to files (because we need to keep so many open,
		 * we temporarily close some).
		 */
		if (krackips->output.noappend)
			krackips->output.pf = pcapfile_openwrite(filename, krackips->linktype);
		else
			krackips->output.pf = pcapfile_openappend(filename, krackips->linktype);


		krackips->output.linktype = krackips->linktype;
		krackips->output.pf_opened = time(0); /* now */
	}


	if (krackips->output.pf) {
		if (krackips->filter.is_filtering && !frame->flags.found.filtered)
			return;

		pcapfile_writeframe(krackips->output.pf, buf, frame->captured_length, frame->original_length,
			frame->time_secs, frame->time_usecs);

		/* Close the file occasionally to make sure it's flushed to the disk */
		if (!krackips->output.noappend)
		if (krackips->output.pf_opened+600 < time(0)) {
			pcapfile_close(krackips->output.pf);
			krackips->output.pf = NULL;
		}
	}

	

}
int
ferret_filter_mac(struct Krackips *krackips, const unsigned char *mac_addr)
{
	unsigned i;

	for (i=0; i<krackips->filter.mac_address_count; i++) {
		if (memcmp(mac_addr, krackips->filter.mac_address[i], 6) == 0)
			return 1;
	}
	return 0;
}

/*****************************************************************************
 * Entry point were we parse a frame captured from libpcap
 *****************************************************************************/
static void
parse_frame(struct Krackips *krackips,
               struct NetFrame *frame,
               const unsigned char *px, unsigned length)
{
	/* Record the current time */
	if (krackips->now != (time_t)frame->time_secs) {
		krackips->now = (time_t)frame->time_secs;

		if (krackips->first == 0)
			krackips->first = frame->time_secs;

        krackips->detect->kludge.time_stamp = frame->time_secs;
	}

    krackips->detect->kludge.dbm = 0;
    krackips->detect->kludge.channel = 0;

	/* Clear the information that we will set in the frame */
	frame->flags.clear = 0;
	krackips->something_new_found = 0;


	switch (frame->layer2_protocol) {
	case 1: /* Ethernet */
		;//parse_ethernet_frame(krackips, frame, px, length);
		break;
	case 0x69: /* WiFi */
		parse_wifi_frame(krackips, frame, px, length);
		break;
	case 119: /* DLT_PRISM_HEADER */
		/* This was original created to handle Prism II cards, but now we see this
		 * from other cards as well, such as the 'madwifi' drivers using Atheros
		 * chipsets.
		 *
		 * This starts with a "TLV" format, a 4-byte little-endian tag, followed by
		 * a 4-byte little-endian length. This TLV should contain the entire Prism
		 * header, after which we'll find the real header. Therefore, we should just
		 * be able to parse the 'length', and skip that many bytes. I'm told it's more
		 * complicated than that, but it seems to work right now, so I'm keeping it 
		 * this way.
		 */
		if (length < 8) {
			FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
			return;
		}
		if (ex32le(px+0) != 0x00000044) {
			FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
			return;
		} else {
			unsigned header_length = ex32le(px+4);

			if (header_length >= length) {
				FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
				return;
			}

			/*
			 * Ok, we've skipped the Prism header, now let's process the 
			 * wifi packet as we would in any other case. TODO: in the future,
			 * we should parse the Prism header and extract some of the
			 * fields, such as signal strength.
			 */
			parse_wifi_frame(krackips, frame, px+header_length, length-header_length);
		}
		break;

	case 127: /* Radiotap headers */
		if (length < 4) {
			//FRAMERR(frame, "radiotap headers too short\n");
			return;
		}
		{
			unsigned version = px[0];
			unsigned header_length = ex16le(px+2);
			unsigned features = ex32le(px+4);
            unsigned flags = px[16];
			unsigned offset;
            int dbm_noise = 0;
            unsigned lock_quality = 0;

            frame->dbm = 0;

			if (version != 0 || header_length > length) {
				FRAMERR(frame, "radiotap headers corrupt\n");
				return;
			}

			/* If FCS is present at the end of the packet, then change
			 * the length to remove it */
			if (features & 0x4000) {
				unsigned fcs_header = ex32le(px+header_length-4);
				unsigned fcs_frame = ex32le(px+length-4);
				if (fcs_header == fcs_frame)
					length -= 4;
				if (header_length >= length) {
					FRAMERR(frame, "radiotap headers corrupt\n");
					return;
				}
			}

			offset = 8;

			if (features & 0x000001) offset += 8;	/* TSFT - Timestamp */
            if (features & 0x000002) {
                flags = px[offset];
                offset += 1;
                
                /* If there's an FCS at the end, then remove it so that we
                 * don't try to decode it as payload */
                if (flags & 0x10)
                    length -= 4;
            }
			if (features & 0x000004) offset += 1;	/* Rate */	
            if (features & 0x000008 && offset+2<header_length) {
                unsigned channel_frequency = ex16le(px+offset);
                unsigned channel = 0;
                switch (channel_frequency) {
                case 2412: channel = 1; break;
                case 2417: channel = 2; break;
                case 2422: channel = 3; break;
                case 2427: channel = 4; break;
                case 2432: channel = 5; break;
                case 2437: channel = 6; break;
                case 2442: channel = 7; break;
                case 2447: channel = 8; break;
                case 2452: channel = 9; break;
                case 2457: channel =10; break;
                case 2462: channel =11; break;
                case 2467: channel =12; break;
                case 2472: channel =13; break;
                case 2477: channel =14; break;
                }
                krackips->detect->kludge.channel = channel;
                offset += 2;	
            }
            if (features & 0x000008 && offset+2<header_length) {
                /*unsigned channel_flags = ex16le(px+offset);*/
                offset += 2;
            }
			if (features & 0x000010) offset += 2;	/* FHSS */	
			if (features & 0x000020 && offset+1<header_length) {
				frame->dbm = ((signed char*)px)[offset];
                krackips->detect->kludge.dbm = frame->dbm;
                offset += 1;
			}
			if (features & 0x000040 && offset+1<header_length) {
				dbm_noise = ((signed char*)px)[offset];

			}
			if (features & 0x000080 && offset+1<header_length) {
				lock_quality = ((unsigned char*)px)[offset];
			}

            if (flags & 0x40) {
                /* FCS/CRC error */
                return;
            }


			parse_wifi_frame(krackips, frame, px+header_length, length-header_length);

		}
		break;
	default:
		FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
		break;
	}
}

#define REMCONNECTIONS 40960
#define REMBUFSIZE 100000000
struct RemConnection {
	unsigned src_ip;
	unsigned dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	uint64_t trigger_frame_number; /* the frame number where we create this entry */
	struct RemConnection *next;
};

struct Remember {
	unsigned char buf[REMBUFSIZE];
	unsigned head;
	unsigned tail;
	unsigned top;
	unsigned count;
	uint64_t frame_number;

	struct RemConnection *connections[REMCONNECTIONS];
} *remember;


/**
 * Hashes the TCP connection to start the lookup in our remembrance table
 */
static unsigned rem_hash(struct NetFrame *frame)
{
	unsigned result;

	result = frame->dst_ipv4;
	result ^= frame->src_ipv4*2;
	result ^= frame->dst_port;
	result ^= frame->dst_port*2;

	result &= REMCONNECTIONS-1;
	return result;
}


/**
 * Looks up a connection entry.
 * If this is a "head" frame that passes the filter test, then we
 * create a new entry in this table. If this is a "tail" frame that
 * is being discarded, we test to see if there is an entry in this
 * table. If so, we know that we have a connection entry from BEFORE
 * the trigger event.
 */
static unsigned rem_connection(struct Krackips *krackips, struct NetFrame *frame, uint64_t frame_number, unsigned do_track)
{
	unsigned index;
	struct RemConnection **r_record;
	
	index = rem_hash(frame);

	r_record = &remember->connections[index];

	while (*r_record) {
		struct RemConnection *r = *r_record;

		if (   r->src_ip == frame->src_ipv4 
			&& r->dst_ip == frame->dst_ipv4 
			&& r->src_port == frame->src_port 
			&& r->dst_port == frame->dst_port)
			break;

		r_record = &(r->next);
	}


	if (*r_record == NULL) {
		struct RemConnection *r;
		
		/* If 'do_track' is set, then it forces us to create a new entry.
		 * Otherwise, if the connection doens't exist, we don't track it */
		if (!do_track)
			return 0;

		if (frame->src_ipv4==0 && frame->dst_ipv4 == 0)
			return 0; /* don't remember non-IPv4 connections */

		r = (struct RemConnection *)malloc(sizeof(*r));
		memset(r, 0, sizeof(*r));
		r->src_ip = frame->src_ipv4;
		r->dst_ip = frame->dst_ipv4;
		r->src_port = frame->src_port;
		r->dst_port = frame->dst_port;
		r->trigger_frame_number = frame_number; /* the frame number where we create this entry */
		r->next = NULL;
	
		*r_record = r;
		return 1;
	} else {
		if (!do_track && (frame_number > (*r_record)->trigger_frame_number)) {
			/* We are past the trigger packet, therefore remove it
			 * from our table */
			struct RemConnection *r = *r_record;

			*r_record = r->next;
			free(r);
			return 0;
		}
	}
	
	if (frame_number <= (*r_record)->trigger_frame_number)
		return 1;
	return 0;
}




unsigned rem_has_space(struct Krackips *krackips, const unsigned char *buf, struct NetFrame *frame)
{
	unsigned space_needed;
	unsigned space_remaining;

	assert(remember->tail < REMBUFSIZE);

	space_needed = sizeof(*frame) + frame->captured_length;
	space_needed += 8 - space_needed%8;


/*
                                 head      tail
                                   V        V
   ...----------+---------+--------+--------+---------+---------+--------...
                | headfrm | headbuf|        | tailfrm | tailbuf |    
   ...----------+---------+--------+--------+---------+---------+--------...
*/

	if (remember->tail > remember->head) {
		space_remaining = remember->tail - remember->head;
		assert(space_remaining < REMBUFSIZE);
	} else if (remember->tail < remember->head) {
		if (remember->head + space_needed < REMBUFSIZE)
			space_remaining = REMBUFSIZE - remember->head;
		else
			space_remaining = remember->tail;
		assert(space_remaining < REMBUFSIZE);
	} else {
		/* start condition where they are the same */
		if (remember->head == 0)
			return 1;
		else
			return 0;
	}

	if (space_needed > space_remaining)
		return 0;
	else
		return 1;
}

void rem_release_packet(struct Krackips *krackips)
{
/*
                                 head      tail
                                   V        V
   ...----------+---------+--------+--------+---------+---------+--------...
                | headfrm | headbuf|        | tailfrm | tailbuf |    
   ...----------+---------+--------+--------+---------+---------+--------...
*/
	struct NetFrame *frame = (struct NetFrame*)(remember->buf + remember->tail);
	unsigned next_tail = remember->tail + sizeof(*frame) + frame->captured_length;
	assert(remember->tail < REMBUFSIZE);

	/* See if this frame is part of a triggered TCP connection */
	if (!frame->flags.found.filtered) {
		if (rem_connection(krackips, frame, remember->frame_number-remember->count, 0))
			frame->flags.found.filtered = 1;
	}

	assert(remember->count > 0);

	next_tail += 8 - next_tail%8;

	sniff_packets(krackips, remember->buf+remember->tail+sizeof(*frame), frame);

	remember->tail = next_tail;
	if (remember->tail >= remember->top) {
		remember->top = remember->head;
		remember->tail = 0;
	}
	remember->count--;
	//printf("[%d] ", remember->count);
	assert(remember->tail < REMBUFSIZE);
}
void rem_save_packet(struct Krackips *krackips, const unsigned char *buf, struct NetFrame *frame)
{
	unsigned new_head;
	assert(remember->tail < REMBUFSIZE);

	remember->frame_number++;

	/* Put trigger packets into the TCP table so that released packets before
	 * the trigger can also be saved to the target capture file */
	if (frame->flags.found.filtered) {
		rem_connection(krackips, frame, remember->frame_number, 1);
	}

	new_head = remember->head + sizeof(*frame) + frame->captured_length;
	new_head += 8-new_head%8;

	if (new_head > REMBUFSIZE) {
		remember->head = 0;
		new_head = remember->head + sizeof(*frame) + frame->captured_length;
		new_head += 8-new_head%8;
		assert(new_head <= remember->tail);
	}


	memcpy(remember->buf+remember->head, frame, sizeof(*frame));
	remember->head += sizeof(*frame);
	memcpy(remember->buf+remember->head, buf, frame->captured_length);
	remember->head += frame->captured_length;
	remember->head += 8-remember->head%8;
	
	if (remember->top < remember->head)
		remember->top = remember->head;
	
	remember->count++;
	//printf("(%d) ", remember->count);
	assert(remember->tail < REMBUFSIZE);
}

void remember_packet(struct Krackips *krackips, const unsigned char *buf, struct NetFrame *frame)
{
	assert(remember->tail < REMBUFSIZE);
	while (!rem_has_space(krackips, buf, frame)) {
		/*unsigned desired_count = remember->count/2;
		do {*/
			rem_release_packet(krackips);
		/*} while (remember->count > desired_count);*/
	}
	rem_save_packet(krackips, buf, frame);
}
void remember_none(struct Krackips *krackips)
{
	while (remember->count)
		rem_release_packet(krackips);
}

static unsigned filtered_out(struct NetFrame *frame, const char *mac_address)
{
	if (frame->src_mac && memcmp(frame->src_mac, mac_address, 6) == 0)
		return 1;
	if (frame->dst_mac && memcmp(frame->dst_mac, mac_address, 6) == 0)
		return 1;
    if (frame->bss_mac == 0 && mac_address == 0)
        return 1;
    if (frame->bss_mac == 0 || mac_address == 0)
        return 0;
	if (frame->bss_mac && memcmp(frame->bss_mac, mac_address, 6) == 0)
		return 1;

	return 0;
}

/*****************************************************************************
 * Process a file containing packet capture data.
 *****************************************************************************/
int
process_file(struct Krackips *krackips, const char *capfilename)
{
	struct PcapFile *capfile;
	unsigned char buf[2048];
	unsigned linktype;
	unsigned frame_number = 0;
	clock_t last_time = clock();
	uint64_t last_bytes=0;

	/*
	 * Open the capture file
	 */
	capfile = pcapfile_openread(capfilename);
	if (capfile == NULL)
		return 0;
	linktype = pcapfile_datalink(capfile);
	krackips->linktype = linktype;
	
	//fprintf(stderr,"%s...", capfilename);
	fflush(stderr);

	/*
	 * Read in all the packets
	 */
	for (;;) {
		struct NetFrame frame[1];
		unsigned x;

		memset(frame,0,sizeof(*frame));

		/* Get next frame */
		x = pcapfile_readframe(capfile,
			&frame->time_secs,
			&frame->time_usecs,
			&frame->original_length,
			&frame->captured_length,
			buf,
			sizeof(buf)
			);

		if (x == 0 || clock() > last_time+1000) {
			char xxx[64];
			uint64_t bytes_read = 0;
			unsigned pdone;
			double bps;
			double mbps;
			clock_t this_time = clock();

			pdone = pcapfile_percentdone(capfile, &bytes_read);
			bps = ((int64_t)(bytes_read-last_bytes)) / ((this_time-last_time)/(double)CLOCKS_PER_SEC);
			mbps = bps * 8.0 / 1000000.0;


			sprintf_s(xxx, sizeof(xxx), "%d", pdone);
			//fprintf(stderr, "%3s%% %7.2f-mbps", xxx, (float)mbps);
			//fprintf(stderr, "%.*s", 17, "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
			fflush(stderr);
			last_time = this_time;
			last_bytes = bytes_read;
		}
		if (x == 0)
			break;

		/* Clear the flag. This will be set if the processing finds something
		 * interesting. At that point, we might want to save a copy of the 
		 * frame in a 'sift' file. */
		frame->filename = capfilename;
		frame->layer2_protocol = linktype;
		frame->frame_number = ++frame_number;
        frame->px = buf;

		/*
		 * Analyze the packet
		 */
		parse_frame(krackips, frame, buf, frame->captured_length);
		if (filtered_out(frame, "\x00\x1f\x33\xf8\x92\x2a"))
			continue;
		remember_packet(krackips, buf, frame);
	}

	/*
	 * Close the file
	 */
	fflush(stderr);
	pcapfile_close(capfile);

	return 0;
}


/*****************************************************************************
 * Provide help, either an overview, or more help on a specific option.
 *****************************************************************************/
static void 
main_help()
{
	fprintf(stderr,"options:\n");
	fprintf(stderr," -i <adapter>    Sniffs the wireless network adapter. \n");
	fprintf(stderr,"                 Must have libpcap/winpcap/ncap installed to work.\n");
	fprintf(stderr," -r <files>      Read files in off-line mode. Can use wildcards, such as \n");
	fprintf(stderr,"                 using \"krackips -r *.pcap\". Doesn't need libpcap to work.\n");
	fprintf(stderr," -c <file>       Reads in more advanced parameters from a file.\n");
}


/******************************************************************************
 ******************************************************************************/
static unsigned
cfg_prefix(const char *name, const char *prefix, unsigned offset)
{
	unsigned i, p;

	if (name[offset] == '.')
		offset++;

	for (i=offset, p=0; name[i] && prefix[p]; i++, p++)
		if (name[i] != prefix[p])
			return 0;
	if (prefix[p] == '\0')
		return i;
	else
		return 0;
}

/*****************************************************************************
 *****************************************************************************/
static unsigned
parse_boolean(const char *value)
{
	switch (value[0]) {
	case '1': /*1*/
	case 'y': /*yes*/
	case 'Y': /*YES*/
	case 'e': /*enabled*/
	case 'E': /*ENABLED*/
	case 't': /*true*/
	case 'T': /*TRUE*/
		return 1;
	case 'o': /*on/off*/
	case 'O': /*ON/OFF*/
		if (value[1] == 'n' || value[1] == 'N')
			return 1;
	}
	return 0;
}



/*****************************************************************************
 * Parse a MAC address from hex input. It can be in a number of
 * formats, such as:
 *	[00:00:00:00:00:00]
 *  00-00-00-00-00-00
 *  000000000000
 *****************************************************************************/
static void
parse_mac_address(unsigned char *dst, size_t sizeof_dst, const char *src)
{
	unsigned i=0;
	unsigned found_non_xdigit=0;
	unsigned premature_end=0;

	if (*src == '[')
		src++;

	while (*src && i<6) {
		if (!isxdigit(*src)) {
			found_non_xdigit = 1;
			src++;
		} else {
			unsigned c;

			c = hexval(*src);
			src++;
			if (*src == '\0')
				premature_end=1;
			else if (!isxdigit(*src))
				found_non_xdigit = 1;
			else {
				c = c<<4 | hexval(*src);
				src++;
			}

			if (i<sizeof_dst)
				dst[i++] = (unsigned char)c;
			
			if (*src && ispunct(*src))
				src++;
		}
	}

	if (found_non_xdigit)
		fprintf(stderr, "parse_mac_address: non hex-digit found\n");
}


/*****************************************************************************
 * Figures out whether the specified filename is a directory or normal
 * file. This is useful when recursing directories -- such as reading in
 * all packet-capture files in a directory structure for testing.
 *****************************************************************************/
static int
is_directory(const char *filename)
{
	struct stat s;

	if (stat(filename, &s) != 0) {
		/* Not found, so assume a "file" instead of "directory" */
		return 0;
	} else if (!(s.st_mode & S_IFDIR)) {
		/* Directory flag not set, so this is a "file" not a "directory" */
		return 0;
	}
	return 1;
}

/*****************************************************************************
 *****************************************************************************/
void 
krackips_set_parameter(struct Krackips *krackips, 
    const char *name, const char *value, unsigned depth)
{
	unsigned x=0;

	if (depth > 10)
		return;
	
	/* This macro is defined to match the leading keyword */
	#define MATCH(str) cfg_prefix(name, str, x) && ((x=cfg_prefix(name, str, x))>0)

	if (MATCH("config")) {
		if (MATCH("echo")) {
			krackips->cfg.echo = strdup(value);
		} else if (MATCH("quiet")) {
			krackips->cfg.quiet = parse_boolean(value);
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
    } else if (MATCH("interface")) {
		if (MATCH("checkfcs")) {
			krackips->cfg.interface_checkfcs = parse_boolean(value);
		} else if (MATCH("scan")) {
			krackips->cfg.interface_scan = parse_boolean(value);
		} else if (MATCH("interval")) {
			if (MATCH("inactive"))
				krackips->interface_interval_inactive = (unsigned)strtoul(value,0,0);
			else if (MATCH("active"))
				krackips->interface_interval_active = (unsigned)strtoul(value,0,0);
		}
	} else if (MATCH("vector")) {
		if (MATCH("mode")) {
			if (strcmp(value, "none")==0)
				krackips->cfg.no_vectors = 1;
		}
	} else if (MATCH("filter")) {
		krackips->filter.is_filtering = 1;
		if (MATCH("mac")) {
			/* Parse the MAC address in the value field and add it
			 * to the end of our list of MAC address filters.
			 * TODO: we should probably sort these and/or check
			 * for duplicates */
			unsigned char **newfilters = (unsigned char**)malloc((krackips->filter.mac_address_count+1)*sizeof(unsigned char*));
			unsigned i;
			for (i=0; i<krackips->filter.mac_address_count; i++)
				newfilters[i] = krackips->filter.mac_address[i];
			newfilters[i] = (unsigned char*)malloc(6);
			memset(newfilters[i], 0xa3, 6);
			parse_mac_address(newfilters[i], 6, value);
			if (krackips->filter.mac_address)
				free(krackips->filter.mac_address);
			krackips->filter.mac_address = newfilters;
			krackips->filter.mac_address_count++;
		} else if (MATCH("ssh")) {
			krackips->filter.is_ssh = 1;
			krackips->filter.something_tcp = 1;
		} else
			printf("unknowwn filter %s\n", name);
	} else if (MATCH("include")) {
		FILE *fp;
		char line[2048];

		fp = fopen(value, "rt");
		if (fp == NULL) {
			fprintf(stderr, "%sreading configuration file\n", "ERR:CFG: ");
			perror(value);
			return;
		}

		while (fgets(line, sizeof(line), fp)) {
			char *name;
			char *value;

			name = line;
			value = strchr(line, '=');
			if (value == NULL)
				continue;
			*value = '\0';
			value++;

			while (*name && isspace(*name))
				memmove(name, name+1, strlen(name));
			while (*value && isspace(*value))
				memmove(value, value+1, strlen(value));
			while (*name && isspace(name[strlen(name)-1]))
				name[strlen(name)-1] = '\0';
			while (*value && isspace(value[strlen(value)-1]))
				value[strlen(value)-1] = '\0';

			krackips_set_parameter(krackips, name, value, depth+1);

		}
	} else if (MATCH("statistics")) {
		krackips->cfg.statistics_print = parse_boolean(value);
	} else if (MATCH("sniffer")) {
		if (MATCH("dir")) {
			const char *directory_name = value;
			size_t directory_length = strlen(directory_name);
			char *p;

			if (directory_length > sizeof(krackips->output.directory)-1) {
				fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
			if (krackips->output.directory[0]) {
				fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, krackips->output.directory);
				fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}

			/* Remove trailing spaces and slashes */
			p = krackips->output.directory;
			while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
				p[strlen(p)-1] = '\0';

			strcpy_s(krackips->output.directory, sizeof(krackips->output.directory), directory_name);
			return;
		} else if (MATCH("filename")) {
			if (is_directory(value)) {
				krackips_set_parameter(krackips, "sniffer.directory", value, depth);
				return;
			}
			strcpy_s(krackips->output.filename, sizeof(krackips->output.filename), value);
			if (krackips->output.sniff == FERRET_SNIFF_NONE)
				krackips->output.sniff = FERRET_SNIFF_MOST;
			if (krackips->output.noappend == 0)
				krackips->output.noappend = 1;
		} else if (MATCH("mode")) {
			if (strcmp(value, "all")==0)
				krackips->output.sniff = FERRET_SNIFF_ALL;
			else if (strcmp(value, "most")==0)
				krackips->output.sniff = FERRET_SNIFF_MOST;
			else if (strcmp(value, "ivs")==0)
				krackips->output.sniff = FERRET_SNIFF_IVS;
			else if (strcmp(value, "sift")==0)
				krackips->output.sniff = FERRET_SNIFF_SIFT;
			else if (strcmp(value, "none")==0)
				krackips->output.sniff = FERRET_SNIFF_NONE;
			else {
				fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
		} else if (MATCH("noappend")) {
			krackips->output.noappend = parse_boolean(value);
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
	} else if (MATCH("snarfer")) {
		if (MATCH("dir")) {
			const char *directory_name = value;
			size_t directory_length = strlen(directory_name);
			char *p;

			if (directory_length > sizeof(krackips->snarfer.directory)-1) {
				fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
			if (krackips->snarfer.directory[0]) {
				fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, krackips->snarfer.directory);
				fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}

			/* Remove trailing spaces and slashes */
			p = krackips->snarfer.directory;
			while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
				p[strlen(p)-1] = '\0';

			strcpy_s(krackips->snarfer.directory, sizeof(krackips->snarfer.directory), directory_name);
			return;
		} else if (MATCH("mode")) {
			if (strcmp(value, "all")==0)
				krackips->snarfer.mode = FERRET_SNIFF_ALL;
			else if (strcmp(value, "most")==0)
				krackips->snarfer.mode = FERRET_SNIFF_MOST;
			else if (strcmp(value, "none")==0)
				krackips->snarfer.mode = FERRET_SNIFF_NONE;
			else {
				fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

	} else
		fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

}


/*****************************************************************************
 * Parse the command-line arguments
 *****************************************************************************/
static void 
main_args(int argc, char **argv, struct Krackips *krackips)
{
	int i;

	for (i=1; i<argc; i++) {
		const char *arg = argv[i];

		/* See if a <name=value> style configuration parameter was 
		 * given on the command-line */
		if (arg[0] != '-' && strchr(argv[i],'=')) {
			char name[256];
			size_t name_length;
			const char *value;
			unsigned j;

			/* Extract the name */
			name_length = strchr(argv[i], '=') - argv[i];
			if (name_length > sizeof(name)-1)
				name_length = sizeof(name)-1;
			memcpy(name, argv[i], name_length);
			while (name_length && isspace(name[name_length-1]))
				name_length--;
			while (name_length && isspace(name[0]))
				memmove(name, name+1, --name_length);
			name[name_length] = '\0';
			for (j=0; j<name_length; j++)
				name[j] = (char)tolower(name[j]);
			
			/* Extract the value */
			value = strchr(argv[i],'=') + 1;
			while (*value && isspace(*value))
				value++;

			/* Set the configuration parameter */
			krackips_set_parameter(krackips, name, value,1);

			continue; /*loop to next command-line parameter*/
		}

		if (arg[0] != '-')
			continue;

		if (arg[1] == '-') {
            if (strcasecmp_s(arg, "--server") == 0)
                krackips_set_parameter(krackips, "mode", "server", 0);
            else if (strcasecmp_s(arg, "--webroot") == 0)
                krackips_set_parameter(krackips, "webroot", argv[++i], 0);
			continue;
		}

		switch (arg[1]) {
		case 'c':
			if (arg[2] == '\0')
				krackips_set_parameter(krackips, "include", argv[++i], 0);
			else
				krackips_set_parameter(krackips, "include", argv[i]+2, 0);
			break;
		case 'd':
			debug++;
			break;
		case 'h':
		case 'H':
		case '?':
			main_help();
			exit(0);
			break;

		case 'q':
			krackips_set_parameter(krackips, "config.quiet", "true", 0);
			break;

		case 'F':
			krackips_set_parameter(krackips, "interface.checkfcs", "true", 0);
			break;
		case 'S':
			krackips_set_parameter(krackips, "statistics.print", "true", 0);
			break;

		case 'r':
			if (krackips->is_live) {
				fprintf(stderr,"ERROR: cannot process live and offline data at the same time\n");
				krackips->is_error = 1;
			}
			krackips->is_offline = 1;
			if (argv[i][2] == '\0') {
				while (i+1<argc) {
					const char *filename = argv[i+1];
					if (filename[0] == '-' || strchr(filename, '='))
						break;
					else
						i++;
				}
			}
			break;
		case 'i':
			if (krackips->is_offline) {
				fprintf(stderr,"Cannot process live and offline data at the same time\n");
				krackips->is_error = 1;
			} else {
				if (arg[2] == '\0' && i+1<argc) {
					strcpy_s(krackips->interface_name, sizeof(krackips->interface_name), argv[i+1]);
					i++;
					krackips->is_live = 1;
					/* TODO: validate*/
				} else if (isdigit(arg[2])) {
					strcpy_s(krackips->interface_name, sizeof(krackips->interface_name), arg+2);
					krackips->is_live = 1;
				} else {
					fprintf(stderr, "%s: invalid argument, expected something like \"-i1\" or \"-i eth0\"\n", argv[i]);
					krackips->is_error = 1;
				}
			}
			break;
		case 'W':
			krackips->is_live = 1;
			break;
		case 'w':
			if (arg[2] == '\0')
				krackips_set_parameter(krackips, "sniffer.filename", argv[++i], 0);
			else
				krackips_set_parameter(krackips, "sniffer.filename", argv[i]+2, 0);
			
			krackips_set_parameter(krackips, "sniffer.mode", "most", 0);
			break;
		}
	}
}

/*****************************************************************************
 *****************************************************************************/
static unsigned
count_digits(uint64_t n)
{
	unsigned i=0;
	for (i=0; n; i++)
		n = n/10;

	if (i == 0)
		i = 1;
	return i;
}

/*****************************************************************************
 *****************************************************************************/
void
print_stats(const char *str1, unsigned stat1, const char *str2, unsigned stat2)
{
	size_t i;
	unsigned digits;

	/* first number */
	digits = count_digits(stat1);
	fprintf(stderr, "%s", str1);
	for (i=strlen(str1); i<16; i++)
		printf(".");
	for (i=digits; i<11; i++)
		printf(".");
	printf("%d", stat1);

	printf(" ");

	/* second number */
	digits = count_digits(stat2);
	fprintf(stderr, "%s", str2);
	for (i=strlen(str2); i<16; i++)
		printf(".");
	for (i=digits; i<11; i++)
		printf(".");
	printf("%d", stat2);

	printf("\n");
}




/*****************************************************************************
 *****************************************************************************/
void
krackips_set_interface_status(struct Krackips *krackips, const char *devicename, unsigned is_running, unsigned channel)
{
	{
		unsigned i;
		for (i=0; i<krackips->adapter_count; i++) {
			if (strcmp(krackips->adapter[i].name, devicename) == 0) {
				krackips->adapter[i].is_open = is_running;
				krackips->adapter[i].channel = channel;
				krackips->adapter[i].last_activity = time(0);
			}
		}
		if (i < sizeof(krackips->adapter)/sizeof(krackips->adapter[0])) {
			memcpy(krackips->adapter[i].name, devicename, strlen(devicename)+1);
			krackips->adapter[i].is_open = is_running;
			krackips->adapter[i].channel = channel;
			krackips->adapter[i].last_activity = time(0);
			krackips->adapter_count++;				
		}
	}
}

/*****************************************************************************
 *****************************************************************************/
unsigned
krackips_get_interface_status(struct Krackips *krackips, const char *devicename, unsigned *r_channel)
{
	unsigned is_running = 0;
	{
		unsigned i;
		for (i=0; i<krackips->adapter_count; i++) {
			if (strcmp(krackips->adapter[i].name, devicename) == 0) {
				is_running = krackips->adapter[i].is_open;
				if (r_channel)
					*r_channel = krackips->adapter[i].channel;
			}
		}
	}
	return is_running;
}


/*****************************************************************************
 *****************************************************************************/
void pcapHandlePacket(unsigned char *v_seap, 
    const struct pcap_pkthdr *framehdr, const unsigned char *buf)
{
	static struct NetFrame frame[1];
	struct Krackips *krackips = (struct Krackips*)v_seap;

	memset(frame,0,sizeof(*frame));

	frame->filename = "live";
	frame->layer2_protocol = krackips->linktype;
	frame->frame_number++;
	
	frame->time_secs = (unsigned)framehdr->ts.tv_sec;
	frame->time_usecs = framehdr->ts.tv_usec;
	frame->original_length = framehdr->len;
	frame->captured_length = framehdr->caplen;
	frame->layer2_protocol = krackips->linktype;	
    frame->px = buf;

	/* Wrap in try/catch block */
	parse_frame(krackips, frame, buf, frame->captured_length);

	if (filtered_out(frame, "\x00\x1f\x33\xf8\x92\x2a"))
		return;
	if (filtered_out(frame, "\x06\x1f\x33\xf8\x92\x2a"))
		return;

	sniff_packets(krackips, buf, frame);

}

/*****************************************************************************
 * Return the name of the type of link giving it's numeric identifier
 *****************************************************************************/
const char *
get_link_name_from_type(unsigned linktype)
{
	switch (linktype) {
	case 0: return "UNKNOWN";
	case 1: return "Ethernet";
	case 105: return "WiFi";
	case 109: return "WiFi-Prism";
	case 127: return "WiFi-Radiotap";
	default: return "";
	}
}

/*****************************************************************************
 * Configure or re-configure the channel on the specified WiFi interface.
 *****************************************************************************/
static void
wifi_set_channel(void *hPcap, unsigned channel, const char *interface_name)
{

#ifdef __linux
	{
		char cmd[256];
		int result;
		sprintf_s(cmd, sizeof(cmd), "iwconfig %s channel %u\n", interface_name, channel);
		fprintf(stderr, "CHANGE: %s", cmd);
		result = system(cmd);
		if (result != 0)
		    fprintf(stderr, "CHANGE: %s (FAILED)", cmd);
	}
#endif
#ifdef WIN32
	{
		void *h = pcap.get_airpcap_handle(hPcap);
		if (h == NULL) {
			fprintf(stderr, "ERR: Couldn't get Airpcap handle\n");
		} else {
			if (pcap.airpcap_set_device_channel(h, channel) != 1) {
				fprintf(stderr, "ERR: Couldn't set '%s' to channel %d\n", interface_name, channel);
			} else
				fprintf(stderr, "CHANGE: monitoring channel %d on wifi interface %s\n", channel, interface_name);
		}
	}
#endif

}


struct MonitorThread {
	struct Krackips *krackips;
	char devicename[256];
	const char *drivername;
};

/*****************************************************************************
 *****************************************************************************/
void krackips_monitor_thread(void *user_data)
{
	struct MonitorThread *mt = (struct MonitorThread*)user_data;
	struct Krackips *krackips = mt->krackips;
	const char *devicename = mt->devicename;
	/*const char *drivername = mt->drivername;*/
    int traffic_seen = 0;
    int total_packets_processed = 0;
    void *hPcap;
    char errbuf[1024];
	unsigned interface_channel = 0;
	unsigned old_interface_channel;
	clock_t old_scan_time = clock();
	unsigned old_scan_channel = 1;

	fprintf(stderr, "Monitor thread start\n");
	
	/* Get the configured channel, if there is one */
	krackips_get_interface_status(krackips, devicename, &interface_channel);

	/*
	 * Open the adapter
	 */
	hPcap = pcap.open_live( devicename,
							4000,				/*snap len*/
							1,					/*promiscuous*/
							10,					/*10-ms read timeout*/
							errbuf
							);
	if (hPcap == NULL) {
		krackips_set_interface_status(krackips, devicename, 0, interface_channel);
		fprintf(stderr, "%s: %s\n", devicename, errbuf);
		return;
	} else {
		krackips_set_interface_status(krackips, devicename, 1, interface_channel);
		fprintf(stderr, "%s: monitoring\n", devicename);
	}
    
    if (pcap.can_set_rfmon(hPcap) == 1) {
        fprintf(stderr, "%s: setting monitor mode\n", devicename);
        pcap.set_rfmon(hPcap);
        pcap.set_datalink(hPcap, 127);
    }



	krackips->linktype = pcap.datalink(hPcap);
	fprintf(stderr, "SNIFFING: %s\n", devicename);
	fprintf(stderr, "LINKTYPE: %d %s\n", krackips->linktype, get_link_name_from_type(krackips->linktype));


    /* 
	 * MAIN LOOOP
	 *
	 * Sit in this loop forever, reading packets from the network then
	 * processing them.
	 */
	old_interface_channel = interface_channel;
    while (!control_c_pressed) {
        int packets_read;
		unsigned is_running;

		/* See if the interface status is still on. When the user turns off
		 * an adapter, we'll first notice it here */
		is_running = krackips_get_interface_status(krackips, devicename, &interface_channel);
		if (!is_running)
			break;

		/* See if the user has changed which interface we are supposed to be
		 * monitoring */
		if (interface_channel != old_interface_channel) {
			if (interface_channel != 0 && interface_channel != (unsigned)-1)
				wifi_set_channel(hPcap, interface_channel, devicename);
			old_interface_channel = interface_channel;
		}

		/* See if are scanning channels */
		if (interface_channel == (unsigned)-1) {
			clock_t new_scan_time = clock();			
			if (new_scan_time > old_scan_time + (CLOCKS_PER_SEC/10)) {
				unsigned new_scan_channel = old_scan_channel + 1;
				if (new_scan_channel > 11)
					new_scan_channel = 1;
				wifi_set_channel(hPcap, new_scan_channel, devicename);
				old_scan_channel = new_scan_channel;
				old_scan_time = new_scan_time;
			}
		}

		packets_read = pcap.dispatch(
								hPcap, /*handle to PCAP*/
								10,        /*next 10 packets*/
								pcapHandlePacket, /*callback*/
								(unsigned char*)krackips);
		if (packets_read < 0)
			break;
        total_packets_processed += packets_read;
        if (!traffic_seen && total_packets_processed > 0) {
            fprintf(stderr, "Traffic seen\n");
            traffic_seen = 1;
        }
    }

    /* Close the file and go onto the next one */
    pcap.close(hPcap);
	krackips_set_interface_status(krackips, devicename, 0, interface_channel);
	printf("****end monitor thread %s****\n", devicename);
}

void launch_thread(struct Krackips *krackips, const char *adapter_name)
{
	ptrdiff_t result;
	struct MonitorThread *mt = (struct MonitorThread*)malloc(sizeof(*mt));
	memset(mt, 0, sizeof(*mt));
	sprintf_s(mt->devicename, sizeof(mt->devicename), "%s", adapter_name);
	fprintf(stderr, "Starting monitor thread for \"%s\"\n", adapter_name);
#ifdef WIN32
	mt->drivername = "airpcap";
#endif
	mt->krackips = krackips;
	result = pixie_begin_thread(krackips_monitor_thread, 0, mt);
	if (result != 0)
		fprintf(stderr, "Error starting thread\n");
	else
		fprintf(stderr, "Thread started\n");
}

int main(int argc, char **argv)
{
	int i;
	struct Krackips *krackips;

	fprintf(stderr, "-- krackips 1.0 - (c) 2008-2017 Robert David Graham\n");
	fprintf(stderr, "-- build = %s %s (%u-bits)\n", __DATE__, __TIME__, (unsigned)sizeof(size_t)*8);

	/*
	 * Register a signal handler for the <ctrl-c> key. This allows
	 * files to be closed gracefully when exiting. Otherwise, the
	 * last bit of data gets corrupted when the user hits <ctrl-c>
	 */
	signal(SIGINT, control_c_handler);

    /*
     * Remove PIPE signals, otherwise bad read/writes to sockets will
     * cause the program to crash
     */
#ifdef SIGPIPE
    signal(SIGPIPE, sigpipe_handler);
#endif
    
    
	/*
	 * Runtime-load the libpcap shared-object or the winpcap DLL. We
	 * load at runtime rather than loadtime to allow this program to 
	 * be used to process offline content, and to provide more helpful
	 * messages to people who don't realize they need to install PCAP.
	 */
	pcaplive_init(&pcap);
	if (!pcap.is_available) {
		fprintf(stderr,"WinPcap is not available. Please install it from: http://www.winpcap.org/\n");
		fprintf(stderr,"Without WinPcap, you can process capture packet capture files (offline mode), \n");
		fprintf(stderr,"but you will not be able to monitor the network (live mode).\n");
	} else {
		fprintf(stderr,"-- %s\n", pcap.lib_version());
	}


	/*
	 * Create an instance of the master object. This is essentially the "globals"
	 * of the system, but I wrap them in a big structure and pass a pointer to
     * it everywhere rather than have real globals. This should make the code easier
     * to integrate into other software if somebody wants.
	 */
	krackips = krackips_create();
	remember = malloc(sizeof(*remember));
	memset(remember, 0, sizeof(*remember));
	
	/*
	 * Parse the command-line arguments. This many also parse the configuration
	 * file that contains more difficult options.
	 */
	main_args(argc, argv, krackips);


	/* 
	 * If the user doesn't specify any options, then print a helpful
	 * message.
	 */
	if (argc <= 1) {
		fprintf(stderr,"Usage:\n");
        fprintf(stderr, "krackips -i mon0\n");
		return 0;
	}


    /*
     * If reading files, then after everything is initialized, go through
     * list and read all the files in.
     */
	for (i=1; i<argc; i++) {
		if (argv[i][0] != '-')
			continue;
		if (argv[i][1] != 'r')
			continue;
		/* Process one or more filenames after the '-r' option */
		if (argv[i][2] != '\0')
			process_file(krackips, argv[i]+2);
		while (i+1 < argc && argv[i+1][0] != '-' && strchr(argv[i+1],'=') == NULL) {
			process_file(krackips, argv[i+1]);
			i++;
		}
	}

	remember_none(krackips);
	if (krackips->output.pf) {
		pcapfile_close(krackips->output.pf);
		krackips->output.pf = NULL;
	}

	if (krackips->cfg.statistics_print) {
		struct tm *tm_first;
		struct tm *tm_last;
		char sz_first[64], sz_last[64];
		int diff = (int)(krackips->now-krackips->first);

		tm_first = localtime(&krackips->first);
		strftime(sz_first, sizeof(sz_first), "%Y-%m-%d %H:%M:%S", tm_first);
		
		tm_last = localtime(&krackips->now);
		strftime(sz_last, sizeof(sz_last), "%Y-%m-%d %H:%M:%S", tm_last);

		fprintf(stderr, "Capture started at %s and ended at %s (%d seconds)\n",
				sz_first, sz_last, diff);

	}

	/*FIXME TEMP TODO
	 * Hardcode monitor thread for testing
	 */
	if (krackips->is_live) {
		printf("5\n");
		fprintf(stderr, "Starting monitor thread\n");
		launch_thread(krackips, krackips->interface_name);
	}

    /*
	{unsigned i=0;
	while (!control_c_pressed) {
		printf("%c\x08", "|\\-/"[i&0x03]);
		fflush(stdout);
		i++;
		pixie_sleep(1000);
	}
	}*/

	krackips_destroy(krackips);

	return 0;
}
