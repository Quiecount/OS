#ifndef OSMEDIC_JSON_OUTPUT_H
#define OSMEDIC_JSON_OUTPUT_H

#include <stdio.h>
#include <string.h>

/* 检查单个 UTF-8 字符，防止文件名中的非法字节破坏 JSON 编码。 */
static size_t utf8_length(const unsigned char *s, size_t remaining)
{
	size_t length;
	unsigned int codepoint;

	if (s[0] >= 0xc2 && s[0] <= 0xdf) {
		length = 2;
		codepoint = s[0] & 0x1f;
	} else if (s[0] >= 0xe0 && s[0] <= 0xef) {
		length = 3;
		codepoint = s[0] & 0x0f;
	} else if (s[0] >= 0xf0 && s[0] <= 0xf4) {
		length = 4;
		codepoint = s[0] & 0x07;
	} else {
		return 0;
	}
	if (length > remaining)
		return 0;
	for (size_t i = 1; i < length; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		codepoint = (codepoint << 6) | (s[i] & 0x3f);
	}
	if ((length == 3 && codepoint < 0x800) ||
	    (length == 4 && codepoint < 0x10000) ||
	    (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
		return 0;
	return length;
}

static void write_json_string(FILE *file, const char *value, size_t capacity)
{
	const unsigned char *s = (const unsigned char *)value;
	size_t length = strnlen(value, capacity);

	fputc('"', file);
	for (size_t i = 0; i < length;) {
		unsigned char c = s[i];
		size_t utf8;

		if (c == '"' || c == '\\') {
			fputc('\\', file);
			fputc(c, file);
		} else if (c < 0x20) {
			fprintf(file, "\\u%04x", c);
		} else if (c < 0x80) {
			fputc(c, file);
		} else if ((utf8 = utf8_length(s + i, length - i)) != 0) {
			fwrite(s + i, 1, utf8, file);
			i += utf8;
			continue;
		} else {
			fprintf(file, "\\u%04x", c);
		}
		i++;
	}
	fputc('"', file);
}


#endif
