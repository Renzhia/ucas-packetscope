# Makefile - 网络嗅探器构建
# 依赖：libpcap, ncurses (macOS 系统自带)

CC      = clang
CFLAGS  = -std=c11 -Wall -Wextra -Wno-unused-parameter -g -DDEBUG -Isrc -Isrc/dissect -Isrc/ui
LDFLAGS = -lpcap -lncurses -lpthread

# macOS SDK 路径
SDKROOT := $(shell xcrun --show-sdk-path 2>/dev/null)
ifdef SDKROOT
CFLAGS += -isysroot $(SDKROOT)
endif

# pkg-config 获取 libpcap 参数（如果可用）
PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs libpcap 2>/dev/null)
ifdef PCAP_LIBS
LDFLAGS = $(PCAP_LIBS) -lncurses -lpthread
CFLAGS += $(PCAP_CFLAGS)
endif

SRC_DIR = src
OBJ_DIR = build/obj

SOURCES = \
    $(SRC_DIR)/main.c \
    $(SRC_DIR)/packet.c \
    $(SRC_DIR)/capture.c \
    $(SRC_DIR)/filter.c \
    $(SRC_DIR)/stream.c \
    $(SRC_DIR)/dissect/dissect.c \
    $(SRC_DIR)/dissect/ethernet.c \
    $(SRC_DIR)/dissect/arp.c \
    $(SRC_DIR)/dissect/ip.c \
    $(SRC_DIR)/dissect/icmp.c \
    $(SRC_DIR)/dissect/tcp.c \
    $(SRC_DIR)/dissect/udp.c \
    $(SRC_DIR)/dissect/http.c \
    $(SRC_DIR)/dissect/dns.c \
    $(SRC_DIR)/ui/ui.c

OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

TARGET = ucassniffer

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -rf build $(TARGET)
