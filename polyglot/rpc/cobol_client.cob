      *> Thin Active RPC client over native ARP1 on TCP (GnuCOBOL).
      *>
      *> Run against `active-rpc/examples/thin_peer.rs`:
      *>
      *>   ACTIVE_RPC_ADDR=127.0.0.1:54321 \
      *>   ACTIVE_RPC_CAP=<32 hex chars> \
      *>   ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf \
      *>   ./rpc-client-cobol
      *>
      *> COBOL has no socket support, so connect/send/recv call
      *> `native/rpc_socket.c` (a byte carrier). The envelope is encoded here,
      *> field by field: COMP-5 fields are native binary (little-endian on the
      *> x86-64 and AArch64 hosts this lane targets) and each one is copied into
      *> the frame through its PIC X redefine, so no numeric conversion ever
      *> touches the wire bytes. The one-byte fields (version, kind, flags for
      *> read-only and redaction, path-scope presence) are written as X"00"/X"01"
      *> literals for the same reason.
      *>
      *> Build: gcc -O2 -c polyglot/rpc/native/rpc_socket.c -o rpc_socket.o
      *>        cobc -x -free polyglot/rpc/cobol_client.cob rpc_socket.o \
      *>             -o rpc-client-cobol
       IDENTIFICATION DIVISION.
       PROGRAM-ID. RPC-CLIENT.
       ENVIRONMENT DIVISION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT PAYLOAD-FILE ASSIGN TO WS-FILE-NAME
               ORGANIZATION IS SEQUENTIAL
               ACCESS MODE IS SEQUENTIAL
               FILE STATUS IS WS-FILE-STATUS.
       DATA DIVISION.
       FILE SECTION.
       FD PAYLOAD-FILE.
       01 PAYLOAD-BYTE PIC X(1).
       WORKING-STORAGE SECTION.

      *> Byte carriers for the numeric views.
       01 WS-NUMBERS.
          05 WS-U16-BIN     PIC 9(4)   COMP-5.
          05 WS-U16-RAW     REDEFINES WS-U16-BIN PIC X(2).
          05 WS-U32-BIN     PIC 9(9)   COMP-5.
          05 WS-U32-RAW     REDEFINES WS-U32-BIN PIC X(4).
          05 WS-U64-BIN     PIC 9(18)  COMP-5.
          05 WS-U64-RAW     REDEFINES WS-U64-BIN PIC X(8).

       01 WS-FRAME-BUFFER.
          05 WS-FRAME       PIC X(1048576).
          05 WS-POS         PIC 9(9)   COMP-5.

       01 WS-RESPONSE-BUFFER.
          05 WS-RESPONSE    PIC X(1048576).
          05 WS-RESPONSE-LEN PIC S9(18) COMP-5.

       01 WS-PAYLOAD-BUFFER.
          05 WS-PAYLOAD     PIC X(1048576).
          05 WS-PAYLOAD-LEN PIC 9(9)   COMP-5.

      *> The response header, read as wire bytes and decoded through redefines.
       01 WS-HEADER-VIEW.
          05 WS-H-MAGIC     PIC X(4).
          05 WS-H-VERSION   PIC X(1).
          05 WS-H-KIND      PIC X(1).
          05 WS-H-FLAGS     PIC X(2).
          05 WS-H-ID        PIC X(8).
          05 WS-H-METHOD    PIC X(4).
       01 WS-HEADER-BYTES   REDEFINES WS-HEADER-VIEW PIC X(20).
       01 WS-ID-VALUE       PIC 9(18) COMP-5.
       01 WS-HEADER-VALUE   PIC 9(9)  COMP-5.

       01 WS-REQUEST-FIELDS.
          05 WS-REQUEST-ID  PIC 9(18) COMP-5.
          05 WS-METHOD      PIC X(8).
          05 WS-METHOD-LEN  PIC 9(9)  COMP-5.
          05 WS-WITH-CAP    PIC 9(9)  COMP-5.

       01 WS-FILE-NAME      PIC X(1024).
       01 WS-FILE-STATUS    PIC X(2).

       01 WS-ADDR-TEXT      PIC X(128).
       01 WS-CAP-TEXT-ENV   PIC X(64).
       01 WS-PAYLOAD-ENV    PIC X(1024).
       01 WS-HOST           PIC X(1024).
       01 WS-HOST-Z         PIC X(257).
       01 WS-HOST-LEN       PIC 9(9)   COMP-5.
       01 WS-PORT-TEXT      PIC X(16).
       01 WS-PORT           PIC 9(18)  COMP-5.
       01 WS-COLON          PIC 9(9)   COMP-5.
       01 WS-INDEX          PIC 9(9)   COMP-5.
       01 WS-SOCKET         PIC S9(18) COMP-5.
       01 WS-CALL-STATUS    PIC S9(18) COMP-5.

       01 WS-CAP-TEXT       PIC X(32).
       01 WS-CAP            PIC X(16).

      *> Response scanning.
       01 WS-TAG            PIC X(1).
       01 WS-VALUE          PIC 9(9)   COMP-5.
       01 WS-DEPTH          PIC 9(2)   COMP-5.
       01 WS-PENDING        PIC 9(9)   COMP-5 OCCURS 64 TIMES.
       01 WS-SCAN           PIC 9(9)   COMP-5.
       01 WS-ARG-COUNT      PIC 9(9)   COMP-5.
       01 WS-ARG-INDEX      PIC 9(9)   COMP-5.
       01 WS-CONTAINER-TYPE PIC 9(1)   COMP-5.
       01 WS-IS-MAP         PIC 9(1)   COMP-5 OCCURS 64 TIMES.
       01 WS-KEY-MODE       PIC 9(1)   COMP-5 OCCURS 64 TIMES.
       01 WS-CODE           PIC X(64).
       01 WS-METHOD-LEN-R   PIC 9(9)   COMP-5.

       PROCEDURE DIVISION.
       MAIN-PARAGRAPH.
           PERFORM LOAD-ENVIRONMENT
           PERFORM LOAD-PAYLOAD

      *> 1. echo with the capability: a response that echoes the payload.
           MOVE 42 TO WS-REQUEST-ID
           MOVE "echo" TO WS-METHOD
           MOVE 4 TO WS-METHOD-LEN
           MOVE 1 TO WS-WITH-CAP
           PERFORM ENCODE-REQUEST
           PERFORM ROUND-TRIP
           PERFORM CHECK-ECHO

      *> 2. a method outside the grant: rpc/method-not-granted.
           MOVE 43 TO WS-REQUEST-ID
           MOVE "refuse" TO WS-METHOD
           MOVE 6 TO WS-METHOD-LEN
           PERFORM ENCODE-REQUEST
           PERFORM ROUND-TRIP
           PERFORM READ-CODE
           IF WS-CODE(1:22) NOT = "rpc/method-not-granted"
              DISPLAY "wrong refusal code: " WS-CODE(1:22)
              STOP RUN
           END-IF

      *> 3. no capability at all: rpc/unknown-capability.
           MOVE 44 TO WS-REQUEST-ID
           MOVE "echo" TO WS-METHOD
           MOVE 4 TO WS-METHOD-LEN
           MOVE 0 TO WS-WITH-CAP
           PERFORM ENCODE-REQUEST
           PERFORM ROUND-TRIP
           PERFORM READ-CODE
           IF WS-CODE(1:22) NOT = "rpc/unknown-capability"
              DISPLAY "wrong refusal code: " WS-CODE(1:22)
              STOP RUN
           END-IF

           DISPLAY "COBOL thin RPC PASS (echo, refusal, missing capability)"
           STOP RUN.

      *> ACCEPT ... FROM ENVIRONMENT reads the runtime's own environment, which
      *> a statically linked C helper does not see in a GnuCOBOL executable.
       LOAD-ENVIRONMENT.
           MOVE SPACES TO WS-ADDR-TEXT
           ACCEPT WS-ADDR-TEXT FROM ENVIRONMENT "ACTIVE_RPC_ADDR"
           IF WS-ADDR-TEXT = SPACES
              DISPLAY "missing environment variable ACTIVE_RPC_ADDR"
              STOP RUN
           END-IF
           MOVE WS-ADDR-TEXT TO WS-HOST
           MOVE 0 TO WS-COLON
           PERFORM VARYING WS-INDEX FROM 1 BY 1 UNTIL WS-INDEX > 1024
              IF WS-HOST(WS-INDEX:1) = ":"
                 MOVE WS-INDEX TO WS-COLON
              END-IF
           END-PERFORM
           IF WS-COLON < 2
              DISPLAY "ACTIVE_RPC_ADDR must be host:port"
              STOP RUN
           END-IF
           COMPUTE WS-HOST-LEN = WS-COLON - 1
           MOVE SPACES TO WS-HOST-Z
           MOVE LOW-VALUES TO WS-HOST-Z(1:1)
           MOVE WS-HOST(1:WS-HOST-LEN) TO WS-HOST-Z(1:WS-HOST-LEN)
           MOVE LOW-VALUES TO WS-HOST-Z(WS-HOST-LEN + 1:1)
           COMPUTE WS-INDEX = WS-COLON + 1
           MOVE SPACES TO WS-PORT-TEXT
           MOVE WS-HOST(WS-INDEX:15) TO WS-PORT-TEXT
           COMPUTE WS-PORT = FUNCTION NUMVAL(WS-PORT-TEXT)

           MOVE SPACES TO WS-CAP-TEXT-ENV
           ACCEPT WS-CAP-TEXT-ENV FROM ENVIRONMENT "ACTIVE_RPC_CAP"
           IF FUNCTION TRIM(WS-CAP-TEXT-ENV) = SPACES
              DISPLAY "missing environment variable ACTIVE_RPC_CAP"
              STOP RUN
           END-IF
           MOVE WS-CAP-TEXT-ENV(1:32) TO WS-CAP-TEXT
           CALL "arp1_hex16" USING BY REFERENCE WS-CAP-TEXT
                                   BY REFERENCE WS-CAP
                              RETURNING WS-CALL-STATUS
           IF WS-CALL-STATUS NOT = 0
              DISPLAY "ACTIVE_RPC_CAP must be 32 hex characters"
              STOP RUN
           END-IF

           MOVE SPACES TO WS-PAYLOAD-ENV
           ACCEPT WS-PAYLOAD-ENV FROM ENVIRONMENT "ACTIVE_RPC_PAYLOAD"
           IF FUNCTION TRIM(WS-PAYLOAD-ENV) = SPACES
              DISPLAY "missing environment variable ACTIVE_RPC_PAYLOAD"
              STOP RUN
           END-IF
           MOVE SPACES TO WS-FILE-NAME
           MOVE FUNCTION TRIM(WS-PAYLOAD-ENV) TO WS-FILE-NAME.

      *> A sequential file of one-byte records: no runtime extension, and the
      *> byte count is exactly what was read.
       LOAD-PAYLOAD.
           MOVE SPACES TO WS-PAYLOAD
           MOVE 0 TO WS-PAYLOAD-LEN
           OPEN INPUT PAYLOAD-FILE
           IF WS-FILE-STATUS NOT = "00"
              DISPLAY "cannot open " WS-FILE-NAME " status " WS-FILE-STATUS
              STOP RUN
           END-IF
           PERFORM UNTIL WS-FILE-STATUS NOT = "00"
              READ PAYLOAD-FILE
                 AT END MOVE "10" TO WS-FILE-STATUS
                 NOT AT END
                    IF WS-PAYLOAD-LEN >= 1048576
                       DISPLAY "payload exceeds the client ceiling"
                       STOP RUN
                    END-IF
                    ADD 1 TO WS-PAYLOAD-LEN
                    MOVE PAYLOAD-BYTE TO WS-PAYLOAD(WS-PAYLOAD-LEN:1)
              END-READ
           END-PERFORM
           CLOSE PAYLOAD-FILE
           IF WS-PAYLOAD-LEN = 0
              DISPLAY "the payload file is empty"
              STOP RUN
           END-IF.

      *> Append helpers. Each keeps WS-POS at the next free byte.
       PUT-U16.
           MOVE WS-U16-RAW TO WS-FRAME(WS-POS:2)
           ADD 2 TO WS-POS.

       PUT-U32.
           MOVE WS-U32-RAW TO WS-FRAME(WS-POS:4)
           ADD 4 TO WS-POS.

       PUT-U64.
           MOVE WS-U64-RAW TO WS-FRAME(WS-POS:8)
           ADD 8 TO WS-POS.

       PUT-METHOD.
           MOVE WS-METHOD(1:WS-METHOD-LEN) TO WS-FRAME(WS-POS:WS-METHOD-LEN)
           ADD WS-METHOD-LEN TO WS-POS.

      *> Build one request frame from WS-REQUEST-FIELDS.
       ENCODE-REQUEST.
           MOVE SPACES TO WS-FRAME
           MOVE 1 TO WS-POS
           MOVE "ARP1" TO WS-FRAME(WS-POS:4)
           ADD 4 TO WS-POS
           MOVE X"01" TO WS-FRAME(WS-POS:1)
           ADD 1 TO WS-POS
           MOVE X"01" TO WS-FRAME(WS-POS:1)
           ADD 1 TO WS-POS
           MOVE 0 TO WS-U16-BIN
           PERFORM PUT-U16
           MOVE WS-REQUEST-ID TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE WS-METHOD-LEN TO WS-U32-BIN
           PERFORM PUT-U32
           PERFORM PUT-METHOD
           MOVE 0 TO WS-U32-BIN
           PERFORM PUT-U32
           MOVE WS-PAYLOAD-LEN TO WS-U32-BIN
           PERFORM PUT-U32
           MOVE WS-PAYLOAD(1:WS-PAYLOAD-LEN) TO WS-FRAME(WS-POS:WS-PAYLOAD-LEN)
           ADD WS-PAYLOAD-LEN TO WS-POS
           IF WS-WITH-CAP = 0
              MOVE 0 TO WS-U32-BIN
              PERFORM PUT-U32
              EXIT PARAGRAPH
           END-IF
           MOVE 1 TO WS-U32-BIN
           PERFORM PUT-U32
           MOVE WS-CAP TO WS-FRAME(WS-POS:16)
           ADD 16 TO WS-POS
           MOVE 1 TO WS-U32-BIN
           PERFORM PUT-U32
           MOVE 4 TO WS-U32-BIN
           PERFORM PUT-U32
           MOVE "echo" TO WS-METHOD
           MOVE 4 TO WS-METHOD-LEN
           PERFORM PUT-METHOD
           MOVE 10000 TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE 67108864 TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE 5000 TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE 100000 TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE 256 TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE 100000 TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE 10000000 TO WS-U64-BIN
           PERFORM PUT-U64
           MOVE X"00" TO WS-FRAME(WS-POS:1)
           ADD 1 TO WS-POS
           MOVE X"00" TO WS-FRAME(WS-POS:1)
           ADD 1 TO WS-POS
           MOVE X"00" TO WS-FRAME(WS-POS:1)
           ADD 1 TO WS-POS.

      *> One request per connection, as the peer serves it.
       ROUND-TRIP.
           CALL "arp1_connect" USING BY REFERENCE WS-HOST-Z
                                     BY VALUE WS-PORT
                                RETURNING WS-SOCKET
           IF WS-SOCKET < 0
              DISPLAY "connect failed"
              STOP RUN
           END-IF
           COMPUTE WS-U32-BIN = WS-POS - 1
           CALL "arp1_send" USING BY VALUE WS-SOCKET
                                  BY REFERENCE WS-U32-RAW
                                  BY VALUE 4
                             RETURNING WS-CALL-STATUS
           IF WS-CALL-STATUS NOT = 0
              DISPLAY "send of the frame length failed"
              STOP RUN
           END-IF
           COMPUTE WS-U64-BIN = WS-POS - 1
           CALL "arp1_send" USING BY VALUE WS-SOCKET
                                  BY REFERENCE WS-FRAME
                                  BY VALUE WS-U64-BIN
                             RETURNING WS-CALL-STATUS
           IF WS-CALL-STATUS NOT = 0
              DISPLAY "send of the frame failed"
              STOP RUN
           END-IF
           CALL "arp1_recv" USING BY VALUE WS-SOCKET
                                  BY REFERENCE WS-RESPONSE
                                  BY VALUE 1048576
                             RETURNING WS-RESPONSE-LEN
           CALL "arp1_close" USING BY VALUE WS-SOCKET
           IF WS-RESPONSE-LEN < 20
              DISPLAY "short or missing response"
              STOP RUN
           END-IF
           MOVE WS-RESPONSE(1:20) TO WS-HEADER-BYTES
           MOVE WS-H-ID TO WS-U64-RAW
           MOVE WS-U64-BIN TO WS-ID-VALUE
           MOVE WS-H-METHOD TO WS-U32-RAW
           MOVE WS-U32-BIN TO WS-METHOD-LEN-R.

       CHECK-ECHO.
           IF WS-H-KIND NOT = X"02"
              DISPLAY "echo was not a response"
              STOP RUN
           END-IF
           IF WS-ID-VALUE NOT = WS-REQUEST-ID
              DISPLAY "echo echoed a different request id"
              STOP RUN
           END-IF
           IF WS-H-MAGIC NOT = "ARP1" OR WS-H-VERSION NOT = X"01"
              DISPLAY "bad response header"
              STOP RUN
           END-IF
           COMPUTE WS-SCAN = 21 + WS-METHOD-LEN-R
           PERFORM SKIP-ARGS
           MOVE WS-RESPONSE(WS-SCAN:4) TO WS-U32-RAW
           MOVE WS-U32-BIN TO WS-VALUE
           ADD 4 TO WS-SCAN
           IF WS-VALUE NOT = WS-PAYLOAD-LEN
              DISPLAY "the payload length was not echoed"
              STOP RUN
           END-IF
           IF WS-RESPONSE(WS-SCAN:WS-PAYLOAD-LEN) NOT =
              WS-PAYLOAD(1:WS-PAYLOAD-LEN)
              DISPLAY "the AINF payload was not echoed"
              STOP RUN
           END-IF.

       READ-CODE.
           IF WS-H-KIND NOT = X"03"
              DISPLAY "the call was not refused"
              STOP RUN
           END-IF
           MOVE SPACES TO WS-CODE
           MOVE WS-RESPONSE(21:WS-METHOD-LEN-R) TO WS-CODE.

      *> Scan past the response arguments.
       SKIP-ARGS.
           MOVE WS-RESPONSE(WS-SCAN:4) TO WS-U32-RAW
           MOVE WS-U32-BIN TO WS-ARG-COUNT
           ADD 4 TO WS-SCAN
           PERFORM VARYING WS-ARG-INDEX FROM 1 BY 1
                   UNTIL WS-ARG-INDEX > WS-ARG-COUNT
              MOVE WS-RESPONSE(WS-SCAN:1) TO WS-TAG
              ADD 1 TO WS-SCAN
              EVALUATE WS-TAG
                 WHEN X"00"
                    PERFORM SKIP-VALUE
                 WHEN X"01"
                    ADD 8 TO WS-SCAN
                 WHEN X"02"
                    ADD 16 TO WS-SCAN
                 WHEN OTHER
                    DISPLAY "unknown argument tag " WS-TAG
                    STOP RUN
              END-EVALUATE
           END-PERFORM.

      *> One value, completely, without recursion: a container pushes its child
      *> count on a small stack. A map alternates key (a bare length-prefixed
      *> string) and value, which the key-mode flag at that depth records.
       SKIP-VALUE.
           MOVE 1 TO WS-DEPTH
           MOVE 1 TO WS-PENDING(1)
           MOVE 0 TO WS-KEY-MODE(1)
           MOVE 0 TO WS-IS-MAP(1)
           PERFORM UNTIL WS-DEPTH = 0
              IF WS-PENDING(WS-DEPTH) = 0
                 SUBTRACT 1 FROM WS-DEPTH
              ELSE
                 SUBTRACT 1 FROM WS-PENDING(WS-DEPTH)
                 IF WS-KEY-MODE(WS-DEPTH) = 1
                    PERFORM SKIP-LENGTH-PREFIXED
                    MOVE 0 TO WS-KEY-MODE(WS-DEPTH)
                 ELSE
                    PERFORM SKIP-ONE-VALUE
                    IF WS-IS-MAP(WS-DEPTH) = 1
                       MOVE 1 TO WS-KEY-MODE(WS-DEPTH)
                    END-IF
                 END-IF
              END-IF
           END-PERFORM.

       SKIP-ONE-VALUE.
           MOVE WS-RESPONSE(WS-SCAN:1) TO WS-TAG
           ADD 1 TO WS-SCAN
           EVALUATE WS-TAG
              WHEN X"00"
                 CONTINUE
              WHEN X"07"
                 CONTINUE
              WHEN X"01"
                 ADD 1 TO WS-SCAN
              WHEN X"02"
                 ADD 8 TO WS-SCAN
              WHEN X"03"
                 ADD 8 TO WS-SCAN
              WHEN X"04"
                 PERFORM SKIP-LENGTH-PREFIXED
              WHEN X"08"
                 PERFORM SKIP-LENGTH-PREFIXED
              WHEN X"09"
                 PERFORM SKIP-LENGTH-PREFIXED
              WHEN X"05"
                 MOVE 0 TO WS-CONTAINER-TYPE
                 PERFORM PUSH-CONTAINER
              WHEN X"06"
                 MOVE 1 TO WS-CONTAINER-TYPE
                 PERFORM PUSH-CONTAINER
              WHEN OTHER
                 DISPLAY "unknown value tag " WS-TAG
                 STOP RUN
           END-EVALUATE.

       PUSH-CONTAINER.
           MOVE WS-RESPONSE(WS-SCAN:4) TO WS-U32-RAW
           MOVE WS-U32-BIN TO WS-VALUE
           ADD 4 TO WS-SCAN
           ADD 1 TO WS-DEPTH
           IF WS-DEPTH > 64
              DISPLAY "value nesting exceeds the ceiling"
              STOP RUN
           END-IF
           MOVE WS-VALUE TO WS-PENDING(WS-DEPTH)
           MOVE WS-CONTAINER-TYPE TO WS-IS-MAP(WS-DEPTH)
           MOVE WS-CONTAINER-TYPE TO WS-KEY-MODE(WS-DEPTH)
           IF WS-CONTAINER-TYPE = 1
              COMPUTE WS-PENDING(WS-DEPTH) = WS-VALUE * 2
           END-IF.

       SKIP-LENGTH-PREFIXED.
           MOVE WS-RESPONSE(WS-SCAN:4) TO WS-U32-RAW
           MOVE WS-U32-BIN TO WS-VALUE
           ADD 4 TO WS-SCAN
           ADD WS-VALUE TO WS-SCAN.
