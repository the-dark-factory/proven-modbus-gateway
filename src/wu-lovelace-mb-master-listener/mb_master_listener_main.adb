with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;
with Ada.Real_Time;
with Ada.Strings.Unbounded;
with GNAT.Sockets;
with GNAT.SHA256;
with Lovelace_Mb_Bounds_Pkg;
with Lovelace_Mb_Mbap_Pkg;
with Lovelace_Mb_Tcp_Adu_Pkg;

--  master-listener (edge, built-not-proved), lovelace-mb round A, W4: the gateway's master side [TCP s.3.1.3,
--  s.4.4.1, s.4.4.2]. Accepts masters on the listen ports the site names, maps (peer IPv4, listen port) to a slot
--  (R-MB-20; unknown = 0), reads 7 header bytes, then EXACTLY Tcp_Adu.Bytes_To_Read (L) more and only when
--  Mbap.Length_Field_Ok (L); else the 7 bytes are passed on and the connection is closed (R-MB-9: cannot resync).
--  So no frame is ever read past Bounds.Max_Tcp_Adu = 260 bytes (Bytes_To_Read <= 253 is the core's Post). The receive
--  time is stamped here, the only clock read (R-MB-17, R-MB-27). One request in flight per connection (R-MB-18): a
--  connection is not read again until its master-out line has come back. It also owns the master sockets' WRITE side:
--  master-out lines (from master-replier, on the loopback return port) are written to the connection they name.
--  CVE-2026-51539 class (slow senders): every frame must complete within Frame_Deadline_Ms of its first byte, else
--  the bytes read so far are passed on (the framer refuses them Short_Adu) and the connection is closed; at most
--  Max_Conns masters at once (one more is closed at accept); an idle connection is closed after Idle_Limit_Ms, one
--  waiting for its master-out line after Reply_Limit_Ms. These bounds are TESTED by the probe, not proved.
--
--  CLI contract:
--    mb_master_listener_main <site-dump> <bind IPv4> <return port>
--  <site-dump>: site-loader's accepted dump; its digest line is recomputed (GNAT.SHA256) and must match; the master
--    lines give the slots and the listen ports (every distinct port is bound on <bind IPv4>).
--  <return port>: bound on 127.0.0.1; master-replier connects and sends master-out lines "<conn> TAB <ADU hex | ->"
--    ("-" = silent: nothing is written, the connection is read again). A line naming no waiting connection is dropped.
--  standard output, one frame-in line per frame, flushed: <conn> TAB <slot> TAB <ms> TAB <ADU hex>
--    conn: 1, 2, ... never reused; ms: monotonic ms since start; hex: every byte read for the frame.
--  standard error: one status line per event (listening, open, closed with its reason, dropped line).
--  exit 2: usage, a malformed dump, a digest mismatch, no master line, or a port that cannot be bound.

procedure Mb_Master_Listener_Main is
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Real_Time.Time;
   use type GNAT.Sockets.Selector_Status;

   package BD renames Lovelace_Mb_Bounds_Pkg;
   package MB renames Lovelace_Mb_Mbap_Pkg;
   package TA renames Lovelace_Mb_Tcp_Adu_Pkg;
   package GS renames GNAT.Sockets;
   package UB renames Ada.Strings.Unbounded;
   package SE renames Ada.Streams;

   Tab               : constant Character := Character'Val (9);
   Max_File          : constant := 1_048_576;
   Max_Masters       : constant := 64;
   Max_Conns         : constant := 16;
   Max_Returns       : constant := 4;
   Max_Line          : constant := 2_048;
   Frame_Deadline_Ms : constant := 1_000;
   Idle_Limit_Ms     : constant := 60_000;
   Reply_Limit_Ms    : constant := 5_000;
   Cap               : constant := BD.Max_Tcp_Adu;

   subtype Byte is Natural range 0 .. 255;
   type Frame_Bytes is array (1 .. Cap) of Byte;

   type Master_Rec is record
      Ip   : UB.Unbounded_String;
      Port : Natural := 0;
      Slot : Natural := 0;
   end record;
   type Master_Array is array (1 .. Max_Masters) of Master_Rec;
   Masters      : Master_Array;
   Master_Count : Natural := 0;

   type Port_Array is array (1 .. Max_Masters) of Natural;
   Ports      : Port_Array := [others => 0];
   Port_Count : Natural := 0;
   type Listen_Array is array (1 .. Max_Masters) of GS.Socket_Type;
   Listens    : Listen_Array := [others => GS.No_Socket];

   type Conn_State is (Free, Idle, Reading, Awaiting);
   type Conn_Rec is record
      State : Conn_State := Free;
      Sock  : GS.Socket_Type := GS.No_Socket;
      Id    : Natural := 0;
      Slot  : Natural := 0;
      Have  : Natural := 0;
      Need  : Natural := 0;
      Since : Long_Long_Integer := 0;
      Buf   : Frame_Bytes := [others => 0];
   end record;
   type Conn_Array is array (1 .. Max_Conns) of Conn_Rec;
   Conns   : Conn_Array;
   Next_Id : Natural := 0;

   type Return_Rec is record
      Used : Boolean := False;
      Sock : GS.Socket_Type := GS.No_Socket;
      Line : UB.Unbounded_String;
   end record;
   type Return_Array is array (1 .. Max_Returns) of Return_Rec;
   Returns     : Return_Array;
   Return_Sock : GS.Socket_Type := GS.No_Socket;

   T0  : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
   Bad : Boolean := False;

   ------------------------------------------------------------------ text helpers
   function Hex_Digit (C : Character) return Integer is
     (if C in '0' .. '9' then Character'Pos (C) - 48
      elsif C in 'a' .. 'f' then Character'Pos (C) - 87
      elsif C in 'A' .. 'F' then Character'Pos (C) - 55
      else -1);

   function Hex2 (V : Byte) return String is
      D : constant String := "0123456789abcdef";
   begin
      return [D (V / 16 + 1), D (V mod 16 + 1)];
   end Hex2;

   function Decimal (N : Long_Long_Integer) return String is
      D : constant String := "0123456789";
      R : String (1 .. 20);
      P : Natural := R'Last + 1;
      W : Long_Long_Integer := N;
   begin
      loop
         P := P - 1;
         R (P) := D (Natural (W mod 10) + 1);
         W := W / 10;
         exit when W = 0;
      end loop;
      return R (P .. R'Last);
   end Decimal;

   --  A decimal field: digits only, 1 .. 9 of them; -1 when malformed.
   function Number (S : String) return Integer is
      V : Integer := 0;
   begin
      if S'Length = 0 or else S'Length > 9 then
         return -1;
      end if;
      for C of S loop
         if C not in '0' .. '9' then
            return -1;
         end if;
         V := V * 10 + (Character'Pos (C) - 48);
      end loop;
      return V;
   end Number;

   function Now_Ms return Long_Long_Integer is
     (Long_Long_Integer (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - T0) * 1000));

   procedure Note (S : String) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "master-listener: " & S);
   end Note;

   --  The I-th TAB-separated field of L (1-based); "" when absent.
   function Field (L : String; I : Positive) return String is
      K     : Positive := 1;
      First : Positive := L'First;
   begin
      for P in L'Range loop
         if L (P) = Tab then
            if K = I then
               return L (First .. P - 1);
            end if;
            K := K + 1;
            First := P + 1;
         end if;
      end loop;
      return (if K = I then L (First .. L'Last) else "");
   end Field;

   function Field_Count (L : String) return Natural is
      K : Natural := 1;
   begin
      for C of L loop
         if C = Tab then
            K := K + 1;
         end if;
      end loop;
      return K;
   end Field_Count;

   function Valid_Ipv4 (S : String) return Boolean is
      Dots  : Natural := 0;
      First : Positive := S'First;
   begin
      if S'Length < 7 or else S'Length > 15 then
         return False;
      end if;
      for P in S'First .. S'Last + 1 loop
         if P > S'Last or else S (P) = '.' then
            if P = First or else P - First > 3 or else Number (S (First .. P - 1)) not in 0 .. 255 then
               return False;
            end if;
            Dots := Dots + (if P > S'Last then 0 else 1);
            First := P + 1;
         end if;
      end loop;
      return Dots = 3;
   end Valid_Ipv4;

   ------------------------------------------------------------------ the site dump (site-policy pool, read-only)
   procedure Load_Dump (Path : String) is
      use type Ada.Directories.File_Kind;
      use type Ada.Directories.File_Size;
      F      : Ada.Text_IO.File_Type;
      Ctx    : GNAT.SHA256.Context := GNAT.SHA256.Initial_Context;
      First  : Boolean := True;
      Digest : Boolean := False;
   begin
      if not Ada.Directories.Exists (Path)
        or else Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File
        or else Ada.Directories.Size (Path) > Max_File
      then
         Bad := True;
         return;
      end if;
      Ada.Text_IO.Open (F, Ada.Text_IO.In_File, Path);
      while not Bad and then not Ada.Text_IO.End_Of_File (F) loop
         declare
            L : constant String := Ada.Text_IO.Get_Line (F);
         begin
            if Digest then
               Bad := True;
            elsif First then
               First := False;
               Bad := L /= "site-loader" & Tab & "accepted";
               GNAT.SHA256.Update (Ctx, L & Character'Val (10));
            elsif Field (L, 1) = "digest" then
               Digest := True;
               Bad := L /= "digest" & Tab & "sha256=" & GNAT.SHA256.Digest (Ctx);
            else
               GNAT.SHA256.Update (Ctx, L & Character'Val (10));
               if Field (L, 1) = "master" then
                  if Field_Count (L) /= 4 or else not Valid_Ipv4 (Field (L, 2))
                    or else Number (Field (L, 3)) not in 1 .. 65_535
                    or else Number (Field (L, 4)) not in 1 .. 16
                    or else Master_Count = Max_Masters
                  then
                     Bad := True;
                  else
                     Master_Count := Master_Count + 1;
                     Masters (Master_Count) :=
                       (Ip => UB.To_Unbounded_String (Field (L, 2)), Port => Number (Field (L, 3)),
                        Slot => Number (Field (L, 4)));
                  end if;
               end if;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (F);
      Bad := Bad or else not Digest or else Master_Count = 0;
   end Load_Dump;

   function Slot_Of (Ip : String; Port : Natural) return Natural is
   begin
      for I in 1 .. Master_Count loop
         if UB.To_String (Masters (I).Ip) = Ip and then Masters (I).Port = Port then
            return Masters (I).Slot;
         end if;
      end loop;
      return 0;
   end Slot_Of;

   ------------------------------------------------------------------ sockets
   procedure Bind_Listen (S : out GS.Socket_Type; Ip : String; Port : Natural) is
   begin
      GS.Create_Socket (S, GS.Family_Inet, GS.Socket_Stream);
      GS.Set_Socket_Option (S, GS.Socket_Level, (GS.Reuse_Address, True));
      GS.Bind_Socket (S, (GS.Family_Inet, GS.Inet_Addr (Ip), GS.Port_Type (Port)));
      GS.Listen_Socket (S, 32);
   exception
      when GS.Socket_Error =>
         Note ("cannot bind " & Ip & ":" & Decimal (Long_Long_Integer (Port)));
         Bad := True;
   end Bind_Listen;

   procedure Open_Ports (Bind_Ip : String; Return_Port : Natural) is
      Seen : Boolean;
   begin
      for I in 1 .. Master_Count loop
         Seen := False;
         for J in 1 .. Port_Count loop
            Seen := Seen or else Ports (J) = Masters (I).Port;
         end loop;
         if not Seen then
            Port_Count := Port_Count + 1;
            Ports (Port_Count) := Masters (I).Port;
         end if;
      end loop;
      for J in 1 .. Port_Count loop
         if not Bad then
            Bind_Listen (Listens (J), Bind_Ip, Ports (J));
            Note ("listening on " & Bind_Ip & ":" & Decimal (Long_Long_Integer (Ports (J))));
         end if;
      end loop;
      if not Bad then
         Bind_Listen (Return_Sock, "127.0.0.1", Return_Port);
      end if;
   end Open_Ports;

   procedure Close_Conn (C : in out Conn_Rec; Why : String) is
   begin
      GS.Close_Socket (C.Sock);
      Note ("conn " & Decimal (Long_Long_Integer (C.Id)) & " closed: " & Why);
      C.State := Free;
      C.Sock := GS.No_Socket;
   end Close_Conn;

   --  One frame-in record: every byte read for this frame, then the connection waits for its master-out line.
   procedure Emit (C : in out Conn_Rec) is
      H : UB.Unbounded_String;
   begin
      for K in 1 .. C.Have loop
         UB.Append (H, Hex2 (C.Buf (K)));
      end loop;
      Ada.Text_IO.Put_Line (Decimal (Long_Long_Integer (C.Id)) & Tab & Decimal (Long_Long_Integer (C.Slot)) & Tab
                            & Decimal (Now_Ms) & Tab & UB.To_String (H));
      Ada.Text_IO.Flush;
      C.State := Awaiting;
      C.Since := Now_Ms;
   end Emit;

   procedure Accept_Master (Listen : GS.Socket_Type; Port : Natural) is
      S    : GS.Socket_Type;
      Peer : GS.Sock_Addr_Type;
   begin
      GS.Accept_Socket (Listen, S, Peer);
      for C of Conns loop
         if C.State = Free then
            Next_Id := Next_Id + 1;
            C := (State => Idle, Sock => S, Id => Next_Id, Slot => Slot_Of (GS.Image (Peer.Addr), Port),
                  Have => 0, Need => 0, Since => Now_Ms, Buf => [others => 0]);
            Note ("conn " & Decimal (Long_Long_Integer (C.Id)) & " open: " & GS.Image (Peer.Addr) & " port "
                  & Decimal (Long_Long_Integer (Port)) & " slot " & Decimal (Long_Long_Integer (C.Slot)));
            return;
         end if;
      end loop;
      Note ("refused a connection: " & Decimal (Long_Long_Integer (Max_Conns)) & " masters already connected");
      GS.Close_Socket (S);
   exception
      when GS.Socket_Error =>
         null;
   end Accept_Master;

   --  Read what this frame still needs, never more: 7 header bytes, then Bytes_To_Read (L) when Length_Field_Ok (L).
   procedure Read_Master (C : in out Conn_Rec) is
      Item : SE.Stream_Element_Array (1 .. SE.Stream_Element_Offset (Cap));
      Last : SE.Stream_Element_Offset;
      L    : MB.Word;
   begin
      if C.State = Idle then
         C.State := Reading;
         C.Have := 0;
         C.Need := BD.Mbap_Header;
         C.Since := Now_Ms;
      end if;
      GS.Receive_Socket (C.Sock, Item (1 .. SE.Stream_Element_Offset (C.Need - C.Have)), Last);
      if Last < 1 then
         if C.Have > 0 then
            Emit (C);
         end if;
         Close_Conn (C, "peer closed");
         return;
      end if;
      for K in 1 .. Natural (Last) loop
         C.Buf (C.Have + K) := Byte (Item (SE.Stream_Element_Offset (K)));
      end loop;
      C.Have := C.Have + Natural (Last);
      if C.Have = BD.Mbap_Header and then C.Need = BD.Mbap_Header then
         L := MB.Length_Field (C.Buf (5), C.Buf (6));
         if MB.Length_Field_Ok (L) then
            C.Need := BD.Mbap_Header + TA.Bytes_To_Read (L);
         else
            Emit (C);
            Close_Conn (C, "Bad_Length_Field");
            return;
         end if;
      end if;
      if C.Have = C.Need then
         Emit (C);
      end if;
   exception
      when GS.Socket_Error =>
         Close_Conn (C, "socket error");
   end Read_Master;

   --  One master-out line: "<conn> TAB <ADU hex | ->".
   procedure Deliver (L : String) is
      Id  : constant Integer := Number (Field (L, 1));
      H   : constant String := Field (L, 2);
      Out_Bytes : SE.Stream_Element_Array (1 .. SE.Stream_Element_Offset (Cap));
      N   : Natural := 0;
      Last : SE.Stream_Element_Offset;
   begin
      if Field_Count (L) /= 2 or else Id < 1
        or else (H /= "-" and then (H'Length = 0 or else H'Length mod 2 /= 0 or else H'Length > 2 * Cap))
      then
         Note ("dropped a malformed master-out line");
         return;
      end if;
      if H /= "-" then
         for P in 0 .. H'Length / 2 - 1 loop
            if Hex_Digit (H (H'First + 2 * P)) < 0 or else Hex_Digit (H (H'First + 2 * P + 1)) < 0 then
               Note ("dropped a malformed master-out line");
               return;
            end if;
            N := N + 1;
            Out_Bytes (SE.Stream_Element_Offset (N)) :=
              SE.Stream_Element (Hex_Digit (H (H'First + 2 * P)) * 16 + Hex_Digit (H (H'First + 2 * P + 1)));
         end loop;
      end if;
      for C of Conns loop
         if C.State = Awaiting and then C.Id = Id then
            begin
               if N > 0 then
                  GS.Send_Socket (C.Sock, Out_Bytes (1 .. SE.Stream_Element_Offset (N)), Last);
               end if;
               C.State := Idle;
               C.Since := Now_Ms;
            exception
               when GS.Socket_Error =>
                  Close_Conn (C, "socket error on reply");
            end;
            return;
         end if;
      end loop;
      Note ("dropped a master-out line for conn " & Field (L, 1) & ": not waiting");
   end Deliver;

   procedure Read_Return (R : in out Return_Rec) is
      Item : SE.Stream_Element_Array (1 .. 4_096);
      Last : SE.Stream_Element_Offset;
   begin
      GS.Receive_Socket (R.Sock, Item, Last);
      if Last < 1 then
         GS.Close_Socket (R.Sock);
         R.Used := False;
         return;
      end if;
      for K in 1 .. Last loop
         if Character'Val (Item (K)) = Character'Val (10) then
            Deliver (UB.To_String (R.Line));
            R.Line := UB.Null_Unbounded_String;
         elsif UB.Length (R.Line) < Max_Line then
            UB.Append (R.Line, Character'Val (Item (K)));
         end if;
      end loop;
   exception
      when GS.Socket_Error =>
         GS.Close_Socket (R.Sock);
         R.Used := False;
   end Read_Return;

   procedure Accept_Return is
      S    : GS.Socket_Type;
      Peer : GS.Sock_Addr_Type;
   begin
      GS.Accept_Socket (Return_Sock, S, Peer);
      for R of Returns loop
         if not R.Used then
            R := (Used => True, Sock => S, Line => UB.Null_Unbounded_String);
            return;
         end if;
      end loop;
      GS.Close_Socket (S);
   exception
      when GS.Socket_Error =>
         null;
   end Accept_Return;

   --  The deadlines: a frame within Frame_Deadline_Ms of its first byte; idle and reply-wait limits.
   procedure Enforce_Deadlines is
      Now : constant Long_Long_Integer := Now_Ms;
   begin
      for C of Conns loop
         if C.State = Reading and then Now - C.Since > Frame_Deadline_Ms then
            Emit (C);
            Close_Conn (C, "frame deadline");
         elsif C.State = Idle and then Now - C.Since > Idle_Limit_Ms then
            Close_Conn (C, "idle limit");
         elsif C.State = Awaiting and then Now - C.Since > Reply_Limit_Ms then
            Close_Conn (C, "no master-out line");
         end if;
      end loop;
   end Enforce_Deadlines;

   procedure Serve is
      Sel    : GS.Selector_Type;
      R_Set  : GS.Socket_Set_Type;
      W_Set  : GS.Socket_Set_Type;
      Status : GS.Selector_Status;
   begin
      GS.Create_Selector (Sel);
      loop
         GS.Empty (R_Set);
         GS.Empty (W_Set);
         for J in 1 .. Port_Count loop
            GS.Set (R_Set, Listens (J));
         end loop;
         GS.Set (R_Set, Return_Sock);
         for R of Returns loop
            if R.Used then
               GS.Set (R_Set, R.Sock);
            end if;
         end loop;
         for C of Conns loop
            if C.State = Idle or else C.State = Reading then
               GS.Set (R_Set, C.Sock);
            end if;
         end loop;
         GS.Check_Selector (Sel, R_Set, W_Set, Status, 0.05);
         if Status = GS.Completed then
            for J in 1 .. Port_Count loop
               if GS.Is_Set (R_Set, Listens (J)) then
                  Accept_Master (Listens (J), Ports (J));
               end if;
            end loop;
            if GS.Is_Set (R_Set, Return_Sock) then
               Accept_Return;
            end if;
            for R of Returns loop
               if R.Used and then GS.Is_Set (R_Set, R.Sock) then
                  Read_Return (R);
               end if;
            end loop;
            for C of Conns loop
               if (C.State = Idle or else C.State = Reading) and then GS.Is_Set (R_Set, C.Sock) then
                  Read_Master (C);
               end if;
            end loop;
         end if;
         Enforce_Deadlines;
      end loop;
   end Serve;

begin
   --  SLOT BEGIN (main)
   if Ada.Command_Line.Argument_Count /= 3 then
      Note ("usage: mb_master_listener_main <site-dump> <bind IPv4> <return port>");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   if not Valid_Ipv4 (Ada.Command_Line.Argument (2))
     or else Number (Ada.Command_Line.Argument (3)) not in 1 .. 65_535
   then
      Note ("usage: the bind address or the return port is malformed");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   Load_Dump (Ada.Command_Line.Argument (1));
   if Bad then
      Note ("site dump unreadable, malformed, digest mismatch or no master line");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   Open_Ports (Ada.Command_Line.Argument (2), Number (Ada.Command_Line.Argument (3)));
   if Bad then
      Note ("a port cannot be bound");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   Serve;
   --  SLOT END (main)
end Mb_Master_Listener_Main;
