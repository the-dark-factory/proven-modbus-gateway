with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;
with Ada.Real_Time;
with Ada.Strings.Unbounded;
with GNAT.Sockets;
with GNAT.SHA256;
with Lovelace_Mb_Bounds_Pkg;
with Lovelace_Mb_Frame_Refusal_Pkg;
with Lovelace_Mb_Mbap_Pkg;
with Lovelace_Mb_Tcp_Adu_Pkg;
with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Pdu_Dispatch_Pkg;
with Lovelace_Mb_Policy_Shape_Pkg;
with Lovelace_Mb_Gate_Refusal_Pkg;
with Lovelace_Mb_Rate_Window_Pkg;
with Lovelace_Mb_Sequence_Pkg;
with Lovelace_Mb_Gate_Decide_Pkg;

--  plc-forwarder (edge, built-not-proved), lovelace-mb round A, W4: the PLC side [TCP s.3.1.3, s.4.4.1]. One TCP
--  connection to the PLC (made on first use and after any failure). Each request is sent BYTE FOR BYTE (R-MB-18); the
--  reply is read as 7 header bytes, then Tcp_Adu.Bytes_To_Read (L) more only when Mbap.Length_Field_Ok (L), within
--  Reply_Deadline_Ms (R-MB-14; else silent), never past Cap bytes. Connect or send failure: unreachable. Bytes waiting
--  before a send are an unmatched reply, discarded. DEFENCE IN DEPTH: first the record is framed, judged
--  (Pdu_Dispatch.Request_Ok) and re-decided by the PROVEN Gate_Decide.Decide on a FRESH state (no write counted, no
--  trigger, Now 0): Gate_Pass exactly when the stateless rules pass, so by Decide's Post nothing reaches the PLC that its
--  slot may not send, that is not writable, or that writes a value outside a declared limit. D-W2E-4 (open ruling):
--  Trailing_Refused True appends bytes already waiting after the ADU (Long_Adu, refused 04 downstream); False hands on
--  exactly 6 + L bytes and discards the rest. Deadline and byte bound (CVE-2026-51539 class) are TESTED, not proved.
--  CLI: mb_plc_forwarder_main <site-dump> <PLC IPv4> <PLC port>; the dump's digest is recomputed and its rules loaded
--  only if Policy_Shape.Valid_Table holds (else exit 2). Input lines: <conn> TAB <slot> TAB <ms> TAB <ADU hex>.
--  Output lines, flushed: <conn> TAB <slot> TAB <ADU hex> TAB <outcome> TAB <detail>, outcome / detail one of
--  refused / <verdict name> (nothing sent), reply / <reply hex>, silent / -, unreachable / -. A malformed input
--  line is noted on standard error and dropped; exit 0 at end of input. A gate-held record (already in the output
--  form, outcome "refused") is passed through unchanged and nothing is sent: one pipeline, one writer (D-W4E-3).

procedure Mb_Plc_Forwarder_Main is
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Real_Time.Time;
   use type GNAT.Sockets.Selector_Status;
   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict;
   use type Lovelace_Mb_Gate_Refusal_Pkg.Gate_Verdict;

   package BD renames Lovelace_Mb_Bounds_Pkg;
   package FR renames Lovelace_Mb_Frame_Refusal_Pkg;
   package MB renames Lovelace_Mb_Mbap_Pkg;
   package TA renames Lovelace_Mb_Tcp_Adu_Pkg;
   package PR renames Lovelace_Mb_Pdu_Refusal_Pkg;
   package PF renames Lovelace_Mb_Pdu_Fields_Pkg;
   package FC renames Lovelace_Mb_Fc_Catalog_Pkg;
   package PD renames Lovelace_Mb_Pdu_Dispatch_Pkg;
   package PS renames Lovelace_Mb_Policy_Shape_Pkg;
   package GR renames Lovelace_Mb_Gate_Refusal_Pkg;
   package RW renames Lovelace_Mb_Rate_Window_Pkg;
   package SQ renames Lovelace_Mb_Sequence_Pkg;
   package GD renames Lovelace_Mb_Gate_Decide_Pkg;
   package GS renames GNAT.Sockets;
   package UB renames Ada.Strings.Unbounded;
   package SE renames Ada.Streams;

   Tab                : constant Character := Character'Val (9);
   Max_File           : constant := 1_048_576;
   Max_Hex            : constant := 65_536;
   Reply_Deadline_Ms  : constant := 1_000;
   Connect_Timeout_Ms : constant := 1_000;
   Trailing_Refused   : constant Boolean := True;
   Cap                : constant := BD.Max_Tcp_Adu + 1;

   subtype Byte is Natural range 0 .. 255;
   type Adu_Bytes is array (1 .. Cap) of Byte;

   T : PS.Policy_Table :=
     (Allow          => [others => [others => False]],
      Range_Count    => 0,
      Ranges         => [others => (Target => PS.Coil_Target, Lo => 0, Hi => 0)],
      Limit_Count    => 0,
      Limits         => [others => (Register => 0, Min => 0, Max => 0)],
      Rates          => [others => (Max_Writes => 1, Window_Ms => 86_400_000)],
      Sequence_Count => 0,
      Sequences      => [others => (Trigger_Step => (Target => PS.Coil_Target, Location => 0, Value => 0),
                                    Then_Step    => (Target => PS.Coil_Target, Location => 0, Value => 0),
                                    Within_Ms    => 1)]);
   Fresh_Rates : constant RW.Rate_States := [others => (Window_Start => 0, Count => 0)];
   Fresh_Seqs  : constant SQ.Seq_States := [others => (Trigger_Seen => False, Trigger_Ms => 0)];

   Plc_Ip    : UB.Unbounded_String;
   Plc_Port  : Natural := 0;
   Plc       : GS.Socket_Type := GS.No_Socket;
   Connected : Boolean := False;
   T0        : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
   Bad       : Boolean := False;

   ------------------------------------------------------------------ text helpers
   function Hex_Digit (C : Character) return Integer is
     (if C in '0' .. '9' then Character'Pos (C) - 48
      elsif C in 'a' .. 'f' then Character'Pos (C) - 87
      elsif C in 'A' .. 'F' then Character'Pos (C) - 55
      else -1);

   function Hex (A : Adu_Bytes; N : Natural) return String is
      D : constant String := "0123456789abcdef";
      R : String (1 .. 2 * N);
   begin
      for K in 1 .. N loop
         R (2 * K - 1) := D (A (K) / 16 + 1);
         R (2 * K) := D (A (K) mod 16 + 1);
      end loop;
      return R;
   end Hex;

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

   function Digits_Only (S : String) return Boolean is
     (S'Length in 1 .. 19 and then (for all C of S => C in '0' .. '9'));

   function Now_Ms return Long_Long_Integer is
     (Long_Long_Integer (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - T0) * 1000));

   procedure Note (S : String) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "plc-forwarder: " & S);
   end Note;

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

   function Frame_Name (V : FR.Frame_Verdict) return String is
     (case V is
         when FR.Frame_Ok         => "Frame_Ok",
         when FR.Bad_Protocol_Id  => "Bad_Protocol_Id",
         when FR.Bad_Length_Field => "Bad_Length_Field",
         when FR.Short_Adu        => "Short_Adu",
         when FR.Long_Adu         => "Long_Adu",
         when FR.Bad_Crc          => "Bad_Crc",
         when FR.Reserved_Address => "Reserved_Address");

   function Pdu_Name (V : PR.Pdu_Verdict) return String is
     (case V is
         when PR.Pdu_Ok               => "Pdu_Ok",
         when PR.Unknown_Function     => "Unknown_Function",
         when PR.Unsupported_Mei_Type => "Unsupported_Mei_Type",
         when PR.Bad_Pdu_Length       => "Bad_Pdu_Length",
         when PR.Bad_Quantity         => "Bad_Quantity",
         when PR.Bad_Byte_Count       => "Bad_Byte_Count",
         when PR.Bad_Coil_Value       => "Bad_Coil_Value",
         when PR.Bad_Device_Id_Code   => "Bad_Device_Id_Code",
         when PR.Address_Overflow     => "Address_Overflow",
         when PR.Echo_Mismatch        => "Echo_Mismatch");

   function Gate_Name (V : GR.Gate_Verdict) return String is
     (case V is
         when GR.Gate_Pass            => "Gate_Pass",
         when GR.Unknown_Master       => "Unknown_Master",
         when GR.Function_Not_Allowed => "Function_Not_Allowed",
         when GR.Address_Not_Writable => "Address_Not_Writable",
         when GR.Mask_On_Limited      => "Mask_On_Limited",
         when GR.Value_Below_Limit    => "Value_Below_Limit",
         when GR.Value_Above_Limit    => "Value_Above_Limit",
         when GR.Rate_Exceeded        => "Rate_Exceeded",
         when GR.Forbidden_Sequence   => "Forbidden_Sequence");

   ------------------------------------------------------------------ the site dump -> Policy_Table
   function Target_Of (S : String) return Integer is
     (if S = "coil" then 0 elsif S = "register" then 1 else -1);

   function Target (K : Integer) return PS.Write_Target is
     (if K = 0 then PS.Coil_Target else PS.Register_Target);

   procedure Load_Rule (L : String) is
      K : constant String := Field (L, 1);
      N : constant Natural := Field_Count (L);
   begin
      if K = "allow" and then N = 3 and then Number (Field (L, 2)) in 0 .. 16 then
         declare
            C     : constant String := Field (L, 3) & ",";
            First : Positive := C'First;
         begin
            if C /= "-," then
               for P in C'Range loop
                  if C (P) = ',' then
                     if Number (C (First .. P - 1)) not in 0 .. 255 then
                        Bad := True;
                     else
                        T.Allow (Number (Field (L, 2))) (FC.Function_Kind_Of (Number (C (First .. P - 1)))) := True;
                     end if;
                     First := P + 1;
                  end if;
               end loop;
            end if;
         end;
      elsif K = "writable" and then N = 4 and then Target_Of (Field (L, 2)) >= 0
        and then Number (Field (L, 3)) in 0 .. 65_535 and then Number (Field (L, 4)) in 0 .. 65_535
        and then T.Range_Count < 32
      then
         T.Range_Count := T.Range_Count + 1;
         T.Ranges (T.Range_Count) :=
           (Target => Target (Target_Of (Field (L, 2))), Lo => Number (Field (L, 3)), Hi => Number (Field (L, 4)));
      elsif K = "limit" and then N = 5 and then Number (Field (L, 2)) in 0 .. 65_535
        and then Number (Field (L, 3)) in 0 .. 65_535 and then Number (Field (L, 4)) in 0 .. 65_535
        and then T.Limit_Count < 64
      then
         T.Limit_Count := T.Limit_Count + 1;
         T.Limits (T.Limit_Count) :=
           (Register => Number (Field (L, 2)), Min => Number (Field (L, 3)), Max => Number (Field (L, 4)));
      elsif K = "rate" and then N = 5 and then Number (Field (L, 2)) in 1 .. 16
        and then Number (Field (L, 3)) >= 0 and then Number (Field (L, 4)) >= 0
      then
         T.Rates (Number (Field (L, 2))) := (Max_Writes => Number (Field (L, 3)), Window_Ms => Number (Field (L, 4)));
      elsif K = "sequence" and then N = 8 and then Target_Of (Field (L, 2)) >= 0 and then Target_Of (Field (L, 5)) >= 0
        and then (for all I in 3 .. 4 => Number (Field (L, I)) in 0 .. 65_535)
        and then (for all I in 6 .. 7 => Number (Field (L, I)) in 0 .. 65_535)
        and then Number (Field (L, 8)) >= 0 and then T.Sequence_Count < 16
      then
         T.Sequence_Count := T.Sequence_Count + 1;
         T.Sequences (T.Sequence_Count) :=
           (Trigger_Step => (Target => Target (Target_Of (Field (L, 2))), Location => Number (Field (L, 3)),
                             Value => Number (Field (L, 4))),
            Then_Step    => (Target => Target (Target_Of (Field (L, 5))), Location => Number (Field (L, 6)),
                             Value => Number (Field (L, 7))),
            Within_Ms    => Number (Field (L, 8)));
      elsif K /= "master" then
         Bad := True;
      end if;
   end Load_Rule;

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
               Load_Rule (L);
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (F);
      Bad := Bad or else not Digest or else not PS.Valid_Table (T);
   end Load_Dump;

   ------------------------------------------------------------------ framing (as response-check)
   function Adu_Frame (A : Adu_Bytes; N : Natural) return FR.Frame_Verdict is
      V : FR.Frame_Verdict;
      L : constant MB.Word := (if N >= BD.Mbap_Header then MB.Length_Field (A (5), A (6)) else BD.Min_Length_Field);
   begin
      if N >= BD.Mbap_Header then
         V := MB.Header_Verdict (MB.Protocol_Id (A (3), A (4)), L);
         if not FR.Is_Refusal (V) then
            V := TA.Adu_Verdict (N, L);
         end if;
      else
         V := TA.Adu_Verdict (N, BD.Min_Length_Field);
      end if;
      return V;
   end Adu_Frame;

   function Pdu_Of (A : Adu_Bytes; N : PF.Pdu_Length) return PF.Pdu_Bytes is
      P : PF.Pdu_Bytes := [others => 0];
   begin
      for K in 1 .. N loop
         P (K) := A (BD.Mbap_Header + K);
      end loop;
      return P;
   end Pdu_Of;

   ------------------------------------------------------------------ the PLC connection
   procedure Drop_Plc (Why : String) is
   begin
      if Connected then
         GS.Close_Socket (Plc);
         Note ("PLC connection closed: " & Why);
      end if;
      Connected := False;
   end Drop_Plc;

   procedure Connect_Plc is
      Status : GS.Selector_Status;
   begin
      GS.Create_Socket (Plc, GS.Family_Inet, GS.Socket_Stream);
      GS.Connect_Socket (Plc, (GS.Family_Inet, GS.Inet_Addr (UB.To_String (Plc_Ip)), GS.Port_Type (Plc_Port)),
                         Duration (Connect_Timeout_Ms) / 1000, null, Status);
      Connected := Status = GS.Completed;
      if not Connected then
         GS.Close_Socket (Plc);
      end if;
   exception
      when GS.Socket_Error =>
         GS.Close_Socket (Plc);
         Connected := False;
   end Connect_Plc;

   --  True when the PLC socket is readable within Ms milliseconds (0: only what is already there).
   function Readable (Ms : Long_Long_Integer) return Boolean is
      Sel    : GS.Selector_Type;
      R_Set  : GS.Socket_Set_Type;
      W_Set  : GS.Socket_Set_Type;
      Status : GS.Selector_Status;
   begin
      GS.Create_Selector (Sel);
      GS.Set (R_Set, Plc);
      GS.Check_Selector (Sel, R_Set, W_Set, Status, Duration (Ms) / 1000);
      GS.Close_Selector (Sel);
      return Status = GS.Completed and then GS.Is_Set (R_Set, Plc);
   end Readable;

   --  Bytes already waiting before a send belong to no request: an unmatched reply, discarded.
   procedure Drain is
      Item : SE.Stream_Element_Array (1 .. 4_096);
      Last : SE.Stream_Element_Offset;
   begin
      for Round in 1 .. 16 loop
         exit when not Connected or else not Readable (0);
         GS.Receive_Socket (Plc, Item, Last);
         if Last < 1 then
            Drop_Plc ("closed by the PLC");
         else
            Note ("discarded unmatched bytes from the PLC");
         end if;
      end loop;
   exception
      when GS.Socket_Error =>
         Drop_Plc ("socket error");
   end Drain;

   function Send_All (A : Adu_Bytes; N : Natural) return Boolean is
      Item : SE.Stream_Element_Array (1 .. SE.Stream_Element_Offset (N));
      Done : SE.Stream_Element_Offset := 0;
      Last : SE.Stream_Element_Offset;
   begin
      for K in 1 .. N loop
         Item (SE.Stream_Element_Offset (K)) := SE.Stream_Element (A (K));
      end loop;
      while Done < Item'Last loop
         GS.Send_Socket (Plc, Item (Done + 1 .. Item'Last), Last);
         if Last <= Done then
            return False;
         end if;
         Done := Last;
      end loop;
      return True;
   exception
      when GS.Socket_Error =>
         return False;
   end Send_All;

   --  Read one reply within the deadline: the header, then exactly what its length field announces; then the
   --  trailing bytes already waiting (D-W2E-4). Ok = False is Plc_Silent (no complete reply in time).
   procedure Read_Reply (R : out Adu_Bytes; Nr : out Natural; Ok : out Boolean) is
      Item  : SE.Stream_Element_Array (1 .. SE.Stream_Element_Offset (Cap));
      Last  : SE.Stream_Element_Offset;
      Need  : Natural := BD.Mbap_Header;
      Start : constant Long_Long_Integer := Now_Ms;
      L     : MB.Word;
   begin
      R := [others => 0];
      Nr := 0;
      Ok := False;
      while Nr < Need loop
         if Now_Ms - Start >= Reply_Deadline_Ms or else not Readable (Reply_Deadline_Ms - (Now_Ms - Start)) then
            Drop_Plc ("reply deadline");
            return;
         end if;
         GS.Receive_Socket (Plc, Item (1 .. SE.Stream_Element_Offset (Need - Nr)), Last);
         if Last < 1 then
            Drop_Plc ("closed by the PLC");
            return;
         end if;
         for K in 1 .. Natural (Last) loop
            R (Nr + K) := Byte (Item (SE.Stream_Element_Offset (K)));
         end loop;
         Nr := Nr + Natural (Last);
         if Nr = BD.Mbap_Header and then Need = BD.Mbap_Header then
            L := MB.Length_Field (R (5), R (6));
            if MB.Length_Field_Ok (L) then
               Need := BD.Mbap_Header + TA.Bytes_To_Read (L);
            else
               Ok := True;
               Drop_Plc ("Bad_Length_Field");
               return;
            end if;
         end if;
      end loop;
      Ok := True;
      if Readable (0) then
         GS.Receive_Socket (Plc, Item (1 .. SE.Stream_Element_Offset (Cap - Nr)), Last);
         if Last < 1 then
            Drop_Plc ("closed by the PLC");
         elsif Trailing_Refused then
            for K in 1 .. Natural (Last) loop
               R (Nr + K) := Byte (Item (SE.Stream_Element_Offset (K)));
            end loop;
            Nr := Nr + Natural (Last);
         else
            Note ("discarded trailing bytes (an unmatched next reply)");
         end if;
      end if;
   exception
      when GS.Socket_Error =>
         Drop_Plc ("socket error");
         Ok := False;
   end Read_Reply;

   ------------------------------------------------------------------ one gate-pass record
   procedure Put (Conn, Slot : String; Q : Adu_Bytes; Nq : Natural; Outcome, Detail : String) is
   begin
      Ada.Text_IO.Put_Line (Conn & Tab & Slot & Tab & Hex (Q, Nq) & Tab & Outcome & Tab & Detail);
      Ada.Text_IO.Flush;
   end Put;

   procedure Forward (Conn, Slot : String; Q : Adu_Bytes; Nq : Natural) is
      R  : Adu_Bytes;
      Nr : Natural;
      Ok : Boolean;
   begin
      Drain;
      if not Connected then
         Connect_Plc;
      end if;
      if Connected and then not Send_All (Q, Nq) then
         Drop_Plc ("send failed");
         Connect_Plc;
         if Connected and then not Send_All (Q, Nq) then
            Drop_Plc ("send failed");
         end if;
      end if;
      if not Connected then
         Put (Conn, Slot, Q, Nq, "unreachable", "-");
         return;
      end if;
      Read_Reply (R, Nr, Ok);
      if Ok then
         Put (Conn, Slot, Q, Nq, "reply", Hex (R, Nr));
      else
         Put (Conn, Slot, Q, Nq, "silent", "-");
      end if;
   end Forward;

   procedure Handle (L : String) is
      H  : constant String := Field (L, 4);
      Q  : Adu_Bytes := [others => 0];
      Nq : Natural := 0;
      Vq : FR.Frame_Verdict;
   begin
      if Field_Count (L) = 5 and then Field (L, 4) = "refused" and then Number (Field (L, 1)) >= 1
        and then Number (Field (L, 2)) in 0 .. 16
      then
         Ada.Text_IO.Put_Line (L);
         Ada.Text_IO.Flush;
         return;
      end if;
      if Field_Count (L) /= 4 or else Number (Field (L, 1)) < 1 or else Number (Field (L, 2)) not in 0 .. 16
        or else not Digits_Only (Field (L, 3)) or else H'Length = 0 or else H'Length > Max_Hex
        or else H'Length mod 2 /= 0
        or else (for some C of H => Hex_Digit (C) < 0)
      then
         Note ("dropped a malformed gate-pass line");
         return;
      end if;
      for P in 0 .. H'Length / 2 - 1 loop
         if Nq < Cap then
            Nq := Nq + 1;
            Q (Nq) := Hex_Digit (H (H'First + 2 * P)) * 16 + Hex_Digit (H (H'First + 2 * P + 1));
         end if;
      end loop;
      Vq := Adu_Frame (Q, Nq);
      if Vq /= FR.Frame_Ok then
         Put (Field (L, 1), Field (L, 2), Q, Nq, "refused", Frame_Name (Vq));
         return;
      end if;
      declare
         N : constant PF.Pdu_Length := Nq - BD.Mbap_Header;
         P : constant PF.Pdu_Bytes := Pdu_Of (Q, N);
      begin
         if not PD.Request_Ok (P, N) then
            Put (Field (L, 1), Field (L, 2), Q, Nq, "refused", Pdu_Name (PD.Request_Verdict (P, N)));
            return;
         end if;
         declare
            V : constant GR.Gate_Verdict := GD.Decide (T, Number (Field (L, 2)), P, N, Fresh_Rates, Fresh_Seqs, 0);
         begin
            if V /= GR.Gate_Pass then
               Put (Field (L, 1), Field (L, 2), Q, Nq, "refused", Gate_Name (V));
               return;
            end if;
         end;
      end;
      Forward (Field (L, 1), Field (L, 2), Q, Nq);
   end Handle;

begin
   --  SLOT BEGIN (main)
   if Ada.Command_Line.Argument_Count /= 3 then
      Note ("usage: mb_plc_forwarder_main <site-dump> <PLC IPv4> <PLC port>");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   if not Valid_Ipv4 (Ada.Command_Line.Argument (2))
     or else Number (Ada.Command_Line.Argument (3)) not in 1 .. 65_535
   then
      Note ("usage: the PLC address or port is malformed");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   Plc_Ip := UB.To_Unbounded_String (Ada.Command_Line.Argument (2));
   Plc_Port := Number (Ada.Command_Line.Argument (3));
   Load_Dump (Ada.Command_Line.Argument (1));
   if Bad then
      Note ("site dump unreadable, malformed, digest mismatch or not a Valid_Table");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   while not Ada.Text_IO.End_Of_File loop
      Handle (Ada.Text_IO.Get_Line);
   end loop;
   Drop_Plc ("end of input");
   Ada.Command_Line.Set_Exit_Status (0);
   --  SLOT END (main)
end Mb_Plc_Forwarder_Main;
