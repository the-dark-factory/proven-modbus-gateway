with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Directories;
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
with Lovelace_Mb_Gate_Decide_Pkg;
with Lovelace_Mb_Gate_Next_Pkg;

--  policy-gate (edge, built-not-proved), lovelace-mb round A, W3: the water-gateway policy gate, LIVE. It holds the
--  ONLY gate state (R-MB-5, R-MB-17): one Gate_Next.Gate_State, the rate window of each master slot and the trigger of
--  each sequence rule, carried from one request to the next for the life of the process. Per frame-in record
--  "<conn> TAB <slot> TAB <ms> TAB <ADU hex>" (master-listener's line, in order): the record's time is the clock
--  (R-MB-27), held non-decreasing (a time below the last one is taken as the last one) and saturated at Clock_Ms'Last,
--  so every stored time stays at or before Now and the cores' preconditions hold; the ADU is framed (Mbap.Header_Verdict,
--  Tcp_Adu.Adu_Verdict) and judged (Pdu_Dispatch.Request_Ok) here, live; a Pdu_Ok request is decided by the PROVEN
--  Gate_Decide.Decide over the table, the record's slot, the state and Now, and the state then becomes the PROVEN
--  Gate_Next.Next_State of that verdict (only a passed write changes it: a refusal never consumes the rate or arms a
--  sequence; a read never does). Output, one line per well-formed input line, flushed, in input order:
--    gate-pass  the frame-in line, unchanged                              (Gate_Pass)
--    gate-held  <conn> TAB <slot> TAB <ADU hex> TAB refused TAB <name>    (frame, PDU or gate verdict, by name)
--  A frame or PDU refusal never reaches Decide and leaves the state as it was. A malformed input line is noted on
--  standard error and dropped. CLI: mb_policy_gate_main <site-dump>; the dump's digest is recomputed and its rules
--  loaded only if Policy_Shape.Valid_Table holds (else exit 2). Exit 0 at end of input.

procedure Mb_Policy_Gate_Main is
   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict;
   use type Lovelace_Mb_Gate_Refusal_Pkg.Gate_Verdict;
   use type Lovelace_Mb_Policy_Shape_Pkg.Clock_Ms;

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
   package GD renames Lovelace_Mb_Gate_Decide_Pkg;
   package GN renames Lovelace_Mb_Gate_Next_Pkg;

   Tab      : constant Character := Character'Val (9);
   Max_File : constant := 1_048_576;
   Max_Hex  : constant := 65_536;
   Cap      : constant := BD.Max_Tcp_Adu + 1;

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

   --  THE GATE STATE: one value for the whole process, never reset between requests.
   S       : GN.Gate_State := GN.Initial_State;
   Last_Ms : PS.Clock_Ms := 0;
   Bad     : Boolean := False;

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

   --  The record's time as a Clock_Ms (R-MB-27), saturated at Clock_Ms'Last. Pre: Digits_Only (D).
   function Clock_Of (D : String) return PS.Clock_Ms is
      V : PS.Clock_Ms := 0;
   begin
      for C of D loop
         if V > (PS.Clock_Ms'Last - 9) / 10 then
            return PS.Clock_Ms'Last;
         end if;
         V := V * 10 + PS.Clock_Ms (Character'Pos (C) - 48);
      end loop;
      return V;
   end Clock_Of;

   procedure Note (S : String) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "policy-gate: " & S);
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

   ------------------------------------------------------------------ framing (as plc-forwarder)
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

   ------------------------------------------------------------------ one frame-in record
   procedure Held (Conn, Slot : String; Q : Adu_Bytes; Nq : Natural; Name : String) is
   begin
      Ada.Text_IO.Put_Line (Conn & Tab & Slot & Tab & Hex (Q, Nq) & Tab & "refused" & Tab & Name);
      Ada.Text_IO.Flush;
   end Held;

   procedure Pass (L : String) is
   begin
      Ada.Text_IO.Put_Line (L);
      Ada.Text_IO.Flush;
   end Pass;

   procedure Handle (L : String) is
      H   : constant String := Field (L, 4);
      Q   : Adu_Bytes := [others => 0];
      Nq  : Natural := 0;
      Vq  : FR.Frame_Verdict;
      Now : PS.Clock_Ms;
   begin
      if Field_Count (L) /= 4 or else Number (Field (L, 1)) < 1 or else Number (Field (L, 2)) not in 0 .. 16
        or else not Digits_Only (Field (L, 3)) or else H'Length = 0 or else H'Length > Max_Hex
        or else H'Length mod 2 /= 0
        or else (for some C of H => Hex_Digit (C) < 0)
      then
         Note ("dropped a malformed frame-in line");
         return;
      end if;
      Now := Clock_Of (Field (L, 3));
      if Now < Last_Ms then
         Now := Last_Ms;
      end if;
      Last_Ms := Now;
      for P in 0 .. H'Length / 2 - 1 loop
         if Nq < Cap then
            Nq := Nq + 1;
            Q (Nq) := Hex_Digit (H (H'First + 2 * P)) * 16 + Hex_Digit (H (H'First + 2 * P + 1));
         end if;
      end loop;
      Vq := Adu_Frame (Q, Nq);
      if Vq /= FR.Frame_Ok then
         Held (Field (L, 1), Field (L, 2), Q, Nq, Frame_Name (Vq));
         return;
      end if;
      declare
         N : constant PF.Pdu_Length := Nq - BD.Mbap_Header;
         P : constant PF.Pdu_Bytes := Pdu_Of (Q, N);
      begin
         if not PD.Request_Ok (P, N) then
            Held (Field (L, 1), Field (L, 2), Q, Nq, Pdu_Name (PD.Request_Verdict (P, N)));
            return;
         end if;
         declare
            Slot : constant PS.Master_Slot := Number (Field (L, 2));
            V    : constant GR.Gate_Verdict := GD.Decide (T, Slot, P, N, S.Rates, S.Seqs, Now);
         begin
            S := GN.Next_State (T, S, V, Slot, P, N, Now);
            if V = GR.Gate_Pass then
               Pass (L);
            else
               Held (Field (L, 1), Field (L, 2), Q, Nq, Gate_Name (V));
            end if;
         end;
      end;
   end Handle;

begin
   --  SLOT BEGIN (main)
   if Ada.Command_Line.Argument_Count /= 1 then
      Note ("usage: mb_policy_gate_main <site-dump>");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   Load_Dump (Ada.Command_Line.Argument (1));
   if Bad then
      Note ("site dump unreadable, malformed, digest mismatch or not a Valid_Table");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   S := GN.Initial_State;
   Last_Ms := 0;
   while not Ada.Text_IO.End_Of_File loop
      Handle (Ada.Text_IO.Get_Line);
   end loop;
   Ada.Command_Line.Set_Exit_Status (0);
   --  SLOT END (main)
end Mb_Policy_Gate_Main;
