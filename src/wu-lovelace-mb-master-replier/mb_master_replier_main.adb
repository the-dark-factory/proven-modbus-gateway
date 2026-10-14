with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings.Unbounded;
with GNAT.Sockets;
with Lovelace_Mb_Bounds_Pkg;
with Lovelace_Mb_Frame_Refusal_Pkg;
with Lovelace_Mb_Mbap_Pkg;
with Lovelace_Mb_Tcp_Adu_Pkg;
with Lovelace_Mb_Pdu_Refusal_Pkg;
with Lovelace_Mb_Pdu_Fields_Pkg;
with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Pdu_Dispatch_Pkg;
with Lovelace_Mb_Pdu_View_Pkg;
with Lovelace_Mb_Resp_Read_Pkg;
with Lovelace_Mb_Resp_Echo_Pkg;
with Lovelace_Mb_Resp_Exception_Pkg;
with Lovelace_Mb_Proxy_Match_Pkg;
with Lovelace_Mb_Gate_Refusal_Pkg;

--  master-replier (edge, built-not-proved), lovelace-mb round A, W4: decides what each master receives [TCP s.3.1.3,
--  s.4.4] [APP s.7]. It also holds response-check's LIVE role (D-W4E-2): a PLC reply is judged by the same proven
--  cores, in the same order, as response-check's oracle mode. Every decision is a carried PROVEN core:
--    the request: Mbap.Header_Verdict, Tcp_Adu.Adu_Verdict -- any frame refusal is answered with NOTHING
--      (Frame_Refusal.Frame_Answer = Answer_Silent, R-MB-9); Pdu_Dispatch.Request_Ok -- a PDU refusal is answered with
--      Pdu_Dispatch.Refusal_Reply (R-MB-8, R-MB-10, R-MB-29);
--    a gate refusal (named by the policy-gate or the forwarder) with Gate_Refusal.Gate_Exception (R-MB-12);
--    a PLC reply: framed (Mbap, Tcp_Adu), matched (Proxy_Match.Reply_Belongs, R-MB-18, R-MB-22), checked by its code
--      (Resp_Read.Read_Resp_Verdict, Device_Id_Head_Verdict + Object_Fits / Next_Object_Pos; Resp_Echo.Echo_Verdict;
--      Resp_Exception.Exception_Reply_Check) and relayed AS RECEIVED, or answered Relay_Code (Plc_Malformed) = 04;
--    no reply: Relay_Code (Plc_Silent) = 0B; no PLC: Relay_Code (Plc_Unreachable) = 0A (R-MB-14);
--    every exception ADU is Proxy_Match.Reply_Header (the request's transaction id and unit id, length 3) followed
--      by the exception function code and the code: Exception_Adu_Length = 9 bytes.
--  A record naming a refusal that its own request bytes contradict is answered 04 and logged Record_Inconsistent.
--
--  CLI contract:
--    mb_master_replier_main <return port | -> [<events-file>]
--  standard input, one record per line (from the policy-gate's gate-held output and the plc-forwarder's output):
--    <conn> TAB <slot> TAB <request ADU hex> TAB <outcome> TAB <detail>, outcome / detail one of
--    refused / <frame, PDU or gate verdict name>, reply / <reply ADU hex>, silent / -, unreachable / -
--  output, one master-out line per record, flushed: <conn> TAB <ADU hex | -> ("-": the master gets nothing), written
--    to 127.0.0.1:<return port> (the master-listener) or, for "-", to standard output.
--  <events-file> (optional): created; one MB_EVENTS record (nine fields, eight TABs: activity, event, mode, slot,
--    unit, fc, address, refusal name, detail) at start and per record ("relayed" or "refused" with the name);
--    the master-out lines are byte-identical with and without it.
--  A malformed record is noted on standard error and dropped. exit 0 at end of input; exit 2: usage, the events
--  file cannot be created, or the return port cannot be connected.

procedure Mb_Master_Replier_Main is
   use type Ada.Streams.Stream_Element_Offset;
   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Verdict;
   use type Lovelace_Mb_Frame_Refusal_Pkg.Frame_Answer_Kind;
   use type Lovelace_Mb_Pdu_Refusal_Pkg.Pdu_Verdict;
   use type Lovelace_Mb_Fc_Catalog_Pkg.Function_Kind;
   use type Lovelace_Mb_Resp_Exception_Pkg.Exception_Reply_Verdict;

   package BD renames Lovelace_Mb_Bounds_Pkg;
   package FR renames Lovelace_Mb_Frame_Refusal_Pkg;
   package MB renames Lovelace_Mb_Mbap_Pkg;
   package TA renames Lovelace_Mb_Tcp_Adu_Pkg;
   package PR renames Lovelace_Mb_Pdu_Refusal_Pkg;
   package PF renames Lovelace_Mb_Pdu_Fields_Pkg;
   package FC renames Lovelace_Mb_Fc_Catalog_Pkg;
   package PD renames Lovelace_Mb_Pdu_Dispatch_Pkg;
   package PV renames Lovelace_Mb_Pdu_View_Pkg;
   package RR renames Lovelace_Mb_Resp_Read_Pkg;
   package RE renames Lovelace_Mb_Resp_Echo_Pkg;
   package RX renames Lovelace_Mb_Resp_Exception_Pkg;
   package PM renames Lovelace_Mb_Proxy_Match_Pkg;
   package GR renames Lovelace_Mb_Gate_Refusal_Pkg;
   package GS renames GNAT.Sockets;
   package UB renames Ada.Strings.Unbounded;
   package SE renames Ada.Streams;

   Tab     : constant Character := Character'Val (9);
   Max_Hex : constant := 65_536;
   Cap     : constant := BD.Max_Tcp_Adu + 1;

   subtype Byte is Natural range 0 .. 255;
   type Adu_Bytes is array (1 .. Cap) of Byte;

   To_Stdout  : Boolean := True;
   Sink       : GS.Socket_Type := GS.No_Socket;
   Sink_Port  : Natural := 0;
   Sink_Ok    : Boolean := False;
   Events     : Ada.Text_IO.File_Type;
   Has_Events : Boolean := False;
   Bad        : Boolean := False;

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

   function Hex2 (V : Byte) return String is
      D : constant String := "0123456789abcdef";
   begin
      return [D (V / 16 + 1), D (V mod 16 + 1)];
   end Hex2;

   function Decimal (N : Natural) return String is
      D : constant String := "0123456789";
      R : String (1 .. 10);
      P : Natural := R'Last + 1;
      W : Natural := N;
   begin
      loop
         P := P - 1;
         R (P) := D (W mod 10 + 1);
         W := W / 10;
         exit when W = 0;
      end loop;
      return R (P .. R'Last);
   end Decimal;

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

   procedure Note (S : String) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "master-replier: " & S);
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
         when PR.Pdu_Ok               => "Reply_Ok",
         when PR.Unknown_Function     => "Unknown_Function",
         when PR.Unsupported_Mei_Type => "Unsupported_Mei_Type",
         when PR.Bad_Pdu_Length       => "Bad_Pdu_Length",
         when PR.Bad_Quantity         => "Bad_Quantity",
         when PR.Bad_Byte_Count       => "Bad_Byte_Count",
         when PR.Bad_Coil_Value       => "Bad_Coil_Value",
         when PR.Bad_Device_Id_Code   => "Bad_Device_Id_Code",
         when PR.Address_Overflow     => "Address_Overflow",
         when PR.Echo_Mismatch        => "Echo_Mismatch");

   function Exception_Name (V : RX.Exception_Reply_Verdict) return String is
     (case V is
         when RX.Exception_Accepted       => "Exception_Accepted",
         when RX.Wrong_Exception_Fc       => "Wrong_Exception_Fc",
         when RX.Bad_Exception_Length     => "Bad_Exception_Length",
         when RX.Undefined_Exception_Code => "Undefined_Exception_Code");

   function Gate_Name (V : GR.Gate_Refusal) return String is
     (case V is
         when GR.Unknown_Master       => "Unknown_Master",
         when GR.Function_Not_Allowed => "Function_Not_Allowed",
         when GR.Address_Not_Writable => "Address_Not_Writable",
         when GR.Mask_On_Limited      => "Mask_On_Limited",
         when GR.Value_Below_Limit    => "Value_Below_Limit",
         when GR.Value_Above_Limit    => "Value_Above_Limit",
         when GR.Rate_Exceeded        => "Rate_Exceeded",
         when GR.Forbidden_Sequence   => "Forbidden_Sequence");

   --  One hex field into an ADU: even length, at most Max_Hex digits; bytes past Cap are checked but not kept, so an
   --  over-long ADU reaches the framer at Cap bytes and is refused (Long_Adu), never silently cut.
   procedure Read_Hex (S : String; N : out Natural; A : out Adu_Bytes; Ok : out Boolean) is
      P : Natural := S'First;
   begin
      N := 0;
      A := [others => 0];
      Ok := S'Length > 0 and then S'Length <= Max_Hex and then S'Length mod 2 = 0;
      while Ok and then P < S'Last loop
         if Hex_Digit (S (P)) < 0 or else Hex_Digit (S (P + 1)) < 0 then
            Ok := False;
         elsif N < Cap then
            N := N + 1;
            A (N) := Hex_Digit (S (P)) * 16 + Hex_Digit (S (P + 1));
         end if;
         P := P + 2;
      end loop;
   end Read_Hex;

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

   ------------------------------------------------------------------ the reply check (response-check's, live)
   function Objects_Verdict (R : PF.Pdu_Bytes; M : PF.Pdu_Length) return PR.Pdu_Verdict is
      Pos : Natural := 8;
   begin
      for I in 1 .. R (7) loop
         if Pos > M - 1 then
            return PR.Bad_Pdu_Length;
         end if;
         if not RR.Object_Fits (M, Pos, R (Pos + 1)) then
            return PR.Bad_Pdu_Length;
         end if;
         Pos := RR.Next_Object_Pos (M, Pos, R (Pos + 1));
      end loop;
      return (if Pos = M + 1 then PR.Pdu_Ok else PR.Bad_Pdu_Length);
   end Objects_Verdict;

   function Normal_Verdict (Q : PF.Pdu_Bytes; Nq : PF.Pdu_Length; R : PF.Pdu_Bytes; M : PF.Pdu_Length)
     return PR.Pdu_Verdict is
      K : constant FC.Function_Kind := PD.Kind_Of (Q);
   begin
      case K is
         when FC.Read_Coils_Fc .. FC.Read_Input_Fc | FC.Read_Write_Fc =>
            return RR.Read_Resp_Verdict (K, PV.Quantity_Of (Q, Nq), M, (if M >= 2 then R (2) else 0));
         when FC.Write_Coil_Fc .. FC.Mask_Write_Fc =>
            return RE.Echo_Verdict
              (K, M, PF.Word_At (Q, Nq, 2), PF.Word_At (Q, Nq, 4),
               (if K = FC.Mask_Write_Fc then PF.Word_At (Q, Nq, 6) else 0),
               (if PF.Field_Present (M, 2, 2) then PF.Word_At (R, M, 2) else 0),
               (if PF.Field_Present (M, 4, 2) then PF.Word_At (R, M, 4) else 0),
               (if PF.Field_Present (M, 6, 2) then PF.Word_At (R, M, 6) else 0));
         when FC.Encapsulated_Fc =>
            declare
               V : constant PR.Pdu_Verdict :=
                 RR.Device_Id_Head_Verdict
                   (M, (if M >= 2 then R (2) else 0), (if M >= 3 then R (3) else 0), Q (3));
            begin
               return (if V = PR.Pdu_Ok then Objects_Verdict (R, M) else V);
            end;
         when FC.Unsupported_Fc =>
            return PR.Unknown_Function;
      end case;
   end Normal_Verdict;

   --  The reply's verdict name; "Reply_Ok" and "Exception_Accepted" are relayed as received.
   function Reply_Verdict (Q_Adu : Adu_Bytes; Q : PF.Pdu_Bytes; Nq : PF.Pdu_Length; Rep : Adu_Bytes; Nr : Natural)
     return String is
      Vr : constant FR.Frame_Verdict := Adu_Frame (Rep, Nr);
   begin
      if Vr /= FR.Frame_Ok then
         return Frame_Name (Vr);
      elsif not PM.Reply_Belongs
        (MB.Transaction_Id (Q_Adu (1), Q_Adu (2)), MB.Unit_Id (Q_Adu (7)), Q (1),
         MB.Transaction_Id (Rep (1), Rep (2)), MB.Unit_Id (Rep (7)), Rep (8))
      then
         return "Reply_Not_Matched";
      end if;
      declare
         M : constant PF.Pdu_Length := TA.Pdu_Length_Of (MB.Length_Field (Rep (5), Rep (6)));
         R : constant PF.Pdu_Bytes := Pdu_Of (Rep, M);
      begin
         if FC.Is_Exception_Byte (R (1)) then
            return Exception_Name (RX.Exception_Reply_Check (Q (1), R (1), M, (if M >= 2 then R (2) else 0)));
         else
            return Pdu_Name (Normal_Verdict (Q, Nq, R, M));
         end if;
      end;
   end Reply_Verdict;

   ------------------------------------------------------------------ output: master-out and MB_EVENTS
   procedure Send_Line (S : String) is
      Item : SE.Stream_Element_Array (1 .. S'Length + 1);
      Last : SE.Stream_Element_Offset;
      Done : SE.Stream_Element_Offset := 0;
   begin
      if To_Stdout then
         Ada.Text_IO.Put_Line (S);
         Ada.Text_IO.Flush;
         return;
      end if;
      for K in S'Range loop
         Item (SE.Stream_Element_Offset (K - S'First + 1)) := Character'Pos (S (K));
      end loop;
      Item (Item'Last) := 10;
      while Sink_Ok and then Done < Item'Last loop
         GS.Send_Socket (Sink, Item (Done + 1 .. Item'Last), Last);
         Sink_Ok := Last > Done;
         Done := Last;
      end loop;
      if not Sink_Ok then
         Note ("master-out line lost: the return connection is down");
      end if;
   exception
      when GS.Socket_Error =>
         Sink_Ok := False;
         Note ("master-out line lost: the return connection is down");
   end Send_Line;

   procedure Connect_Sink is
   begin
      for Try in 1 .. 50 loop
         begin
            GS.Create_Socket (Sink, GS.Family_Inet, GS.Socket_Stream);
            GS.Connect_Socket (Sink, (GS.Family_Inet, GS.Inet_Addr ("127.0.0.1"), GS.Port_Type (Sink_Port)));
            Sink_Ok := True;
            return;
         exception
            when GS.Socket_Error =>
               GS.Close_Socket (Sink);
               delay 0.1;
         end;
      end loop;
      Bad := True;
   end Connect_Sink;

   procedure Event (Kind, Slot : String; Q : Adu_Bytes; Nq : Natural; Name, Detail : String) is
      Fc   : constant String := (if Nq >= BD.Mbap_Header + 1 then Hex2 (Q (BD.Mbap_Header + 1)) else "-");
      Addr : constant String :=
        (if Nq >= BD.Mbap_Header + 3 and then Q (BD.Mbap_Header + 1) in 1 .. 6 | 15 | 16 | 22 | 23
         then Decimal (Q (BD.Mbap_Header + 2) * 256 + Q (BD.Mbap_Header + 3)) else "-");
   begin
      if Has_Events then
         Ada.Text_IO.Put_Line (Events, "master-replier" & Tab & Kind & Tab & "live" & Tab & Slot & Tab
                               & (if Nq >= BD.Mbap_Header then Hex2 (Q (7)) else "-") & Tab & Fc & Tab & Addr & Tab
                               & Name & Tab & Detail);
         Ada.Text_IO.Flush (Events);
      end if;
   end Event;

   --  The exception ADU: Reply_Header (the request's transaction id and unit id, PDU length 2), fc byte, code.
   function Exception_Adu (Q : Adu_Bytes; Fc_Byte, Code : Byte) return String is
      H : constant PM.Reply_Mbap := PM.Reply_Header (MB.Transaction_Id (Q (1), Q (2)), MB.Unit_Id (Q (7)), 2);
      A : Adu_Bytes := [others => 0];
   begin
      A (1 .. PM.Exception_Adu_Length) :=
        [PM.Hi_Byte (H.Transaction), PM.Lo_Byte (H.Transaction), PM.Hi_Byte (H.Protocol), PM.Lo_Byte (H.Protocol),
         PM.Hi_Byte (H.Length), PM.Lo_Byte (H.Length), H.Unit, Fc_Byte, Code];
      return Hex (A, PM.Exception_Adu_Length);
   end Exception_Adu;

   procedure Open_Events (Path : String) is
   begin
      Ada.Text_IO.Create (Events, Ada.Text_IO.Out_File, Path);
      Has_Events := True;
      Event ("started", "-", [others => 0], 0, "-", "-");
   exception
      when Ada.Text_IO.Name_Error | Ada.Text_IO.Use_Error =>
         Bad := True;
   end Open_Events;

   procedure Finish is
   begin
      if Sink_Ok then
         GS.Close_Socket (Sink);
      end if;
      if Has_Events then
         Ada.Text_IO.Close (Events);
      end if;
   end Finish;

   ------------------------------------------------------------------ one record
   procedure Answer (L : String) is
      Conn    : constant String := Field (L, 1);
      Slot    : constant String := Field (L, 2);
      Outcome : constant String := Field (L, 4);
      Detail  : constant String := Field (L, 5);
      Q       : Adu_Bytes;
      Nq      : Natural;
      Ok      : Boolean;
      Vq      : FR.Frame_Verdict;
   begin
      Read_Hex (Field (L, 3), Nq, Q, Ok);
      if Field_Count (L) /= 5 or else Number (Conn) < 1 or else Number (Slot) not in 0 .. 16 or else not Ok
        or else not (Outcome = "refused" or else Outcome = "reply" or else Outcome = "silent"
                     or else Outcome = "unreachable")
      then
         Note ("dropped a malformed record");
         return;
      end if;
      Vq := Adu_Frame (Q, Nq);
      if FR.Frame_Answer (Vq) = FR.Answer_Silent then
         Send_Line (Conn & Tab & "-");
         Event ("refused", Slot, Q, Nq, Frame_Name (Vq), "conn=" & Conn & " answer=silent");
         return;
      end if;
      declare
         N    : constant PF.Pdu_Length := Nq - BD.Mbap_Header;
         P    : constant PF.Pdu_Bytes := Pdu_Of (Q, N);
         Fail : constant String := Exception_Adu (Q, PD.Exception_Fc_Byte (P (1)), RX.Relay_Code (RX.Plc_Malformed));
      begin
         if not PD.Request_Ok (P, N) then
            declare
               X : constant PD.Exception_Reply := PD.Refusal_Reply (P, N);
            begin
               Send_Line (Conn & Tab & Exception_Adu (Q, X.Fc_Byte, X.Code));
               Event ("refused", Slot, Q, Nq, Pdu_Name (PD.Request_Verdict (P, N)), "conn=" & Conn & " exc=" & Hex2 (X.Code));
            end;
         elsif Outcome = "silent" or else Outcome = "unreachable" then
            declare
               F : constant RX.Plc_Failure := (if Outcome = "silent" then RX.Plc_Silent else RX.Plc_Unreachable);
            begin
               Send_Line (Conn & Tab & Exception_Adu (Q, PD.Exception_Fc_Byte (P (1)), RX.Relay_Code (F)));
               Event ("refused", Slot, Q, Nq, (if Outcome = "silent" then "Plc_Silent" else "Plc_Unreachable"),
                      "conn=" & Conn & " exc=" & Hex2 (RX.Relay_Code (F)));
            end;
         elsif Outcome = "reply" then
            declare
               Rep : Adu_Bytes;
               Nr  : Natural;
            begin
               Read_Hex (Detail, Nr, Rep, Ok);
               declare
                  V : constant String := (if Ok then Reply_Verdict (Q, P, N, Rep, Nr) else "Record_Inconsistent");
               begin
                  if V = "Reply_Ok" or else V = "Exception_Accepted" then
                     Send_Line (Conn & Tab & Hex (Rep, Nr));
                     Event ("relayed", Slot, Q, Nq, V, "conn=" & Conn & " n=" & Decimal (Nr));
                  else
                     Send_Line (Conn & Tab & Fail);
                     Event ("refused", Slot, Q, Nq, V, "conn=" & Conn & " exc=04");
                  end if;
               end;
            end;
         else
            for V in GR.Gate_Refusal loop
               if Detail = Gate_Name (V) then
                  Send_Line (Conn & Tab & Exception_Adu (Q, PD.Exception_Fc_Byte (P (1)), GR.Gate_Exception (V)));
                  Event ("refused", Slot, Q, Nq, Detail, "conn=" & Conn & " exc=" & Hex2 (GR.Gate_Exception (V)));
                  return;
               end if;
            end loop;
            Send_Line (Conn & Tab & Fail);
            Event ("refused", Slot, Q, Nq, "Record_Inconsistent", "conn=" & Conn & " named=" & Detail & " exc=04");
         end if;
      end;
   end Answer;

begin
   --  SLOT BEGIN (main)
   if Ada.Command_Line.Argument_Count not in 1 .. 2 then
      Note ("usage: mb_master_replier_main <return port | -> [<events-file>]");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   if Ada.Command_Line.Argument (1) /= "-" then
      if Number (Ada.Command_Line.Argument (1)) not in 1 .. 65_535 then
         Note ("usage: the return port is malformed");
         Ada.Command_Line.Set_Exit_Status (2);
         return;
      end if;
      To_Stdout := False;
      Sink_Port := Number (Ada.Command_Line.Argument (1));
      Connect_Sink;
   end if;
   if not Bad and then Ada.Command_Line.Argument_Count = 2 then
      Open_Events (Ada.Command_Line.Argument (2));
   end if;
   if Bad then
      Note ("the return port cannot be connected or the events file cannot be created");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   while not Ada.Text_IO.End_Of_File loop
      Answer (Ada.Text_IO.Get_Line);
   end loop;
   Finish;
   Ada.Command_Line.Set_Exit_Status (0);
   --  SLOT END (main)
end Mb_Master_Replier_Main;
