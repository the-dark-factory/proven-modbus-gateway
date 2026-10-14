with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Unbounded;
with GNAT.SHA256;
with Lovelace_Mb_Fc_Catalog_Pkg;
with Lovelace_Mb_Policy_Shape_Pkg;

--  site-loader (edge, built-not-proved), lovelace-mb round A, W3 water-gateway policy. The ONLY writer of the
--  site-policy pool: it reads one SITE FILE into a Policy_Table and accepts it only if the carried PROVEN core
--  Policy_Shape.Valid_Table holds; any fault refuses the WHOLE file (nothing of it is ever printed or used).
--  Decisions are core calls: Fc_Catalog.Function_Kind_Of (a code is known), Fc_Catalog.Is_Write_Kind (a slot is
--  granted a write), Policy_Shape.Valid_Table after EVERY line (its first failing clause names the refusal, so a
--  table fault is attributed to the line that made it), and Valid_Table again on the whole table before the dump.
--
--  CLI contract:
--    mb_site_loader_main <site-file>
--  exit 0: the canonical dump below on standard output.  exit 1: ONE line on standard output,
--    site-loader TAB refused TAB line=<k> TAB <refusal name>
--  and nothing else (the first fault in file order; k counts every physical line from 1).
--  exit 2: usage, missing, not a file, or over 1 MiB: one line on standard error, nothing on standard output.
--
--  SITE FILE: one rule per line; "#" starts a comment anywhere on a line; blank lines are skipped; fields are
--  separated by spaces or TABs (a trailing CR is blank, so CRLF files load the same); numbers are decimal digits only.
--    master   <peer IPv4 a.b.c.d> <gateway listen port 1..65535> <slot 1..16>      (R-MB-20; edge data)
--    allow    <slot 0..16> <function code> ...       (codes of [APP s.5.1] the gateway parses; repeat lines add)
--    writable <coil|register> <lo> <hi>             (one write range; at most 32)
--    limit    <register> <min> <max> [label ...]    (one value limit; at most 64; the label is free text)
--    rate     <slot 1..16> <max writes> <window ms>  (at most one per slot)
--    sequence <coil|register> <addr> <value> followed-by <coil|register> <addr> <value> within <ms>  (at most 16)
--  Addresses and values are 0..65535. A slot granted any write code needs a rate line; a slot with none gets the
--  default rate 1 per 86400000 ms (it cannot write, but Valid_Table bounds every slot's rule).
--  Refusal names: Unknown_Keyword, Wrong_Field_Count, Malformed_Number, Number_Out_Of_Range, Bad_Address, Bad_Slot,
--    Bad_Target, Unknown_Function_Code, Malformed_Sequence, Coil_Step_Value (R-MB-26), Duplicate_Master,
--    Duplicate_Rate, Too_Many_Masters, Too_Many_Ranges, Too_Many_Limits, Too_Many_Sequences, Rate_Missing (at the
--    slot's first allow line granting a write); from Valid_Table's clauses: Range_Lo_Above_Hi, Limit_Min_Above_Max,
--    Duplicate_Limit, Rate_Out_Of_Bounds, Within_Zero, Slot_Zero_Allowance; Invalid_Table (line 0, final check).
--
--  DUMP (every field TAB-separated, every line ends LF, in this order):
--    site-loader TAB accepted                                           (no line count: the digest names the policy, not the layout)
--    master TAB <a.b.c.d> TAB <port> TAB <slot>                         one per master line, file order
--    allow TAB <slot> TAB <codes ascending, comma-separated, or ->      slots 0 .. 16
--    writable TAB <coil|register> TAB <lo> TAB <hi>                     table order = file order
--    limit TAB <register> TAB <min> TAB <max> TAB <label or ->          label words joined by one space
--    rate TAB <slot> TAB <max writes> TAB <window ms> TAB <declared|default>    slots 1 .. 16
--    sequence TAB <t> TAB <addr> TAB <value> TAB <t> TAB <addr> TAB <value> TAB <within ms>
--    digest TAB sha256=<64 lowercase hex of every dump byte above this line>
--  The digest is the load-time digest of the site-policy pool: a consumer recomputes it to catch a changed table.

procedure Mb_Site_Loader_Main is
   package Fc renames Lovelace_Mb_Fc_Catalog_Pkg;
   package Ps renames Lovelace_Mb_Policy_Shape_Pkg;
   package U renames Ada.Strings.Unbounded;
   use type Fc.Function_Kind;
   use type Ps.Write_Target;
   use type U.Unbounded_String;

   HT          : constant Character := Character'Val (9);
   LF          : constant Character := Character'Val (10);
   Max_File    : constant := 1_048_576;
   Max_Tokens  : constant := 64;
   Max_Masters : constant := 64;
   Max_Number  : constant := 999_999_999;
   Max_Item    : constant := 65_535;

   Default_Rate : constant Ps.Rate_Rule := (Max_Writes => 1, Window_Ms => 86_400_000);
   No_Step      : constant Ps.Sequence_Step := (Target => Ps.Coil_Target, Location => 0, Value => 0);

   type Master_Entry is record
      A, B, C, D : Natural;
      Port       : Natural;
      Slot       : Ps.Known_Slot;
   end record;

   type Master_Array is array (1 .. Max_Masters) of Master_Entry;
   type Token_Array is array (1 .. Max_Tokens) of U.Unbounded_String;
   type Label_Array is array (Ps.Limit_Index) of U.Unbounded_String;
   type Line_Per_Slot is array (Ps.Known_Slot) of Natural;

   T : Ps.Policy_Table :=
     (Allow          => (others => (others => False)),
      Range_Count    => 0,
      Ranges         => (others => (Target => Ps.Coil_Target, Lo => 0, Hi => 0)),
      Limit_Count    => 0,
      Limits         => (others => (Register => 0, Min => 0, Max => 0)),
      Rates          => (others => Default_Rate),
      Sequence_Count => 0,
      Sequences      => (others => (Trigger_Step => No_Step, Then_Step => No_Step, Within_Ms => 0)));

   Masters      : Master_Array := (others => (A => 0, B => 0, C => 0, D => 0, Port => 0, Slot => 1));
   Master_Count : Natural := 0;
   Labels       : Label_Array := (others => U.Null_Unbounded_String);
   Rate_Line    : Line_Per_Slot := (others => 0);
   Write_Line   : Line_Per_Slot := (others => 0);
   Bad          : Boolean := False;
   Bad_Line     : Natural := 0;
   Bad_Name     : U.Unbounded_String := U.Null_Unbounded_String;
   Lines        : Natural := 0;

   function Img (N : Natural) return String is
      S : constant String := Natural'Image (N);
   begin
      return S (S'First + 1 .. S'Last);
   end Img;

   procedure Refuse (K : Natural; Name : String) is
   begin
      if not Bad then
         Bad := True;
         Bad_Line := K;
         Bad_Name := U.To_Unbounded_String (Name);
      end if;
   end Refuse;

   function Is_Blank (C : Character) return Boolean is
     (C = ' ' or else C = HT or else C = Character'Val (11) or else C = Character'Val (12)
      or else C = Character'Val (13));

   function Tok (Toks : Token_Array; I : Positive) return String is (U.To_String (Toks (I)));

   procedure Split (Line : String; Toks : out Token_Array; N : out Natural; Over : out Boolean) is
      I : Natural := Line'First;
      J : Natural;
   begin
      Toks := (others => U.Null_Unbounded_String);
      N := 0;
      Over := False;
      while I <= Line'Last loop
         if Is_Blank (Line (I)) then
            I := I + 1;
         else
            J := I;
            while J < Line'Last and then not Is_Blank (Line (J + 1)) loop
               J := J + 1;
            end loop;
            if N = Max_Tokens then
               Over := True;
            else
               N := N + 1;
               Toks (N) := U.To_Unbounded_String (Line (I .. J));
            end if;
            I := J + 1;
         end if;
      end loop;
   end Split;

   procedure Number (S : String; K : Positive; Max : Natural; V : out Natural) is
   begin
      V := 0;
      if S'Length = 0 or else S'Length > 9 or else (for some C of S => C not in '0' .. '9') then
         Refuse (K, "Malformed_Number");
         return;
      end if;
      for C of S loop
         V := V * 10 + (Character'Pos (C) - Character'Pos ('0'));
      end loop;
      if V > Max then
         V := 0;
         Refuse (K, "Number_Out_Of_Range");
      end if;
   end Number;

   procedure Slot_Of (S : String; K : Positive; Lowest : Natural; V : out Natural) is
   begin
      Number (S, K, Max_Number, V);
      if not Bad and then (V < Lowest or else V > Ps.Master_Slot'Last) then
         V := Lowest;
         Refuse (K, "Bad_Slot");
      end if;
   end Slot_Of;

   procedure Target_Of (S : String; K : Positive; V : out Ps.Write_Target) is
   begin
      V := Ps.Coil_Target;
      if S = "register" then
         V := Ps.Register_Target;
      elsif S /= "coil" then
         Refuse (K, "Bad_Target");
      end if;
   end Target_Of;

   function Target_Name (V : Ps.Write_Target) return String is
     (if V = Ps.Coil_Target then "coil" else "register");

   procedure Address_Of (S : String; K : Positive; M : in out Master_Entry) is
      Parts : array (1 .. 4) of Natural := (others => 0);
      P     : Positive := 1;
      Seen  : Natural := 0;
      Ok    : Boolean := S'Length in 7 .. 15;
   begin
      for C of S loop
         exit when not Ok;
         if C = '.' then
            if Seen = 0 or else P = 4 then
               Ok := False;
            else
               P := P + 1;
               Seen := 0;
            end if;
         elsif C in '0' .. '9' then
            Seen := Seen + 1;
            if Seen > 3 then
               Ok := False;
            else
               Parts (P) := Parts (P) * 10 + (Character'Pos (C) - Character'Pos ('0'));
               Ok := Parts (P) <= 255;
            end if;
         else
            Ok := False;
         end if;
      end loop;
      if not Ok or else P /= 4 or else Seen = 0 then
         Refuse (K, "Bad_Address");
      else
         M.A := Parts (1);
         M.B := Parts (2);
         M.C := Parts (3);
         M.D := Parts (4);
      end if;
   end Address_Of;

   procedure Master_Line (Toks : Token_Array; N : Natural; K : Positive) is
      M    : Master_Entry := (A => 0, B => 0, C => 0, D => 0, Port => 0, Slot => 1);
      Port : Natural;
      Slot : Natural;
   begin
      if N /= 4 then
         Refuse (K, "Wrong_Field_Count");
         return;
      end if;
      Address_Of (Tok (Toks, 2), K, M);
      Number (Tok (Toks, 3), K, Max_Item, Port);
      if not Bad and then Port = 0 then
         Refuse (K, "Number_Out_Of_Range");
      end if;
      Slot_Of (Tok (Toks, 4), K, 1, Slot);
      if Bad then
         return;
      end if;
      M.Port := Port;
      M.Slot := Slot;
      if (for some I in 1 .. Master_Count =>
            Masters (I).A = M.A and then Masters (I).B = M.B and then Masters (I).C = M.C
            and then Masters (I).D = M.D and then Masters (I).Port = M.Port)
      then
         Refuse (K, "Duplicate_Master");
      elsif Master_Count = Max_Masters then
         Refuse (K, "Too_Many_Masters");
      else
         Master_Count := Master_Count + 1;
         Masters (Master_Count) := M;
      end if;
   end Master_Line;

   procedure Allow_Line (Toks : Token_Array; N : Natural; K : Positive) is
      Slot : Natural;
      Code : Natural;
      Kind : Fc.Function_Kind;
   begin
      if N < 3 then
         Refuse (K, "Wrong_Field_Count");
         return;
      end if;
      Slot_Of (Tok (Toks, 2), K, 0, Slot);
      for I in 3 .. N loop
         exit when Bad;
         Number (Tok (Toks, I), K, Max_Number, Code);
         if not Bad then
            Kind := (if Code <= Fc.Octet'Last then Fc.Function_Kind_Of (Code) else Fc.Unsupported_Fc);
            if Kind = Fc.Unsupported_Fc then
               Refuse (K, "Unknown_Function_Code");
            else
               T.Allow (Slot) (Kind) := True;
               if Slot >= 1 and then Fc.Is_Write_Kind (Kind) and then Write_Line (Slot) = 0 then
                  Write_Line (Slot) := K;
               end if;
            end if;
         end if;
      end loop;
   end Allow_Line;

   procedure Writable_Line (Toks : Token_Array; N : Natural; K : Positive) is
      Target : Ps.Write_Target;
      Lo, Hi : Natural;
   begin
      if N /= 4 then
         Refuse (K, "Wrong_Field_Count");
         return;
      end if;
      Target_Of (Tok (Toks, 2), K, Target);
      Number (Tok (Toks, 3), K, Max_Item, Lo);
      Number (Tok (Toks, 4), K, Max_Item, Hi);
      if Bad then
         return;
      elsif T.Range_Count = Ps.Range_Tally'Last then
         Refuse (K, "Too_Many_Ranges");
      else
         T.Range_Count := T.Range_Count + 1;
         T.Ranges (T.Range_Count) := (Target => Target, Lo => Lo, Hi => Hi);
      end if;
   end Writable_Line;

   procedure Limit_Line (Toks : Token_Array; N : Natural; K : Positive) is
      Register, Min, Max : Natural;
      Label              : U.Unbounded_String := U.Null_Unbounded_String;
   begin
      if N < 4 then
         Refuse (K, "Wrong_Field_Count");
         return;
      end if;
      Number (Tok (Toks, 2), K, Max_Item, Register);
      Number (Tok (Toks, 3), K, Max_Item, Min);
      Number (Tok (Toks, 4), K, Max_Item, Max);
      for I in 5 .. N loop
         if I > 5 then
            U.Append (Label, ' ');
         end if;
         U.Append (Label, Toks (I));
      end loop;
      if Bad then
         return;
      elsif T.Limit_Count = Ps.Limit_Tally'Last then
         Refuse (K, "Too_Many_Limits");
      else
         T.Limit_Count := T.Limit_Count + 1;
         T.Limits (T.Limit_Count) := (Register => Register, Min => Min, Max => Max);
         Labels (T.Limit_Count) := Label;
      end if;
   end Limit_Line;

   procedure Rate_Line_Of (Toks : Token_Array; N : Natural; K : Positive) is
      Slot, Max, Window : Natural;
   begin
      if N /= 4 then
         Refuse (K, "Wrong_Field_Count");
         return;
      end if;
      Slot_Of (Tok (Toks, 2), K, 1, Slot);
      Number (Tok (Toks, 3), K, Max_Number, Max);
      Number (Tok (Toks, 4), K, Max_Number, Window);
      if Bad then
         return;
      elsif Rate_Line (Slot) /= 0 then
         Refuse (K, "Duplicate_Rate");
      else
         T.Rates (Slot) := (Max_Writes => Max, Window_Ms => Window);
         Rate_Line (Slot) := K;
      end if;
   end Rate_Line_Of;

   procedure Step_Of (Toks : Token_Array; First : Positive; K : Positive; S : out Ps.Sequence_Step) is
      Target          : Ps.Write_Target;
      Location, Value : Natural;
   begin
      Target_Of (Tok (Toks, First), K, Target);
      Number (Tok (Toks, First + 1), K, Max_Item, Location);
      Number (Tok (Toks, First + 2), K, Max_Item, Value);
      S := (Target => Target, Location => Location, Value => Value);
      if not Bad and then Target = Ps.Coil_Target and then Value > 1 then
         Refuse (K, "Coil_Step_Value");
      end if;
   end Step_Of;

   procedure Sequence_Line (Toks : Token_Array; N : Natural; K : Positive) is
      Trigger, Second : Ps.Sequence_Step;
      Within          : Natural;
   begin
      if N /= 10 then
         Refuse (K, "Wrong_Field_Count");
         return;
      elsif Tok (Toks, 5) /= "followed-by" or else Tok (Toks, 9) /= "within" then
         Refuse (K, "Malformed_Sequence");
         return;
      end if;
      Step_Of (Toks, 2, K, Trigger);
      Step_Of (Toks, 6, K, Second);
      Number (Tok (Toks, 10), K, Max_Number, Within);
      if Bad then
         return;
      elsif T.Sequence_Count = Ps.Sequence_Tally'Last then
         Refuse (K, "Too_Many_Sequences");
      else
         T.Sequence_Count := T.Sequence_Count + 1;
         T.Sequences (T.Sequence_Count) := (Trigger_Step => Trigger, Then_Step => Second, Within_Ms => Within);
      end if;
   end Sequence_Line;

   function Broken_Clause return String is
     (if not Ps.Ranges_Ordered (T) then "Range_Lo_Above_Hi"
      elsif not Ps.Limits_Ordered (T) then "Limit_Min_Above_Max"
      elsif not Ps.Limits_Distinct (T) then "Duplicate_Limit"
      elsif not Ps.Rates_Bounded (T) then "Rate_Out_Of_Bounds"
      elsif not Ps.Sequences_Timed (T) then "Within_Zero"
      elsif not Ps.Slot_Zero_Closed (T) then "Slot_Zero_Allowance"
      else "Invalid_Table");

   procedure Apply_Line (Raw : String; K : Positive) is
      Cut  : Integer := Raw'Last;
      Toks : Token_Array;
      N    : Natural;
      Over : Boolean;
   begin
      for I in Raw'Range loop
         if Raw (I) = '#' then
            Cut := I - 1;
            exit;
         end if;
      end loop;
      Split (Raw (Raw'First .. Cut), Toks, N, Over);
      if N = 0 then
         return;
      elsif Over then
         Refuse (K, "Wrong_Field_Count");
      elsif Tok (Toks, 1) = "master" then
         Master_Line (Toks, N, K);
      elsif Tok (Toks, 1) = "allow" then
         Allow_Line (Toks, N, K);
      elsif Tok (Toks, 1) = "writable" then
         Writable_Line (Toks, N, K);
      elsif Tok (Toks, 1) = "limit" then
         Limit_Line (Toks, N, K);
      elsif Tok (Toks, 1) = "rate" then
         Rate_Line_Of (Toks, N, K);
      elsif Tok (Toks, 1) = "sequence" then
         Sequence_Line (Toks, N, K);
      else
         Refuse (K, "Unknown_Keyword");
      end if;
      if not Bad and then not Ps.Valid_Table (T) then
         Refuse (K, Broken_Clause);
      end if;
   end Apply_Line;

   procedure Finish is
      First_Missing : Natural := 0;
   begin
      for S in Ps.Known_Slot loop
         if Write_Line (S) /= 0 and then Rate_Line (S) = 0
           and then (First_Missing = 0 or else Write_Line (S) < First_Missing)
         then
            First_Missing := Write_Line (S);
         end if;
      end loop;
      if First_Missing /= 0 then
         Refuse (First_Missing, "Rate_Missing");
      end if;
      if not Bad and then not Ps.Valid_Table (T) then
         Refuse (0, "Invalid_Table");
      end if;
   end Finish;

   function Dump_Body return String is
      B : U.Unbounded_String := U.Null_Unbounded_String;

      procedure Add (S : String) is
      begin
         U.Append (B, S & LF);
      end Add;

   begin
      Add ("site-loader" & HT & "accepted");
      for I in 1 .. Master_Count loop
         Add ("master" & HT & Img (Masters (I).A) & "." & Img (Masters (I).B) & "." & Img (Masters (I).C) & "."
              & Img (Masters (I).D) & HT & Img (Masters (I).Port) & HT & Img (Masters (I).Slot));
      end loop;
      for S in Ps.Master_Slot loop
         declare
            Codes : U.Unbounded_String := U.Null_Unbounded_String;
         begin
            for Kind in Fc.Public_Kind loop
               if T.Allow (S) (Kind) then
                  if Codes /= U.Null_Unbounded_String then
                     U.Append (Codes, ",");
                  end if;
                  U.Append (Codes, Img (Fc.Code_Of (Kind)));
               end if;
            end loop;
            Add ("allow" & HT & Img (S) & HT
                 & (if Codes = U.Null_Unbounded_String then "-" else U.To_String (Codes)));
         end;
      end loop;
      for I in 1 .. T.Range_Count loop
         Add ("writable" & HT & Target_Name (T.Ranges (I).Target) & HT & Img (T.Ranges (I).Lo) & HT
              & Img (T.Ranges (I).Hi));
      end loop;
      for I in 1 .. T.Limit_Count loop
         Add ("limit" & HT & Img (T.Limits (I).Register) & HT & Img (T.Limits (I).Min) & HT & Img (T.Limits (I).Max)
              & HT & (if Labels (I) = U.Null_Unbounded_String then "-" else U.To_String (Labels (I))));
      end loop;
      for S in Ps.Known_Slot loop
         Add ("rate" & HT & Img (S) & HT & Img (T.Rates (S).Max_Writes) & HT & Img (T.Rates (S).Window_Ms) & HT
              & (if Rate_Line (S) /= 0 then "declared" else "default"));
      end loop;
      for I in 1 .. T.Sequence_Count loop
         Add ("sequence" & HT & Target_Name (T.Sequences (I).Trigger_Step.Target) & HT
              & Img (T.Sequences (I).Trigger_Step.Location) & HT & Img (T.Sequences (I).Trigger_Step.Value) & HT
              & Target_Name (T.Sequences (I).Then_Step.Target) & HT & Img (T.Sequences (I).Then_Step.Location)
              & HT & Img (T.Sequences (I).Then_Step.Value) & HT & Img (T.Sequences (I).Within_Ms));
      end loop;
      return U.To_String (B);
   end Dump_Body;

begin
   --  SLOT BEGIN (main)
   if Ada.Command_Line.Argument_Count /= 1 then
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "site-loader: usage: mb_site_loader_main <site-file>");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   declare
      use type Ada.Directories.File_Kind;
      use type Ada.Directories.File_Size;
      Path : constant String := Ada.Command_Line.Argument (1);
      F    : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path)
        or else Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File
        or else Ada.Directories.Size (Path) > Max_File
      then
         Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "site-loader: missing, not a file, or too large");
         Ada.Command_Line.Set_Exit_Status (2);
         return;
      end if;
      Ada.Text_IO.Open (F, Ada.Text_IO.In_File, Path);
      while not Bad and then not Ada.Text_IO.End_Of_File (F) loop
         Lines := Lines + 1;
         Apply_Line (Ada.Text_IO.Get_Line (F), Lines);
      end loop;
      Ada.Text_IO.Close (F);
      if not Bad then
         Finish;
      end if;
      if Bad then
         Ada.Text_IO.Put_Line ("site-loader" & HT & "refused" & HT & "line=" & Img (Bad_Line) & HT
                               & U.To_String (Bad_Name));
         Ada.Command_Line.Set_Exit_Status (1);
      else
         declare
            Text : constant String := Dump_Body;
         begin
            Ada.Text_IO.Put (Text);
            Ada.Text_IO.Put_Line ("digest" & HT & "sha256=" & GNAT.SHA256.Digest (Text));
         end;
         Ada.Command_Line.Set_Exit_Status (0);
      end if;
   end;
   --  SLOT END (main)
end Mb_Site_Loader_Main;
