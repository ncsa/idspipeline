@load base/frameworks/notice

module Bad_IRC;

export {
  redef enum Notice::Type += {
    BadIRC 
  };

  const bad_irc_nick = 
    # AB|1234, ABCD||1234567
    /^[a-zA-Z]+\|+[0-9]{4,}$/ |
    
    # [0|1234], [1||1234567]
    /^\[[0-9]\|+[0-9]{4,}\]$/ |
    
    # [0]-1234, [1]-1234567, {0}-12345
    /^(\[|\{)[0-9](\]|\})-[0-9]{4,}$/ |
    
    # [AB|DEU|1234], [AB1234|USA|1234567]
    /^\[[a-zA-Z]+[0-9]*\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[0-9]+\]$/ |
    
    # ruby1234
    /^ruby[0-9]+$/ |
    
    # A-1234, B-1234567, X1234
    /^[a-zA-Z]-?[0-9]{4,}$/ |
    
    # [AB]|1234, [ABCD]-1234567
    /^\[[a-zA-Z]+\](\||-)[0-9]{4,}$/ |
    
    # [RAPEDv12]-1234, [RAPEDv1234]-1234567
    /^\[RAPEDv[0-9]+\]-?[0-9]{4,}$/ |
    
    # ZOMBIE1234
    /^ZOMBIE[0-9]{4,}$/ |
    
    # |1234
    /^\|[0-9]{4,}$/ |
    
    # [A]1234, [ABCD]1234567
    /^\[[a-zA-Z]+\][0-9]{4,}$/ |
    
    # W0*1234
    /^W0.[0-9]{4,}$/ |
    
    # AB-|-1234, ABCD-|-1234567
    /^[a-zA-Z]{1,4}-\|-[0-9]{4,}$/ |
    
    # [A]ABCD|1234, [A]ABCD-1234
    /^\[[a-zA-Z]\][a-zA-Z]+(\||-)[0-9]{4,}$/ |
    
    # [ABC-1234]-12345
    /^\[[a-zA-Z]+-[0-9]+\]-[0-9]{4,}$/ |
    
    # |ABCD|A|1234
    /^\|[a-zA-Z]+\|[a-zA-Z]\|[0-9]{4,}$/ |
    
    # [1]|1234
    /^\[[0-9]\]\|[0-9]{4,}$/ |
    
    # |12|ABCD|1234
    /^\|[0-9]{1,2}\|[a-zA-Z]{1,4}\|[0-9]{4,}$/ |
    
    # [A][ABC]1234, [A][ABC]-1234
    /^\[[a-zA-Z]\]\[[a-zA-Z]+\]-?[0-9]{4,}$/ |
    
    # [ABCD][ABCD12-1234]
    /^\[[a-zA-Z]+\]\[[a-z0-9]+-[0-9]{4,}\]$/ |
    
    # |12||-X-||1234, |AB||-X-||1234
    /^\|[0-9|a-z]+\|\|-[a-zA-Z]-\|\|[0-9]{4,}$/ |
    
    # [ABCD-1234]
    /^\[[a-zA-Z]+-[0-9]{4,}\]$/ | 
    
    # [ABCD123]-1234
    /^\[[a-z0-9]+\]-[0-9]{4,}$/ |
    
    # [ABCD0374]1234
    /^\[([a-zA-Z]+[0,1,3,7,4]+)*\][0-9]{4,}$/ |
    
    # [AB||1234]
    /^\[[a-z0,1,3,7,4]+\|\|[0-9]{4,}\]$/ |
    
    # DEU|XP|SP4|496015
    /^(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|[a-z0-9]{1,3}\|[0-9]{4,}$/ |
    
    # [999379|0|UUU]
    /^\[[0-9]{4,}\|[0-9]\|[a-zA-Z]{1,3}\]$/ |
    
    # [_]|309597
    /^\[.\]\|[0-9]{4,}$/ |
    
    # [[Xx0x0xX]]-803400, [|x00x|]96695
    /^\[[\[|\|][a-z,1,0,3,7,4]{1,9}[\]|\|]\]-?[0-9]{4,}$/ |
    
    # [19]le[XP]70736
    /^\[[0-9]{1,2}\][a-zA-Z]{1,2}\[[a-zA-Z]{1,2}\][0-9]{4,}$/ |
    
    # AB-1234
    /^[a-zA-Z]{1,2}-[0-9]{4,}$/ |
    
    # |00||DnB||2727
    /^\|[0-9]{1,2}\|{1,2}[a-zA-Z]{1,4}\|{1,2}[0-9]{4,}$/ |
    
    # FIRE_BOT_32306
    /^FIRE_BOT_[0-9]{4,}$/ |
    
    # Ayu-San|8034002
    /^[a-zA-Z]{1,3}-[a-zA-Z]{1,3}\|[0-9]{4,}$/ |
    
    # [^R||184824682]
    /^\[.{1,2}\|\|[0-9]{4,}\]$/ |
    
    # {[52785]}
    /^\{\[[0-9]{4,}\]\}$/ |
    
    # br_pHeHIwc
    /^br_[a-zA-Z]{4,}$/ |
    
    # [I]jhrowfqkyrzf
    /^\[I\][a-zA-Z]{6,}$/ |
    
    # |LSD|-8238
    /^\|[LSD]\|-[0-9]{4,}$/ |
    
    # r00t-R00T3D-9108
    /^r00t-[a-z0-9]{2,8}-[0-9]{4,}$/ |
    
    # cX-allmp3s-CD7671
    /^cX-all[a-z0-9]{1,6}-CD[0-9]{4,}$/ |
    
    # [M00|BGR|14086]
    /^\[[a-zA-Z][0-9]{1,2}\|[a-zA-Z]{1,3}\|[0-9]{4,}\]$/ |
    
    # [00|FRA|432865] [00|DEU|597660] [03|USA|147700] [00|KOR|437247]
    /^\[[0-9]{1,2}\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[0-9]{4,}\]$/ |
    
    # URXv2-75863
    /^URXv[0-9]-[0-9]{4,}$/ |
    
    # xXx-803400248
    /^xXx-[0-9]{4,}$/ |
    
    # [-UrX-]-8034002
    /^\[-[a-zA-Z]{1,3}-\]-[0-9]{4,}$/ |
    
    # {RX}-527853
    /^\{[a-zA-Z]{1,3}\}-[0-9]{4,}$/ |
    
    # (&#O##@wGoacNEQ
    /^\(&.{4,}@[a-zA-Z]{4,}$/ |
    
    # ^kYprPp   FALSE-POSITIVE???
    /^\^[a-zA-Z]{5,}$/ |
    
    # [CHN][0H]dcjsoywzo new[CHN][28H]dcjsoywzo
    /^(new|NE)?\[(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\]\[[0-9]{1,4}H\][a-zA-Z]{4,}$/ |
    
    # r00t3d-6485006232
    /^r00t3d-[0-9]{4,}$/ |
    
    # RBOT|F|USA|XP-11348
    /^RBOT\|[a-zA-Z]?\|?(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)-[0-9]{4,}$/ |
    
    # RBOT||XP-SP2-80340024
    /^RBOT\|\|(XP|2K|K3|UN)-(SP2|SP4)-[0-9]{4,}$/ |
    
    # XP|00|DEU|1425
    /^(XP|2K|K3|UN)\|[0-9]{1,2}\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[0-9]{4,}$/ |
    
    # roda69_1711
    /^roda[0-9]{1,2}_[0-9]{4,}$/ |
    
    # [FirstTime|00|SAU|XP|SP2]-49
    /^\[FirstTime\|[0-9]{1,2}\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|SP[0-9]\]-[0-9]{2,}$/ |
    
    # UM114EC555267
    /^UM114EC[0-9]{4,}$/ |
    
    # p|iubfqr
    /^p\|[a-zA-Z]{4,}$/ |
    
    # What--2622
    /^What--[0-9]{4,}$/ |
    
    # [00|DEU|XP|SP2]-6820
    /^\[[0-9]{1,2}\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|SP[0-9]\]-[0-9]{4,}$/ |
    
    # DEU|XP|SP2|00|1000|L|293
    /^(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|SP[0-9]\|[0-9]{1,2}\|[0-9]{1,4}\|L\|[0-9]{1,3}$/ |
    
    # [XP|L|RUS|GRC|00]-tgQSTdLQ
    /^\[(XP|2K|K3|UN)\|L\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[0-9]{1,2}\]-[a-zA-Z]{4,}$/ |
    
    # [DEU][3]11G-BL
    /^\[(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\]\[[0-9]{1,1}\][0-9]{1,2}[a-zA-Z]-[a-zA-Z]{2,}$/ |
    
    # [THA-[20H]tcpxhhcci
    /^\[(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)-\[[0-9]{1,2}H\][a-zA-Z]{4,}$/ |
    
    # \00\USA\jbmzb6upnw
    /^\\[0-9]{1,2}\\(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\\[a-z,0-9]{4,}$/ |
    
    # DEU|XP|LAN|9|838810041
    /^(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|LAN\|[0-9]\|[0-9]{4,}$/ |
    
    # \00M\CHN\k6dj1myhia
    /^\\\d{1,2}[a-zA-Z]{1,2}?\\(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\\\w{4,}$/ |
    
    # [M|11|DEU|XP|34037]
    /^\[[a-zA-Z]\|[0-9]{1,2}\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|[0-9]{3,}\]$/ |
    
    # [M00|THA|59007878]
    /^\[[a-zA-Z][0-9]{1,2}\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[0-9]{4,}\]$/ |
    
    # ][l4m3r][gqaowo
    /^\]\[l4m3r\]\[[a-zA-Z]{4,}$/ |
    
    # NY8463404018863
    /^NY[0-9]{7,}$/ |
    
    # awk-7262056
    /^awk-[0-9]{4,}$/ |
    
    # T80-166013755
    /^T80-[0-9]{4,}$/ |
    
    # [XP|DEU]123456789
    /^\[(XP|2K|K3|UN)\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\]{4,}$/ |
    
    # ]tG[-xwakwp
    /^\]tG\[-[a-zA-Z]{4,}$/ |
    
    # [DEU-0H-ferwwgwq FQ[FRA-1H-sadfgww
    /^[a-zA-Z]{0,2}\[(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\-[0-9]H\-[a-zA-Z]{4,}$/ |
    
    # [DEU][12]91G-BW
    /^\[(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\]\[[0-9]{1,2}\]\w{1,3}\-[a-zA-Z]{1,2}$/ |
    
    # USA|XP|SP2|00|2341
    /^(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|SP[0-9]\|[0-9]{1,2}\|[0-9]{3,}$/ |
    
    # [A][T][L]-3985100
    /^\[A\]\[T\]\[L\]-[0-9]{4,}$/ |
    
    # ][laMer][xdqikq
    /^\]\[laMer\]\[[a-zA-Z]{4,}$/ |
    
    # NT51|4357583
    /^NT[0-9]{1,2}\|[0-9]{4,}$/ |
    
    # [00][XP][SP2][USA]-751625146
    /^\[[0-9]{1,2}\]\[(XP|2K|K3|UN)\]\[SP[0-9]\]\[(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\]\-[0-9]{4,}$/ |
    
    # USA|00|XP|SP2|381
    /^(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[0-9]{1,2}\|(XP|2K|K3|UN)\|SP[0-9]\|[0-9]{3,}$/ |
    
    # [USA|XP|L|00]-mmgjr
    /^\[(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|(XP|2K|K3|UN)\|[a-zA-Z]\|[0-9]{1,2}\]\-[a-zA-Z]{4,}$/ |
    
    # [LZ]WmLcbbFd
    /^\[LZ\][a-zA-Z]{4,}$/ |
    
    # bot-4184076-13
    /^bot-[0-9]{4,}-13$/ |
    
    # [nLh]DEU-265560
    /^\[nLh\](DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)-[0-9]{4,}$/ |
    
    # [MT01|LBN|80686]
    /^\[[a-zA-Z]{1,2}[0-9]{1,2}\|(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[0-9]{4,}\]$/ |
    
    #  DEU|SEL|4sv
    /^(DEU|GBR|USA|FRA|CHN|KOR|MEX|NLD|EGY|PRT|CZE|SAU|NOR|MAR|AUT|TUR|ESP|POL|CAN|SVK|HUN|ZAF|BGR|HRV|TWN|NLD|ITA|THA|SWE|BRA|RUS|GRC|LBN)\|[a-zA-Z]{1,3}\|[a-z0-9]{3}$/ &redef;

}

event irc_user_message(c: connection, is_orig: bool, user: string, host: string, server: string, real_name: string) &priority=-5
{
  if(bad_irc_nick in c$irc$nick)
  {
    NOTICE([$note=BadIRC,
    $msg=fmt("IRC 'USER' message with suspicious nickname %s",c$irc$nick),
    $conn=c]);
  }
}

