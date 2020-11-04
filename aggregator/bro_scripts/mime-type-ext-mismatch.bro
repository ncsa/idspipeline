@load base/frameworks/notice

module Mime;

export {
  redef enum Notice::Type += {
          Mime_Type_Ext_Mismatch,
  };

  redef enum Log::ID += {
    ## Loggin stream for file analysis.
    LOG
  };

  ## Contains all metadata related to the analysis of a given file.
  ## For the most part, fields here are derived from ones of the same name
  ## in :bro:see:`fa_file`.
  type Info: record {
    ## The time when the file was first seen.
    ts: time &log;

    ## An identifier associated with a single file.
    fuid: string &log;

    ## If this file was transferred over a network
    ## connection this should show the host or hosts that
    ## the data sourced from.
    tx_hosts: set[addr] &default=addr_set() &log;

    ## If this file was transferred over a network
    ## connection this should show the host or hosts that
    ## the data traveled to.
    rx_hosts: set[addr] &default=addr_set() &log;

    ## Connection UIDs over which the file was transferred.
    conn_uids: set[string] &default=string_set() &log;

    ## An identification of the source of the file data.  E.g. it
    ## may be a network protocol over which it was transferred, or a
    ## local file path which was read, or some other input source.
    source: string &log &optional;

    ## A mime type provided by the strongest file magic signature
    ## match against the *bof_buffer* field of :bro:see:`fa_file`,
    ## or in the cases where no buffering of the beginning of file
    ## occurs, an initial guess of the mime type based on the first
    ## data seen.
    mime_type: string &log;

    ## A filename for the file if one is available from the source
    ## for the file.  These will frequently come from
    ## "Content-Disposition" headers in network protocols.
    filename: string &log;

    ## The type of this alert
    note: string &log;

    ## A human readable message for the alert.
    msg: string &log;

  } &redef;

  global log_files: event(rec: Info);
 
  ## Mapping between mime types and regular expressions for URLs
  ## The log mime.log is written to if there is a mismatch between 
  ## mime_type and extension
  const mime_types_extensions: table[string] of pattern = {
    ["application/vnd.tcpdump.pcap"] = /(([pP])?[cC][aA][pP]|[dD][mM][pP])$/,
    ["text/x-shellscript"] = /((ba|tc|c|z|fa|ae|k)?sh)$/,
    ["text/x-perl"] = /([pP][eE][rR][lL]|[aA][lL]|[pP][lL]|[pP][mM])$/,
    ["text/x-ruby"] = /([rR][bB])$/,
    ["text/x-python"] = /([pP][yY]|[wW][sS][gG][iI])$/,
    ["text/x-awk"] = /([aA][wW][kK])$/,
    ["text/x-tcl"] = /([tT][cC][lL]|[tT][kK])$/,
    ["text/x-lua"] = /([lL][uU][aA])$/,
    ["application/javascript"] = /([jJ][sS])$/,
    ["text/x-php"] = /[pP][hH][pP][123s]?$/,
    ["application/zip"] = /([zZ][iI][pP])$/,
    ["application/x-rar"] = /([rR][aA][rR])$/,
    ["application/x-gzip"] = /([gG][zZ])$/,
    ["application/x-tar"] = /([tT][aA][rR])$/,
    ["application/x-dmg"] = /([dD][mM][gG])$/,
    ["application/x-7z-compressed"] = /([7][zZ])$/,

    ## We don't really care about pictures/videos
    ##["audio/mpeg"] = /([mM][pP][3]|[mM][pP][gG][aA])$/,
    ##["audio/mp4"] = /([mM][4][aA])$/,
    ##["image/tiff"] = /([tT][iI][fF][fF]?)$/,
    ##["image/gif"] = /([gG][iI][fF])$/,
    ##["image/jpeg"] = /([jJ][pP][eE][gG]?|[jJ][pP][gG])$/,
    ##["image/x-ms-bmp"] = /([bB][mM][pP])$/,
    ##["image/vnd.adobe.photoshop"] = /([pP][sS][dD])$/,
    ##["image/png"] = /[pP][nN][gG]$/,

    ["application/msword"] = /([dD][oO][cC])$/,
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = /([dD][oO][cC][xX])$/,
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = /([xX][lL][sS][xX])$/,
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = /([pP][pP][tT][xX])$/,

    ##["video/x-flv"] = /([fF][lL][vV])$/,
    ##["video/x-flc"] = /([fF][lL][cC])$/,
    ##["video/mpeg"] = /([mM][pP]([2]|[e]|[g]|[e][g])|[vV][oO][bB]|[vV][dD][rR])$/,
    ##["video/webm"] = /([wW][eE][bB][mM])$/,
    ##["video/quicktime"] = /([qQ][tT]([vV][rR])?|[mM][oO][oO]?[vV])$/,
    ##["video/mp4"] = /([mM][pP][4]|([mM]|[fF])[4][vV])$/,

    ["application/x-java-archive"] = /([jJ][aA][rR])$/,
    ["application/x-pem"] = /([pP][eE][mM]|[dD][eE][rR]|[cC][eE][rR][tT]|[cC][rR][tT])$/,
    ["application/x-ms-shortcut"] = /([lL][nN][kK])$/,
    ["application/x-bittorrent"] = /([tT][oO][rR][rR][eE][nN][tT]$)/,

    ##["audio/x-wav"] = /([wW][aA][vV])$/,

    ["application/x-dosexec"] = /([eE][xX][eE]|[dD][lL][lL])$/,
    ["application/pdf"] = /([pP][dD][fF])$/,
    ["text/rtf"] = /([rR][tT][fF])$/,

    ##["audio/x-aiff"] = /([aA][iI][fF]([cC|[fF])?)$/,
    ##["audio/x-flac"] = /([fF][lL][aA][cC])$/,
    ##["audio/midi"] = /([mM][iI][dD]([iI])?|[kK][aA][rR])$/,

    ["text/x-tex"] = /([iI][nN][sS])$/,
    ["application/xml"] = /([xX][mM][lL])$/,
    ["text/html"] = /([hH][tT][mM][lL]?)$/,
  } &redef;
  
}

event bro_init() &priority=5
{
  Log::create_stream(Mime::LOG, [$columns=Info, $ev=log_files, $path="mime"]);
}

event file_sniff(f: fa_file, meta: fa_metadata)
{
  if (!meta?$mime_type || !f$info?$filename) return;
  if(/\./ !in f$info$filename) return;
  if(f$info$filename == "f.txt") return;

	local mime_ext = meta$mime_type;
  local file_ext_array = split_string_all(f$info$filename, /\./);
  local file_ext = file_ext_array[|file_ext_array| - 1];

  if(mime_ext in mime_types_extensions && 
     mime_types_extensions[mime_ext] !in file_ext)
  {
    local message = fmt("'%s' downloaded as '%s'", mime_ext, f$info$filename);
    local note = fmt("Mime_Type_Ext_Mismatch");

    ## sort of hacky way to get single id. Should be changed
    for(id in f$conns)
    
    ## Add this in to save files that have mismatch
    #Files::add_analyzer(f, Files::ANALYZER_EXTRACT);

    Log::write(Mime::LOG, [$ts=f$info$ts, $fuid=f$info$fuid, 
                          $tx_hosts=f$info$tx_hosts, 
                          $rx_hosts=f$info$rx_hosts, 
                          $conn_uids=f$info$conn_uids, 
                          $source=f$info$source, $mime_type=meta$mime_type, 
                          $filename=f$info$filename, 
                          $note=note, $msg=message]);

    NOTICE([$note=Mime_Type_Ext_Mismatch,
      $msg=fmt("%s downloaded as %s", meta$mime_type, f$info$filename)]);
    
  }
}
