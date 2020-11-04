@load base/frameworks/notice

module LargeTrafficChange;

export {
  redef enum Notice::Type += {
    ## Indicates packets were dropped by the packet filter.
    LargeOrigTrafficChange,
    LargeRespTrafficChange,
  };
    
  redef enum Log::ID += { LOG };

  type Info: record {
      start_time: string &log;
      role: string &log;
      epoch: interval &log;
      lastn: count &log;
      total_bytes: double &log;
      cur_mean: double &log;
      cur_std_dev: double &log;
      cur_variance: double &log;
  };

  global log_large_traffic_change: event(rec: Info);

  #this will capture 24 hours of traffic
  global epoch: interval = 5min &redef;
  global lastn: count = 288;
  global orig_num_std_dev: count = 5;
  global resp_num_std_dev: count = 4;

  global orig_traffic_vec: vector of double;
  global orig_i: count = 0;
  global orig_variance: double = 0;
  global orig_mean: double = 0;
  global orig_old_variance: double = 0;
  global orig_old_mean: double = 0;
    
  global resp_traffic_vec: vector of double;
  global resp_i: count = 0;
  global resp_variance: double = 0;
  global resp_mean: double = 0;
  global resp_old_variance: double = 0;
  global resp_old_mean: double = 0;
}

event bro_init()
{
  local rec: LargeTrafficChange::Info;
  Log::create_stream(LargeTrafficChange::LOG, [$columns=Info, $ev=log_large_traffic_change]);

  local orig_r1 = SumStats::Reducer($stream="orig_traffic", $apply=set(SumStats::SUM));
  SumStats::create([$name="orig_traffic",
    $epoch=epoch,
    $reducers=set(orig_r1),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
    {
      local orig_r = result["orig_traffic"];
      orig_mean = 0;
      orig_variance = 0;
      #print fmt("orig_sum: %f", orig_r$sum);

      orig_traffic_vec[orig_i%lastn] = orig_r$sum;

      if(orig_i >= lastn - 1)
      {
        for(j in orig_traffic_vec)
        {
          orig_mean = orig_mean + orig_traffic_vec[j]; 
        }
        orig_mean = orig_mean / lastn;
        #print fmt("orig_mean: %f", orig_mean);

        for(j in orig_traffic_vec)
        {
          orig_variance = orig_variance + (orig_traffic_vec[j] - orig_mean)*(orig_traffic_vec[j] - orig_mean);
        }
        orig_variance = orig_variance / lastn;
        #print fmt("orig_variance %f", orig_variance);
        
        if(orig_i >= lastn)
        {
          #print fmt("orig_mean+%f*orig_std_dev %f", orig_num_std_dev, orig_old_mean + orig_num_std_dev*sqrt(orig_old_variance));
          if(orig_r$sum > orig_old_mean + orig_num_std_dev*sqrt(orig_old_variance))
          {
            #print fmt("Orig Notice raised");
            NOTICE([$note=LargeOrigTrafficChange,
              $msg=fmt("Orig Traffic %f > %f (mean %f + orig_num_std_dev %f * std_dev %f)", orig_r$sum, orig_old_mean + orig_num_std_dev*sqrt(orig_old_variance), orig_old_mean, orig_num_std_dev, sqrt(orig_old_variance))]);
          }  

        }

        local orig_rec = [$start_time= strftime("%c", orig_r$begin), $epoch=epoch, $lastn=lastn, $role=key$str, $total_bytes=orig_r$sum, $cur_mean=orig_old_mean, $cur_std_dev=sqrt(orig_old_variance), $cur_variance=orig_old_variance];
        Log::write(LargeTrafficChange::LOG, orig_rec);

        orig_old_variance = orig_variance;
        orig_old_mean = orig_mean;
      }

      orig_i = orig_i + 1; 
    }
  ]);

  local resp_r1 = SumStats::Reducer($stream="resp_traffic", $apply=set(SumStats::SUM));
  SumStats::create([$name="resp_traffic",
    $epoch=epoch,
    $reducers=set(resp_r1),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
    {
      local resp_r = result["resp_traffic"];
      resp_mean = 0;
      resp_variance = 0;
      #print fmt("resp_sum: %f", resp_r$sum);

      resp_traffic_vec[resp_i%lastn] = resp_r$sum;

      if(resp_i >= lastn - 1)
      {
        for(j in resp_traffic_vec)
        {
          resp_mean = resp_mean + resp_traffic_vec[j]; 
        }
        resp_mean = resp_mean / lastn;
        #print fmt("resp_mean: %f", resp_mean);

        for(j in resp_traffic_vec)
        {
          resp_variance = resp_variance + (resp_traffic_vec[j] - resp_mean)*(resp_traffic_vec[j] - resp_mean);
        }
        resp_variance = resp_variance / lastn;
        #print fmt("resp_variance %f", resp_variance);
        
        if(resp_i >= lastn)
        {
          #print fmt("resp_mean+%f*resp_std_dev %f", resp_num_std_dev, resp_old_mean + resp_num_std_dev*sqrt(resp_old_variance));
          if(resp_r$sum > resp_old_mean + resp_num_std_dev*sqrt(resp_old_variance))
          {
            #print fmt("Resp Notice raised");
            NOTICE([$note=LargeRespTrafficChange,
              $msg=fmt("Resp Traffic %f > %f (mean %f + resp_num_std_dev %f * std_dev %f)", resp_r$sum, resp_old_mean + resp_num_std_dev*sqrt(resp_old_variance), resp_old_mean, resp_num_std_dev, sqrt(resp_old_variance))]);
          }  

        }

        local resp_rec = [$start_time= strftime("%c", resp_r$begin), $epoch=epoch, $lastn=lastn, $role=key$str, $total_bytes=resp_r$sum, $cur_mean=resp_old_mean, $cur_std_dev=sqrt(resp_old_variance), $cur_variance=resp_old_variance];
        Log::write(LargeTrafficChange::LOG, resp_rec);

        resp_old_variance = resp_variance;
        resp_old_mean = resp_mean;
      }

      resp_i = resp_i + 1; 
    }
  ]);
}

event connection_state_remove(c: connection)
{
        SumStats::observe("orig_traffic", [$str="orig"], [$num=c$orig$size]);
        SumStats::observe("resp_traffic", [$str="resp"], [$num=c$resp$size]);
        #SumStats::observe("agg_traffic", [$str="aggregate"], [$num=c$resp$size + c$orig$size]);

}
