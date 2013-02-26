#!/usr/bin/perl

# original code by Matt Amdur
# modified by Kyle Hailey to seperate out reads and writes and compact histograms

 $DEBUG=0;
  if  ( 1 == $DEBUG ) { $debug=1; }

  my ($TSHARK) = "/usr/local/bin/tethereal -V -r ";
  my ($TSHARK_FILTER) = "rpc.msgtyp eq 0 or rpc.msgtyp eq 1  ";

  my ($server_file) = $ARGV[0];
  my ($client_file) = $ARGV[1];

  my (%server_frames) = ();
  my (%client_frames) = ();
  my (%xids);

  $bucketmin=7;
  $bucketmax=20;

  @buckett[0]="1u ";
  @buckett[1]="2u ";
  @buckett[2]="4u ";
  @buckett[3]="8u ";
  @buckett[4]="l6u ";
  @buckett[5]="32u ";
  @buckett[6]="64u ";
  @buckett[7]=".1m ";   # 128
  @buckett[8]=".2m ";   # 256
  @buckett[9]=".5m ";   # 512
  @buckett[10]="1m ";   # 1024
  @buckett[11]="2m ";   # 2048
  @buckett[12]="4m ";   # 4096
  @buckett[13]="8m ";   # 8192
  @buckett[14]="16m ";  # 16384
  @buckett[15]="33m ";  # 32768
  @buckett[16]="65m ";  # 65536
  @buckett[17]=".1s ";   # 131072
  @buckett[18]=".3s ";   # 262144
  @buckett[19]=".5s ";   # 524288
  @buckett[20]="1s ";    # 1048576
  @buckett[21]="2s ";    # 2097152
  @buckett[22]="4s ";    # 4194304
  @buckett[23]="8s ";    # 8388608
  @buckett[24]="17s ";   # 16777216
  @buckett[25]="34s ";   # 33554432
  @buckett[26]="67s ";   # 67108864

  sub print_hist_head {
     printf("type       avg ms count ",);
     for ($bucket = $bucketmin; $bucket < $bucketmax; $bucket++) {
        printf ("%6s", $buckett[$bucket] );
     }
     printf ("%6s+", $buckett[$bucketmax-1] );
     printf("\n");
 }

 sub print_hist {

         $sum_min=0;
         $sum_max=0;

       
         # sum up all the buckets below the minimum bucket
         for ($bucket = 0; $bucket <= $bucketmin; $bucket++) {
             $sum_min+= $hist{$event,$bucket} ;
             printf("sum_min: %d, bucket %d value %d\n",  $sum_min,  $bucket, $hist{$event,$bucket} )  if defined($debug) ;
         }

         # sum up all the buckets above the maximum bucket
         for ($bucket = $bucketmax; $bucket <= $cur_max_bucket{$event}; $bucket++) {
             $sum_max+= $hist{$event,$bucket} ;
             printf("sum_max: %d, bucket %d value %d\n",  $sum_max,  $bucket, $hist{$event,$bucket} )  if defined($debug) ;
         }

         # if maxbucket eq min bucket add the max and min
         if ( $bucketmin < $bucketmax ) {
              printf ("%6d",  $sum_min  );             
              printf("\nfinal sum_min: %d \n",  $sum_min )  if defined($debug) ;
         } else  {
              printf ("%6d",  $sum_min + $sum_max  );
              printf("\n sum_max + sum_min : %d \n",  $sum_min + $sum_max )  if defined($debug) ;
         }

         # iterate through all the buckets between max and min bucket
         for ($bucket = $bucketmin+1; ( $bucket <= $cur_max_bucket{$event} && $bucket < $bucketmax ) ; $bucket++) {
             printf ("%6d",  $hist{$event,$bucket}  );
             $total+=$hist{$event,$bucket};
         }

         # print out max bucket if its below the maximum seen so far
         if ( $bucketmax <= $cur_max_bucket{$event} &&  $bucketmin  < $bucketmax ) {
            printf ("%6d",  $sum_max  );
         }

         printf("\n");
  }

#
# Parse the packet trace
#
sub parse_file {
	my ($file) = @_[0];
	my ($frames) = @_[1];
        my ($type);
        my ($size)=0;
	my ($xid, $call_frame, $reply_frame, $frame, $ela );
	open (FILE, "$TSHARK $file $TSHARK_FILTER|") ||
		die "Failed to exec $TSHARK $file $TSHARK_FILTER";
        $type="NONE";
	while (<FILE>) {
		my ($line) = $_;

                 if ($line =~ /V3 Procedure: WRITE/) {
                    $type="WRITE";
                 }
                 if ( $line =~ /count:/ ) {
                    $size=$line;
                    $size =~ s/.*://;
                 }
                 if ($line =~ /V3 Procedure: READ/) {
                    $type="READ";
                 }
                 if ($line =~ /Remote Procedure Call, Type:Call/) {
			$line =~ m/XID:0x([0-9a-f]*)/;
			$xid = "0x$1";
			$xid = 0;
  		 } elsif ($line =~ /Remote Procedure Call, Type:Reply/) {
		 	$line =~ m/XID:0x([0-9a-f]*)/;
			$xid = "0x$1";
		 }  
                 if ($line =~ m/Time from request: ([0-9]\.[0-9]*)/) {
			if ($xid eq 0) { die "no xid for time"; }
                        $ela=$1*1000*1000; 
			if (!(exists $xids{$type}{$xid})) { $xids{$type}{$xid} = $xid; }
                        $frames->{"$xid"} = $1;
                        $packets{$file}{$type}{"$xid"} = $1;
                        if ( $ela > 0 ) {
                               $bucket=int(log($ela)/log(2)+1);
                               $hist{$type,$bucket}++;
                               $hist_ct{$type}++;
                               $hist_sm{$type}+=$ela;
                               if ( $bucket >  $cur_max_bucket{$type}  ) {
                                  $cur_max_bucket{$type} =$bucket;
                               }
                        }  else  {
                               $zeros{$type}++;
                        }
                        $count{$type}++;
			$xid = 0;
                        $type="NONE";
                        $size=0;
		} 
	}
	close (FILE);

        print_hist_head;
        if ( $count{$type} > 0 ) {
          foreach $event ( "READ", "WRITE","NONE") {
            if ($hist_ct{$event} ) {
               printf("%7s :%6.2f,%7d",$event,$hist_sm{$event}/$hist_ct{$event}/1000,$hist_ct{$event});
               print_hist;
            } 
          }
       }

}

sub process_packets {
	my ($xid);
	my ($match) = 0;
	my ($miss) = 0;
	my ($ela) = 0;

        # these didn't work as private
        # as they aren't used else where, using them as global
	#my ($x) ;
        #my ($server) ;
        #my ($client) ;
        #my ($diff) ;

	my ($server_latency) = 0;
	my ($client_latency) = 0;

        foreach $type ("READ","WRITE","NONE") {
  	   for $xid (keys %{$xids{$type}} ) {
   		if (exists $packets{$server_file}{$type}{"$xid"} and
   		    exists $packets{$client_file}{$type}{"$xid"} ) {
			$server = $packets{$server_file}{$type}{"$xid"};
			$client = $packets{$client_file}{$type}{"$xid"} ;
			$diff = $client -  $server;
                        foreach $x ( "server", "client","diff") {
                           $ela=${$x}*1000*1000;
                           if ($ela > 0 ) { $bucket=int(log($ela)/log(2)+1); }
                           $event=$type . "-" . $x;
                           $hist{$event,$bucket}++;
                           if ( $bucket >  $cur_max_bucket{$event}  ) {
                              $cur_max_bucket{$event} =$bucket;
                           }
                           $hist_sm{$event}+=$ela;
                           $hist_ct{$event}++;
                        } 
			$match{$type}++;
		} else {
			$miss{$type}++;
		}
	   }
           if ( $match{$type} > 0  ) {
             printf("%s\n", $type);
             print_hist_head;
             foreach $x ( "server", "client","diff") {
                $event=$type . "-" . $x;
                if ($hist_ct{$event} ) {
                      printf("%7s :%6.2f,%7d",$x,$hist_sm{$event}/$hist_ct{$event}/1000,$hist_ct{$event});
                } else {
                      printf("%7s :%6.2f,%7d",$x,-1,$hist_ct{$event});
                }
                print_hist;
             }
	     my ($total) = $miss{$type} + $match{$type};
             print "Processed $total packets (Matched: $match{$type} Missed: $miss{$type})\n";
          }
       }
}
		
printf(" ==================== Individual HOST DATA ============\n");

print "Parsing server trace: $server_file\n";
parse_file($server_file, \%server_frames);
print "Parsing client trace: $client_file\n";
parse_file($client_file, \%client_frames);
printf(" \n");

printf(" ==================== MATCHED DATA  ============\n");
process_packets();

