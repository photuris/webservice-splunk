WebService::Splunk
==================

Perl wrapper for Splunk REST API. Simple, no frills. Uses JSON responder.

  #!/usr/bin/env perl

  use strict;
  use warnings;
  use WebService::Splunk;

  my $query = 'sourcetype=things | dedup id';

  my $splunk = WebService::Splunk->new(
  	hostname => '127.0.0.1',
  	username => 'admin',
  	password => 'test123'
  );

  my $things = $splunk->query($query);

  for my $row (@{$things->{results}}) {
    say $row->{field1}, "\t", $row->{field2};
  }
