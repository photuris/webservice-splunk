#!/usr/bin/env perl

package WebService::Splunk;

use utf8;                   # unicode
use Modern::Perl '2013';    # best practices
use Moose;                  # object orientation
use LWP::UserAgent;         # http client
use IO::Socket::SSL;        # secure sockets layer
use JSON::XS;               # javascript object notation
use Carp;                   # error handling

=head1 ATTRIBUTES

=over4

=item B<hostname>

The Splunk instance hostname.

=item B<username>

Splunk login user name.

=item B<password>

Splunk login password.

=item B<port>

Splunk API port (defaults to 8089).

=item B<unsafe_ssl>

Flag to ignore SSL certificate verification.

=item B<jobs_uri>

Path to RESTful interface for Splunk search jobs.

=item B<login_uri>

Path to RESTful inteface for Splunk logins.

=item B<json_parser>

JSON parser.

=item B<user_agent>

User agent class.

=item B<mode>

All output is parsed as JSON.

=cut

has 'hostname'  => ( is => 'rw', isa => 'Str', required => 1 );
has 'username'  => ( is => 'rw', isa => 'Str', required => 1 );
has 'password'  => ( is => 'rw', isa => 'Str', required => 1 );
has 'port'      => ( is => 'rw', isa => 'Int', default => 8089 );
has 'unsafe_ssl'=> ( is => 'rw', isa => 'Bool', default => 0);

has 'jobs_path' => (
  is => 'rw', isa => 'Str', default => '/servicesNS/admin/search/search/jobs'
);

has 'login_path' => (
  is => 'rw', isa => 'Str', default => '/servicesNS/admin/search/auth/login'
);

has 'jobs_uri'  => ( is => 'rw', isa => 'Str' );
has 'login_uri' => ( is => 'rw', isa => 'Str' );

has 'json_parser' => (
  is       => 'ro',
  isa      => 'JSON::XS',
  required => 1,
  default  => sub { JSON::XS->new }
);

has 'user_agent' => (
  is       => 'ro',
  isa      => 'LWP::UserAgent',
  required => 1,
  default  => sub { LWP::UserAgent->new( agent => 'SAPortal' ) }
);

has 'mode' => (
  is      => 'ro',
  isa     => 'Str',
  default => sub { 'output_mode=json' }
);

=back

Processes run before object instantiation.

=cut

around BUILDARGS => sub {
  my $orig  = shift;
  my $class = shift;
  my %args  = @_;

  # Ignore SSL certificate verification
  if ($args{unsafe_ssl}) {
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

    IO::Socket::SSL::set_ctx_defaults(
      SSL_verifycn_scheme => 'www', SSL_verify_mode => 0
    );
  }

  return $class->$orig(@_);
};

=head1 METHODS

=over4

=item B<BUILD()>

At object instantiation, build URL parameters.

=cut

sub BUILD {
  my $self = shift;

  $self->login_uri(
    'https://' . $self->hostname . ':' . $self->port . $self->login_path
  );

  $self->jobs_uri(
    'https://' . $self->hostname . ':' . $self->port . $self->jobs_path
  );
}

=item B<_request()>

Pass an HTTP request to the Splunk server, and return the
results (JSON-decoded).

@param  scalar {String}  HTTP method (GET, POST, PUT, or DELETE)
@param  scalar {String}  The target URL
@param  scalar {String}  POST content
@param  scalar {String}  Splunk login session

=cut

sub _request {
  my $self = shift;
  my ( $method, $target, $content, $session ) = @_;

  $method = uc $method;

  if ($method eq 'POST') {
    if ($content) {
      $content .= '&' . $self->mode;
    }
  }
  elsif ($method eq 'GET') {
    if ($target =~ m/\&/) {
      $target .= '&' . $self->mode;
    }
    else {
      $target .= '?' . $self->mode;
    }
  }

  my $request = HTTP::Request->new(
    $method => $target, $session ? [ $session ] : undef
  );

  if ($method eq 'POST') {
    $request->content_type('application/x-www-form-urlencoded');

    if ($content) {
      $request->content($content);
    }
  }

  my $response = $self->user_agent->request($request);

  if ($response->is_success) {
    if ($response->decoded_content) {
      return $self->json_parser->decode($response->decoded_content);
    }
  }
  else {
    croak $response->status_line;
  }

  return 0;
}

=item B<_get_session()>

Provided the username and password, create a user session ID.

@returns  ref {Hash}  Splunk login session

=cut

sub _get_session {
  my $self = shift;

  my $login_string =
    'username=' . $self->username . '&password=' . $self->password;

  if ( my $key = $self->_request('POST', $self->login_uri, $login_string) ) {
    return { Authorization => "Splunk $key->{sessionKey}" };
  }

  return 0;
}

=item B<_run_job()>

Create a search job, given an SPL query string. Optionally, pass in
the user session ID (if one isn't given, a session will be generated).
Return the job ID.

@param    scalar {String}   The query string
@param    scalar {String}   The user session ID
@returns  scalar {Integer}  The job ID

=cut

sub _run_job {
  my $self = shift;
  my ( $query, $session ) = @_;

  $session = $self->_get_session unless defined $session;   # login session
  $query   = $self->_correct_query_string($query);          # validate query
  $query   = "search=$query&required_field_list=*";         # format string

  if ($session) {
    if (my $job = $self->_request('POST', $self->jobs_uri, $query, $session)) {
      return $job->{sid};
    }
  }

  return 0;
}

=item B<_query_job()>

Given a job ID, continually query job for run status, and
if it's finished, fetch and return the results.

@param    scalar {Integer}  The job ID
@param    scalar {String}   The user session ID
@returns  ref {Hash}        The results

=cut

sub _query_job {
  my $self = shift;
  my ( $job_id, $session ) = @_;

  my $job_processing = 1;    # job status is still pending
  my $results;

  while ($job_processing) {
    $results = $self->_request(
      'GET', $self->jobs_uri . "/$job_id/results", undef, $session
    );

    $job_processing = 0 if $results;
  }

  if ($results) {
    return $results;
  }

  return 0;
}

=item B<query()>

Run the SPL query, return the results.

@param    ref {String}  The query string
@returns  ref {Hash}    The results

=cut

sub query {
  my $self = shift;
  my ( $query ) = @_;

  if (my $job_id = $self->_run_job($query)) {
    if (my $results = $self->_query_job($job_id)) {
      return $results;
    }
  }

  return 0;
}

=item B<_correct_query_string()>

Prepend "search" keyword to query, if it's not included.

@param    ref {String}     The query string
@returns  scalar {String}  The query string

=cut

sub _correct_query_string {
  my $self = shift;
  my ( $query ) = @_;

  $query = "search $query" if $query !~ /^search/;

  return $query;
}

=back

=cut

__PACKAGE__->meta->make_immutable;
no Moose;

=head1 SYNOPSIS

Splunk integration library.

=cut
