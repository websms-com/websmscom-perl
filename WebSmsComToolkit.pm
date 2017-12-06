# MIT License
#
# Copyright sms.at internet services gmbh
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the
# following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
# NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
# USE OR OTHER DEALINGS IN THE SOFTWARE.

=head1 NAME

WebSmsComToolkit - SMS Client

=head1 SYNOPSIS

 # sending a text message
 
 use WebSmsComToolkit;
 
 # 1. create client
 
  $sms_client  = WebSmsComToolkit::Client->new( "https://api.websms.com",
                                                "username",
                                                "password");
 
 # 2. create a message
 
 $sms_message = WebSmsComToolkit::TextMessage->new( $recipient_address_list, 
                                                    $utf8_message_text);
 
 # 3. send message
 
 $response    = $sms_client->send( $sms_message, 
                                   $max_sms_per_message, 
                                   $test);
 

=head1 DESCRIPTION

This module can be used to create a reusable sms client over which
you can send created I<TextMessages> or I<BinaryMessages>.

=head2 FEATURES

=over 4

=item * correct Unicode handling

=item * convenient API communication I<(uses LWP::Useragent to post JSON to BusinessPlatform API)>

=item * simple to use

You should not need to play around with the HTTP Request itself

=back

=cut

package WebSmsComToolkit;

our $VERSION = '1.10';

use strict;
use utf8;
use LWP::UserAgent;
use JSON::XS;
use Carp;

=head2 Classes

=over 4

=item B<WebSmsComToolkit::Client>

  $sms_client  = WebSmsComToolkit::Client->new( "https://api.websms.com",
                                                "username",
                                                "password");
  
=cut

package WebSmsComToolkit::Client;

use base qw(WebSmsComToolkit);

sub new {
  my ($proto, $url_base, $user, $pass) = @_;
  my $class = ref($proto) || $proto;
  
  my $self = {};
  
  bless $self, $class;
  $self->init($url_base, $user, $pass) or return undef;

  return $self;
}

sub init {
  my ($self, $url_base, $user, $pass) = @_;
  
  $url_base =~ s/\/+$//;
  
  $self->{'config'} = {};
  $self->{'config'}->{'timeout'}            = 10; # in seconds
  $self->{'config'}->{'endpoint'}           = $url_base;
  $self->{'config'}->{'endpoint_base'}      = "/json";
  $self->{'config'}->{'endpoint_text'}      = "/smsmessaging/text";
  $self->{'config'}->{'endpoint_binary'}    = "/smsmessaging/binary";
  $self->{'config'}->{'endpoint_converged'} = "/converged/text";
  $self->{'config'}->{'user'}               = $user;
  $self->{'config'}->{'pass'}               = $pass;
  $self->{'config'}->{'verbose'}            = 0;
  
  ## Error-Messages ##
  $self->{'error'}  = {};
  $self->{'error'}->{'internal'}  = "An internal error occurred.";
  
  ### Modules
  $self->_create_useragent() or return undef;
  $self->_create_http_headers() or return undef;
  
}


=item I<$client-E<gt>verbose($bool)>

set/get verbose - print HTTP Transfer to STDOUT

  $sms_client->set_verbose(1);
  
=cut

sub verbose {
  my ($self, $value) = @_;
  if (defined($value)) {
    $self->{'config'}->{'verbose'} = ($value) ? 1 : 0;
  }
  return $self->{'config'}->{'verbose'};
}

=item I<$client-E<gt>user_agent()>

direct access to LWP::UserAgent object

  $sms_client->user_agent();
  
  # for setting connection timeout use
  $sms_client->timeout(10);
  
=cut

sub user_agent {
  my ($self) = @_;
  return $self->{'lwp_user_agent'};
}

=item I<$client-E<gt>timeout($seconds)>

Set connection timeout in seconds
  
  $sms_client->timeout(10);
  
=cut

sub timeout {
  my ($self, $seconds) = @_;
  
  if (defined($seconds)) {
    $self->{'config'}->{'timeout'} = $seconds;
    $self->{'lwp_user_agent'}->timeout($self->{'config'}->{'timeout'});
  }
  return $self->{'config'}->{'timeout'};
}

sub _create_useragent {
  my ($self) = @_;
  
  $self->{'lwp_user_agent'} = LWP::UserAgent->new or do {
    Carp::croak ("Couldnot create LWP::UserAgent");
    return undef;
  };
  
  $self->{'lwp_user_agent'}->agent("Perl SDK Client (v".$VERSION.", Perl " . $] . ")");
  $self->{'lwp_user_agent'}->timeout($self->{'config'}->{'timeout'});
  #$self->{'lwp_user_agent'}->proxy($setting);
  
  return 1;
}

sub _create_http_headers {
  my ($self) = @_;
  
  $self->{'http_headers'} = HTTP::Headers->new(Content_Type => 'application/json; charset=UTF-8') or do {
    Carp::carp ("Couldnot create HTTP::Header");
    return undef;
  };
  $self->{'http_headers'}->authorization_basic($self->{'config'}->{'user'}, $self->{'config'}->{'pass'});
  
  return 1;
}

sub _do_request {
  my ($self, $url, $content) = @_;
  
  $self->{'last_http_response'} = undef;

  my $request = HTTP::Request->new('POST', $url, $self->{'http_headers'}, $content) or do {
    Carp::carp ("Couldnot create HTTP::Request");
    return undef;
  };
  $request->protocol('HTTP/1.0');
  
  my $response;
  my $reponse_content;

  print "HTTP Request :\n----\n".$request->as_string()."\n----\n" if ($self->{'config'}->{'verbose'});

  eval {
    local $SIG{ALRM} = sub { die "Timeout" }; # NB: \n required
    alarm $self->{'config'}->{'timeout'}+1;

    $response = $self->{'lwp_user_agent'}->request($request); 

    alarm 0;
  };

  if (@!) {
    Carp::carp("Forced Timeout: @!\n");
  }
  
  if ($response) {
    print "HTTP Response:\n----\n".$response->as_string()."\n----\n" if ($self->{'config'}->{'verbose'});
  } else {
    Carp::carp ("LWP::UserAgent Request to '$url' returned no response");
  }
   
  $self->{'last_http_request'}   = $request;
  $self->{'last_http_response'}  = $response;

  return $response;
}

=item I<$client-E<gt>send($message_object, $max_sms_per_message, $test)>

Send Message. 

$message object must be of type (I<WebSmsComToolkit::TextMessage>, I<WebSmsComToolkit::BinaryMessage> or I<WebSmsComToolkit::ConvergedMessage>)
  
  # send text message (1 SMS)
  $text_message = WebSmsComToolkit::TextMessage->new( ['4367612345678'], 'Hallo Welt!');
  
  $sms_client->send($text_message, 1);
  
  # send binary message (2 SMS)
  $binary_message = WebSmsComToolkit::BinaryMessage->new( 
                      ['4367612345678'], ['BQAD/AIBWnVzYW1tZW4=','BQAD/AICZ2Vmw7xndC4=']);
  
  $response = $sms_client->send($binary_message) or die "LWP Connection error.";

  # send converged message (1 SMS)
  my $additional_push_parameters = { 'key' => 'value' };
  $converged_message = WebSmsComToolkit::ConvergedMessage->new(
                      ['4367612345678'], 'Hallo Welt!', $additional_push_parameters);
  
  $sms_client->send($converged_message, 1);
  
  # Response success:
  # $response = {
  #        'transferId'    => '005065a89200043a409e',
  #        'statusMessage' => 'OK',
  #        'statusCode'    => 2000
  #      }
  if ($response->{'statusCode'} == 2000 || $response->{'statusCode'} == 2001) {
    print "Message transferred. transferId: ".$response->{'statusCode'}."\n";
  }

  #
  # Response error (HTTP or server error):
  # $response = {
  #        'error'        => 1, # always 1
  #        'http_status'   => 'OK',
  #        'error_content' => 2000
  #      }
  if ($response->{'error'}) {
    print $response->{'http_status'}."\n".$response->{'error_content'};
  }
  
  
=cut

sub send {
  my ($self, $message_object, $max_sms_per_message, $test ) = @_;
  
  if (defined($max_sms_per_message) && ($max_sms_per_message !~ /\d+$/ || $max_sms_per_message < 1)) {
      Carp::croak("max_sms_per_message parameter has to be a number > 0 or undefined");
  }
  
  my $endpoint_url = $self->{'config'}->{'endpoint'}.$self->{'config'}->{'endpoint_base'};
  
  if (ref($message_object) eq 'WebSmsComToolkit::TextMessage') {
  
    $endpoint_url .= $self->{'config'}->{'endpoint_text'};
  
  } elsif (ref($message_object) eq 'WebSmsComToolkit::BinaryMessage') {
  
    if (defined($max_sms_per_message)) {
      Carp::carp ("BinaryMessage does not support 'max_sms_per_message' parameter. Set to undef to prevent this warning.");
    }
    $endpoint_url .= $self->{'config'}->{'endpoint_binary'};

  } elsif (ref($message_object) eq 'WebSmsComToolkit::ConvergedMessage') {

    $endpoint_url .= $self->{'config'}->{'endpoint_converged'};
  
  } else {
    Carp::carp ("Invalid message object ".ref($message_object).", must be of WebSmsComToolkit::TextMessage, WebSmsComToolkit::BinaryMessage or WebSmsComToolkit::ConvergedMessage.");
    return undef;
  }
  
  my $msg = $message_object->data();
  
  $msg->{'test'}             = ($test) ? JSON::XS::true : JSON::XS::false;
  
  if ($max_sms_per_message) {
    $msg->{'maxSmsPerMessage'} = $max_sms_per_message;
  }
  
  my $json = JSON::XS::encode_json($msg);
  
  my $http_response = $self->_do_request($endpoint_url, $json) or return undef;
  
  my $json_response = undef;
  if ($http_response && $http_response->is_success && $http_response->header('Content-Type') =~ /json/i) {
    # decode API response
    $json_response = JSON::XS::decode_json($http_response->content);
  } elsif ($http_response) {
    # check for 401 or garbage
    $json_response                    = {};
    $json_response->{'http_status'}   = $http_response->status_line || '';
    $json_response->{'error'}         = 1;
    if ($json_response->{'http_status'} =~ /^401 /) {
      $json_response->{'error_content'} = "User not authorized or bad credentials (HTP Status 401) - check correct username and password at client creation.";
    } else {
      $json_response->{'error_content'} = $http_response->content;
    }
  } else {
    Carp::carp("No HTTP Response. Please check given URL or SSL capability of LWP::UserAgent");
  }
  
  return $json_response;
}


package WebSmsComToolkit::Message;

use base qw(WebSmsComToolkit);

our $availableSenderAdressType = {'national' => 1, 'international' => 1, 'alphanumeric' => 1, 'shortcode' => 1};

sub new {
  my ($proto, $recipients) = @_;
  my $class = ref($proto) || $proto;
  
  my $self = [];
  $self->[0] = {};
  $self->[0]->{'recipientAddressList'}     = [];
  $self->[0]->{'senderAddress'}            = undef;
  $self->[0]->{'senderAddressType'}        = undef;
  $self->[0]->{'sendAsFlashSms'}           = undef;
  $self->[0]->{'notificationCallbackUrl'}  = undef;
  $self->[0]->{'clientMessageId'}          = undef;
  $self->[0]->{'priority'}                 = undef;
  
  bless $self, $class;
  
  $self->recipient_address_list($recipients) or return undef;
  
  return $self;
}

## return defined values
sub data {
  my ($self) = @_;
  my $data = {};
  foreach my $key (keys %{$self->[0]}) {
    $data->{$key} = $self->[0]->{$key} if (defined($self->[0]->{$key}));
  }
  return $data;
}

#----------------------------------------------------------------
# recipient_address_list($array)
#   - set array of recipients 
#     (array of strings containing full international MSISDNs)
#----------------------------------------------------------------
sub recipient_address_list {
  my ($self, $recipientAddressList) = @_;
  if (defined($recipientAddressList)) {
    if ($self->check_recipient_address_list($recipientAddressList)) {
      $self->[0]->{'recipientAddressList'} = $recipientAddressList;
    } else {
      Carp::carp ("recipient_address_list parameter must be ARRAY of strings containing recipients MSISDN");
      return undef;
    }
  }
  return $self->[0]->{'recipientAddressList'};
}

#----------------------------------------------------------------
#  getSenderAddress
#    - returns set senderAddress
#----------------------------------------------------------------
sub sender_address {
  my ($self, $senderAddress) = @_;
  if (defined($senderAddress)) {
    if (ref($senderAddress) eq '') {
      $self->[0]->{'senderAddress'} = $senderAddress;
    } else {
      Carp::carp ("sender_address '$senderAddress' invalid. Must be string scalar containing numeric or alphanumeric value");
      return undef;
    }
  } 
  return $self->[0]->{'senderAddress'};
}

#----------------------------------------------------------------
#  sender_address_type
#    - returns set sender address type
#----------------------------------------------------------------
sub sender_address_type {
  my ($self, $senderAddressType) = @_;
  if (defined($senderAddressType)) {
    if (exists($availableSenderAdressType->{$senderAddressType})) {
      $self->[0]->{'senderAddressType'} = $senderAddressType;
    } elsif (!$senderAddressType) {
      $self->[0]->{'senderAddressType'} = undef;
    } else {
      Carp::carp ("sender_address_type '$senderAddressType' invalid. Must be one of '".join(', ',keys %{$availableSenderAdressType})."'.");
      return undef;
    }
  } 
  return $self->[0]->{'senderAddressType'};
}

#----------------------------------------------------------------
#  send_as_flash_sms
#    - returns set SendAsFlashSms flag
#----------------------------------------------------------------
sub send_as_flash_sms {
  my ($self, $sendAsFlashSms) = @_;
  if (defined($sendAsFlashSms)) {
    $self->[0]->{'sendAsFlashSms'} = ($sendAsFlashSms ne 'false' && $sendAsFlashSms) ? JSON::XS::true : JSON::XS::false;
  }
  return $self->[0]->{'sendAsFlashSms'};
}
#----------------------------------------------------------------
#  notification_callback_url
#    - set string og notification callback url
#    customers url that listens for delivery report notifications
#    or replies for this message
#----------------------------------------------------------------
sub notification_callback_url {
  my ($self, $notification_callback_url) = @_;
  
  if (defined($notification_callback_url)) {
    if (ref($notification_callback_url) eq '') {
      $self->[0]->{'notificationCallbackUrl'} = $notification_callback_url;
    } elsif (!$notification_callback_url) {
      $self->[0]->{'notificationCallbackUrl'} = undef;
    } else {
      Carp::carp ("notification_callback_url '$notification_callback_url' invalid. Must be string scalar. ");
      return undef;
    }
  }
  return $self->[0]->{'notificationCallbackUrl'};
}

#----------------------------------------------------------------
#  client_message_id($string)
#    - set message id for this message, returned with response
#      and used for notifications
#----------------------------------------------------------------
sub client_message_id {
  my ($self, $clientMessageId) = @_;
  if (defined($clientMessageId)) {
    if (ref($clientMessageId) eq '') {
      $self->[0]->{'clientMessageId'} = $clientMessageId;
    } elsif ($clientMessageId eq '') {
      $self->[0]->{'clientMessageId'} = undef;
    } else {
      Carp::carp ("client_message_id '$clientMessageId' invalid. Must be string scalar.");
      return undef;
    }
  }
  return $self->[0]->{'clientMessageId'};
}

#----------------------------------------------------------------
#  setPriority(int $priority)
#    - sets message priority as integer (1 to 9)
#     (if supported by account settings)
#----------------------------------------------------------------
sub priority {
  my ($self, $priority) = @_;
  if (defined($priority)) {
    if ($priority =~ /^\d+$/) {
      $self->[0]->{'priority'} = $priority;
    } elsif (!$priority) {
      $self->[0]->{'priority'} = undef;
    } else {
      Carp::carp ("priority '$priority' invalid. Must be a number.");
      return undef;
    }
  }
  return $self->[0]->{'priority'};
}

#----------------------------------------------------------------
#  getJsonData
#    - returns data as json
#----------------------------------------------------------------
sub get_json_data {
  my $self = shift;
  return JSON::XS::encode_json($self->data());
}

#----------------------------------------------------------------
#  checkRecipientAddressList($recipientAddressList)
#      - used to check validity of array
#----------------------------------------------------------------
sub check_recipient_address_list {
  my ($self, $recipientAddressList) = @_;
  
  if (ref($recipientAddressList) ne 'ARRAY') {
    Carp::carp ("Argument 'recipient_address_list' (array) invalid while constructing ".__PACKAGE__);
    return undef;
  }
  
  foreach my $recipient (@{$recipientAddressList}) {
    if ($recipient !~ /^\d{1,15}$/) {
      Carp::carp ("Recipient '" . $recipient . "' is invalid. (must be numeric)");
      return undef;
    }
    if ($recipient =~ /^0/) {
      Carp::carp ("Recipient '" . $recipient . "' is invalid. (max. 15 digits full international MSISDN. Example: 4367612345678)");
      return undef;
    }
  }
  return 1;
}

#--------------------------------------------------------------------

=item B<WebSmsComToolkit::TextMessage>

Message Object for Text Messages
  
  $sms_message = WebSmsComToolkit::TextMessage->new( $recipient_address_list, 
                                                     $utf8_message_text);

=cut

#--------------------------------------------------------------------
package WebSmsComToolkit::TextMessage;

use base qw(WebSmsComToolkit::Message);

sub new {
  my ($proto, $recipients, $message_content) = @_;
  my $class = ref($proto) || $proto;
  
  my $self = $class->SUPER::new($recipients) or return undef; 
  
  $self->[0]->{'messageContent'}         = undef;
  
  if (!defined($self->message_content($message_content))) {
    return undef;
  }
  
  return $self;
}


=item I<$message-E<gt>message_content($utf8_text)>

set/get message_content (sms text)

  $message->message_content("Eurozeichen: \xE2\x82\xAC");
  
=cut

sub message_content {
  my ($self, $message_content) = @_;
  
  if (defined($message_content)) {
    if (ref($message_content) eq '') {
      $self->[0]->{'messageContent'} = $message_content;
    } else {
      Carp::carp ("Invalid message_content for TextMessage. Must be utf8 string scalar.");
      return undef;
    }
  }
  return $self->[0]->{'messageContent'};
}

#--------------------------------------------------------------------
#
#--------------------------------------------------------------------

=item B<WebSmsComToolkit::BinaryMessage>

Message Object for Binary Messages

  $sms_message = WebSmsComToolkit::BinaryMessage->new(  $recipient_address_list, 
                                                        $bas64_encoded_message_segments_arrayref,
                                                        $userDataHeaderPresent);

=cut

#--------------------------------------------------------------------
package WebSmsComToolkit::BinaryMessage;

use base qw(WebSmsComToolkit::Message);

sub new {
  my ($proto, $recipients, $message_content, $user_data_header_present) = @_;
  my $class = ref($proto) || $proto;
  
  my $self = $class->SUPER::new($recipients) or return undef; 
  
  if (ref($message_content) ne 'ARRAY') {
    Carp::carp ("message_content parameter must be ARRAY of strings containing Base64 encoded Binary");
    return undef;
  }
  
  $self->[0]->{'messageContent'}         = [];
  $self->[0]->{'userDataHeaderPresent'}  = JSON::XS::false;
  
  if (!defined($self->message_content($message_content))) {
    return undef;
  }
  $self->user_data_header_present($user_data_header_present);
  
  return $self;
}

=item I<$message-E<gt>message_content($arrayref)>

set/get message_content (arrayref of strings containing base64 encoded binary)

  $message->message_content(['BQAD/AIBWnVzYW1tZW4=','BQAD/AICZ2Vmw7xndC4=']);
  
=cut

sub message_content {
  my ($self, $message_content) = @_;
  
  if (defined($message_content)) {
    if (ref($message_content) eq 'ARRAY') {
      $self->[0]->{'messageContent'} = $message_content;
    } else {
      Carp::carp ("message_content parameter must be ARRAY of strings containing Base64 encoded Binary");
      return undef;
    }
  }
  return $self->[0]->{'messageContent'};
}

=item I<$message-E<gt>user_data_header_present($bool)>

set/get user_data_header_present
  
  # the base64 encoded binary already contains user data header
  $message->message_content(['BQAD/AIBWnVzYW1tZW4=','BQAD/AICZ2Vmw7xndC4=']);
  $message->user_data_header_present(1);
  
=cut

sub user_data_header_present {
  my ($self, $userDataHeaderPresent) = @_;
  if (defined($userDataHeaderPresent)) {
    $self->[0]->{'userDataHeaderPresent'} = ($userDataHeaderPresent ne 'false' && $userDataHeaderPresent) ? JSON::XS::true : JSON::XS::false;
  }
  return $self->[0]->{'userDataHeaderPresent'};
}

#--------------------------------------------------------------------

=item B<WebSmsComToolkit::ConvergedMessage>

Message Object for Converged Messages
  
  $sms_message = WebSmsComToolkit::ConvergedMessage->new( $recipient_address_list, 
                                                          $utf8_message_text,
                                                          $parameter_hash);

=cut

#--------------------------------------------------------------------
package WebSmsComToolkit::ConvergedMessage;

use base qw(WebSmsComToolkit::TextMessage);

sub new {
  my ($proto, $recipients, $message_content, $additional_push_parameters) = @_;
  my $class = ref($proto) || $proto;
  
  my $self = $class->SUPER::new($recipients,$message_content) or return undef; 
  
  $self->[0]->{'additionalPushParameters'}         = undef;

  $self->additional_push_parameters($additional_push_parameters);
  
  return $self;
}


=item I<$message-E<gt>additional_push_parameters($parameter_hash)>

set/get additional_push_parameters (parameter hash)

  $message->additional_push_parameters({ 'key' => 'value'});
  
=cut

sub additional_push_parameters {
  my ($self, $additional_push_parameters) = @_;
  
  if (defined($additional_push_parameters)) {
    if (ref($additional_push_parameters) eq 'HASH') {
      $self->[0]->{'additionalPushParameters'} = $additional_push_parameters;
    } else {
      Carp::carp ("Invalid additional_push_parameters for ConvergedMessage. Must be hash reference.");
      return undef;
    }
  }
  return $self->[0]->{'additionalPushParameters'};
}

=back

=head1 A FEW NOTES ON UNICODE AND PERL

Since this often leads to confusion, here are a few very clear words on
how Unicode works in Perl, modulo bugs.

=over 4

=item 1. Perl strings can store characters with ordinal values > 255.

This enables you to store Unicode characters as single characters in a
Perl string - very natural.

=item 2. Perl does I<not> associate an encoding with your strings.

... until you force it to, e.g. when matching it against a regex, or
printing the scalar to a file, in which case Perl either interprets your
string as locale-encoded text, octets/binary, or as Unicode, depending
on various settings. In no case is an encoding stored together with your
data, it is I<use> that decides encoding, not any magical meta data.

=item 3. The internal utf-8 flag has no meaning with regards to the
encoding of your string.

The flag tells string operations to regard utf-8 characters and usually prevents 
multibyte characters from being cut in the middle.
You can have Unicode strings with that flag set, with that
flag clear, and you can have binary data with that flag set and that flag
clear. Other possibilities exist, too.

If you didn't know about that flag, just the better, pretend it doesn't
exist.

=item 4. A "Unicode String" is simply a string where each character can be
validly interpreted as a Unicode code point.

If you have UTF-8 encoded data, it is no longer a Unicode string, but a
Unicode string encoded in UTF-8, giving you a binary string.

=item 5. A string containing "high" (> 255) character values is I<not> a UTF-8 string.

=back

=head1 EXAMPLES 

=head3 Info on how to set UTF-8 or Unicode message content

=encoding utf-8 

These 3 message examples are all valid and show how to B<set> but do B<not> describe how to B<I<convert>> string encodings to utf8:

See L<http://perldoc.perl.org/Encode.html> for B<conversion>

=over 1

=item 1.) Source code itself is written in utf-8:

  use utf8;
  $utf8_message_content = "Euro-sign: €"  # where the euro sign is 3 bytes \xE2\x82\xAC

=item 2.) is the same as in 1.) but source code itself is for example in iso-8859-15, latin1 or cp1252 etc.
Decode(flag) perl internal string containing 3 bytes (utf8) for euro sign as utf-8 string (Encode::decode)
  
  use Encode;
  my $utf8_message_content = decode("utf-8","Hallo Welt! Eurozeichen: \xE2\x82\xAC");

=item 3.) is like 2.) but using unicode

  my $unicode_message_content = "Euro-sign: \x{000020AC}"); # 4bytes

=back

=head3 TextMessage

Fully working sample (put WebSmsComToolkit.pm somewhere where perl can find it or set $path_to_toolkit):

  #!/usr/bin/perl
  my $path_to_toolkit = ''; #'<path to WebSmsComToolkit.pm>'
  unshift(@INC, $path_to_toolkit) if ($path_to_toolkit ne '');
  
  use WebSmsComToolkit;
  use Encode;

  my ($sms_client, $message, $response);

  # --- Modify these values to your needs ---
  my $gateway_url          = 'https://api.websms.com';
  my $username             = 'your username';
  my $password             = 'your password';
  my $recipients           = ['4367612345678'];
  my $utf8_message_content = decode("utf-8","Hallo Welt! Eurozeichen: \xE2\x82\xAC");
  my $max_sms_per_message  = 1;
  my $test                 = 0; # // 1: do not send sms but test interface, 0: send sms

  # --- 1. create client, 2. create message, 3. send message --- 
  $sms_client = WebSmsComToolkit::Client->new($gateway_url, $username, $password);
  $sms_client->verbose(1);

  $message = WebSmsComToolkit::TextMessage->new($recipients, $utf8_message_content);

  $response = $sms_client->send($message, $max_sms_per_message, $test);

  if (exists($response->{'error'})) {
    
    # HTTP or server error
    print $response->{'http_status'}."\n".$response->{'error_content'};
        
  } else {
  
    # read return values from API
    if ($response->{'statusCode'} == 2000 || $response->{'statusCode'} == 2001) {
      print "SMS sent, transferId: ".$response->{'transferId'}."\n";
    } else {
      print "statusCode   : ".$response->{'statusCode'}."\n";
      print "statusMessage: ".$response->{'statusMessage'}."\n";
    }
  }

=head3 BinaryMessage

=encoding utf-8 

Fully working sample (put WebSmsComToolkit.pm somewhere where perl can find it or set path):

  #!/usr/bin/perl
  my $path_to_toolkit = ''; #'<path to WebSmsComToolkit.pm>'
  unshift(@INC, $path_to_toolkit) if ($path_to_toolkit ne '');
  
  use WebSmsComToolkit;
  use Encode;

  my ($sms_client, $message, $response);

  # --- Modify these values to your needs ---
  my $gateway_url              = 'https://api.websms.com';
  my $username                 = 'your username';
  my $password                 = 'your password';
  my $recipients               = ['4367612345678'];
  my $message_content          = ['BQAD/AIBWnVzYW1tZW4=','BQAD/AICZ2Vmw7xndC4=']; # "Zusammen","gefügt."
  my $max_sms_per_message      = undef;
  my $user_data_header_present = 1;
  my $test                     = 0; # // 1: do not send sms but test interface, 0: send sms

  # --- 1. create client, 2. create message, 3. send message --- 
  $sms_client = WebSmsComToolkit::Client->new($gateway_url, $username, $password);
  $sms_client->verbose(1);
  
  $message = WebSmsComToolkit::BinaryMessage->new($recipients, $message_content, $user_data_header_present);

  $response = $sms_client->send($message, undef, $test);

  if (exists($response->{'error'})) {
    
    # HTTP or server error
    print $response->{'http_status'}."\n".$response->{'error_content'};
        
  } else {
  
    # read return values from API
    if ($response->{'statusCode'} == 2000 || $response->{'statusCode'} == 2001) {
      print "SMS sent, transferId: ".$response->{'transferId'}."\n";
    } else {
      print "statusCode   : ".$response->{'statusCode'}."\n";
      print "statusMessage: ".$response->{'statusMessage'}."\n";
    }
  }
  
=head3 ConvergedMessage

Fully working sample (put WebSmsComToolkit.pm somewhere where perl can find it or set $path_to_toolkit):

  #!/usr/bin/perl
  my $path_to_toolkit = ''; #'<path to WebSmsComToolkit.pm>'
  unshift(@INC, $path_to_toolkit) if ($path_to_toolkit ne '');
  
  use WebSmsComToolkit;
  use Encode;

  my ($sms_client, $message, $response);

  # --- Modify these values to your needs ---
  my $gateway_url                = 'https://api.websms.com';
  my $username                   = 'your username';
  my $password                   = 'your password';
  my $recipients                 = ['4367612345678'];
  my $utf8_message_content       = decode("utf-8","Hallo Welt! Eurozeichen: \xE2\x82\xAC");
  my $max_sms_per_message        = 1;
  my $additional_push_parameters = { 'key' => 'value' };
  my $test                 = 0; # // 1: do not send sms but test interface, 0: send sms

  # --- 1. create client, 2. create message, 3. send message --- 
  $sms_client = WebSmsComToolkit::Client->new($gateway_url, $username, $password);
  $sms_client->verbose(1);

  $message = WebSmsComToolkit::ConvergedMessage->new($recipients, $utf8_message_content, $additional_push_parameters);

  $response = $sms_client->send($message, $max_sms_per_message, $test);

  if (exists($response->{'error'})) {
    
    # HTTP or server error
    print $response->{'http_status'}."\n".$response->{'error_content'};
        
  } else {
  
    # read return values from API
    if ($response->{'statusCode'} == 2000 || $response->{'statusCode'} == 2001) {
      print "SMS sent, transferId: ".$response->{'transferId'}."\n";
    } else {
      print "statusCode   : ".$response->{'statusCode'}."\n";
      print "statusMessage: ".$response->{'statusMessage'}."\n";
    }
  }

=head2 LIMITATIONS

Yet unknown....

=head1 SECURITY CONSIDERATIONS

uses SSL endpoint


=head1 THREADS

not tested.


=head1 BUGS

They usually fly around in places where you never expect them.

Feel free to report them, we happily fixed them ever after.

=cut

=head1 SEE ALSO

In case you have any problems using this package, 
you can easily omit it and send the requests yourself,
see following full example without error handling:
Take a look at our API specification at https://api.websms.com

    #!/usr/bin/perl
    use strict;
    #use utf8;
    use Encode;
    use LWP::UserAgent;
    use JSON::XS qw(encode_json decode_json);
    use Data::Dumper;
    
    my $sms_client = LWP::UserAgent->new;
       $sms_client->timeout(10); 
    
    my $url      = "https://api.websms.com";
    my $username = "your_username";
    my $password = "your_password";
      
    my $header = HTTP::Headers->new(Content_Type => 'application/json; charset=UTF-8');
    
    $header->authorization_basic($username, $password);
      
    # Text Message  
    my $endpoint   = '/json/smsmessaging/text';
    my $Message    = {
        'test'                    => JSON::XS::false, # or JSON::XS::true
        'recipientAddressList'    => [4367612345678],
        #  messageContent without real utf-8 encoding can also be 
        #  described with unicode escaped characters "\x{000020AC}urozeichen"
        'messageContent'          => decode('utf-8',"\xE2\x82\xACurozeichen"), 
        "sendAsFlashSms"          => JSON::XS::false, 
        "notificationCallbackUrl" => "http://your_domain/endpoint", 
        "clientMessageId"         => "myMessageId123", 
        "priority"                => 1, 
    
      };
    
    ## Binary Message
    #  my $endpoint   = '/json/smsmessaging/binary';
    #  my $Message    = {
    #    'test'                    => JSON::XS::false, # or JSON::XS::true
    #    'recipientAddressList'    => [4367612345678],
    #    'messageContent'          => ['BQAD/AIBWnVzYW1tZW4=','BQAD/AICZ2Vmw7xndC4='],
    #    "userDataHeaderPresent"   => JSON::XS::true,  #binary
    #    #"senderAddress"          => "4367600000001", 
    #    #"senderAddressType"      => "international", 
    #    "sendAsFlashSms"          => JSON::XS::true, 
    #    "notificationCallbackUrl" => "http://your_domain/endpoint", 
    #    "clientMessageId"         => "myMessageId123", 
    #    "priority"                => 1, 
    #  };
      
    $url        .= $endpoint;
    my $content  = encode_json($Message);
    my $request  = HTTP::Request->new('POST', $url, $header, $content);
    my $response = $sms_client->request($request); 
      
    print "Request:\n----\n"  . $request->as_string() . "\n----\n";
    print "Response:\n----\n" . $response->as_string(). "\n----\n";
      
    my $answer         = decode_json($response->content);
      
    my $status_code    = $answer->{'statusCode'};
    my $status_message = $answer->{'statusMessage'};
    my $transfer_id    = $answer->{'transferId'};
      
    if ($response->is_success) {
      
      print "Request was sucessful.\n";
      print "statusCode   : $status_code\n";
      print "statsMessage : $status_message\n";
      print "TransferId   : $transfer_id\n";
    
    } elsif ($response->is_error) {
      print "HTTP error code   : ".$response->code."\n";
    }



=head1 AUTHOR

Gerd Reifenauer <gerd.reifenauer@websms.com>

http://websms.com/

=cut

1;
