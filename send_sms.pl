#!/usr/bin/perl
#unshift(@INC, '<path to WebSmsComToolkit.pm>');

use WebSmsComToolkit;
use Encode;

my ($sms_client, $message, $response);

# --- Modify these values to your needs ---
my $gateway_url          = 'https://api.websms.com';
my $username             = 'your username';
my $password             = 'your password';
my $recipients           = ['4367612345678'];
my $utf8_message_content = decode("utf-8","Hallo Welt! Eurozeichen: \xE2\x82\xAC");# or "Eurozeichen: \x{000020AC}"
my $max_sms_per_message  = 1;
my $test                 = 0; # // 1: do not send sms but test interface, 0: send sms

# --- 1. create client, 2. create message, 3. send message --- 
$sms_client = WebSmsComToolkit::Client->new($gateway_url, $username, $password);
$sms_client->verbose(1);

$message = WebSmsComToolkit::TextMessage->new($recipients, $utf8_message_content);
#$message = binary_sample_message();

$response = $sms_client->send($message, $max_sms_per_message, $test) or die "LWP Connection error.";

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

# --- end ---

sub binary_sample_message {
  
  # base64 encoded binary containing UDH (2 concatenated sms)
  my $message_content          = ['BQAD/AIBWnVzYW1tZW4=','BQAD/AICZ2Vmw7xndC4=']; # "Zusammen","gefügt."
  my $user_data_header_present = 1;
  
  $max_sms_per_message = undef;
  
  my $binary_message = WebSmsComToolkit::BinaryMessage->new($recipients, $message_content, $user_data_header_present);
  
  return $binary_message;
}

#-----------------------------------------
# Info on message content:
# -------------------------
# Decode perl internal string message content to perl flagged utf-8 encoded characters (Encode::decode)
# which is roughly the same as using utf8 source code and writing utf8 character strings.
#
# So:
#
#   my $utf8_message_content = decode("utf-8","Hallo Welt! Eurozeichen: \xE2\x82\xAC");
# 
# is like using utf-8 source code encoding and writing:
#
#   use utf8;
#   $utf8_message_content = "€urozeichen"  # where the euro sign is 3 bytes 
#
# is like using latin1 encoding for source and writing:
#
#   my $unicode_message_content = "Hallo Welt! Eurozeichen: \x{000020AC}"); # 4bytes
#
