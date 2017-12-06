#!/usr/bin/perl
use strict;
#use utf8;
use Encode;
use LWP::UserAgent;
use JSON::XS qw(encode_json decode_json);
use Data::Dumper;

my $sms_client = LWP::UserAgent->new;
   $sms_client->timeout(10); 

my $url    = "https://api.websms.com";
  
my $header = HTTP::Headers->new(Content_Type => 'application/json; charset=utf-8');

$header->authorization_basic('your username', 'your password');

# Text Message  
my $endpoint   = '/json/smsmessaging/text';
my $Message    = {
    'test'                    => JSON::XS::false, # or JSON::XS::true
    'recipientAddressList'    => [436761234567],
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
#    'test'                    => JSON::XS::true, # or JSON::XS::false
#    'recipientAddressList'    => [436761234567],
#    'messageContent'          => ["BQAD/AMAU2VnbWVudDEs","BQAD/AMBU2VnbWVudDIs","BQAD/AMCU2VnbWVudDMu"],
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
  
print "Request:\n----\n".$request->as_string()."\n----\n";
print "Response:\n----\n".$response->as_string()."\n----\n";
  
my $answer         = decode_json($response->content);
  
my $status_code    = $answer->{'statusCode'};
my $status_message = $answer->{'statusMessage'};
my $transfer_id    = $answer->{'transferId'};
  
if ($response->is_success) {
  
  # request was successful
  print "Request sucessful.\n";
  print "Code           : $status_code\n";
  print "CodeDescription: $status_message\n";
  print "TransferId     : $transfer_id\n";

} elsif ($response->is_error) {
  print "HTTP error code   : ".$response->code."\n";
}
