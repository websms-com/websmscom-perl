
 
                  W E B S M S . C O M   P E R L   T O O L K I T 


What is it?
-------

  A lightweight Perl-client-library for using websms.com SMS services.
  Reduces the complexity of network-communication between client and SMS gateway, 
  to help business-customer save time and money for focusing on their business logic.

# Installation

  The following requirements exist for running the Perl Toolkit:

   *  tested with Perl Version 5.8.8

Dependencies
------------   
   *  LWP::UserAgent (2.033 or higher)
   *  JSON::XS       (2.25 or higher)
   *  Carp           (1.04 or higher)

Installation Instructions
-------------------------

  Add WebsmsComToolkit.pm to a directory of your include path / package path to access the classes and 
  methods for sending text and binary SMS.
  
  In case you don't want to use this package but communicate with the API on your own, see the fully working
  sample script in the package documentation.
  
Sample Scripts
-------------------------
  
  *  [send_sms.pl]()              (how to use WebsmsComToolkit.pm)
  *  [send_sms_quick_sample.pl]()  (how to do it without WebsmsComToolkit.pm)
  *  See POD of WebsmsComToolkit.pm

  
The Latest Version
-------
  
   * Version 1.1.0: Converged Messaging support
   * Version 1.0.0: Basic text- and binary-sms-sending.


Documentation
-------
  The documentation available as of the date of this release is included 
  in send_sms.pl and WebsmsComToolkit.html.
  

Contact
-------
  For any further questions into detail the contact-email is developer@websms.com
