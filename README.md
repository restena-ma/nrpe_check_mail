# nrpe_check_urgentmail
Nagios NRPE check which alerts if mails are found in a specified folder

==== How it works ====

__step 1__

You have to copy the email which should raise an alert in the folder /var/lib/nrpe_check_urgentmail/incoming.

__step 2__

When Nagios and/or Icinga call the plugin, it looks in the incoming folder. if an email is found, the CRITICAL status is returned with some information about the email.

In order to ensure that __all__ the monitoring servers record the alert, a small json file is stored by the plugin (/var/lib/nrpe_check_urgentmail/status.json). The file contains a record of all emails in the incoming folder and of the servers having notified the file presence.

The CRITICAL status is maintained during 5 minutes. 

The plugin deletes the email 10 minutes after the first server have seen it in order to keep the incoming folder clean in the long term.
