# Highly Dependable Systems Course Project 2016
## File server with integrity guarantees, using smartcard authentication and with intrusion-tolerant replication

Configure testing libraries (IntelliJ - JUnit): https://www.jetbrains.com/help/idea/2016.1/configuring-testing-libraries.html?origin=old_help

Run: minimum 4 instances of Block Server, for f = 1;
(N = 3f + 1; Q = 2f + 1)

To run on PC labs using CC:
* add this argument: -Djava.library.path=/usr/local/lib64/pteid_jni/
* change in FS_Library, methods **initPublicKey** and **signData** (just comment and uncomment lines)