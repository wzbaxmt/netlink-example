# netlink-example
kernel module(mynetlink.ko) communicate with the user-mode application(mynetlink), each process has two threads(send/recv);

内核态与用户态交互信息，两边主动收发。


Use step:

make;

insmod mynetlink.ko;

./mynetlink;

ps:
use cmd dmesg see the kernel print
