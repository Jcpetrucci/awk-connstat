awk-connstat
============

Portable / easily readable output of Check Point connections table (fw tab -t connections).

##### Sample output
```
Expert@Firewall-1# fw tab -t connections -u -v | ./awk-connstat.awk
           SRC IP    SRC PORT           DST IP    DST PORT  IPP   DIR        STATE  REMATCH  TIMEOUT     RULE
-------------------------------------------------------------------------------------------------------------------------------
      10.13.8.115       43867        10.13.0.9         389    6   OUT  ESTABLISHED    YES       3503  IMPLIED
      10.13.8.115       59679      10.13.8.119         257    6   OUT  ESTABLISHED    YES       3575  IMPLIED
      10.13.8.115       59452        10.13.0.9       49154    6   OUT  ESTABLISHED    YES       3598  IMPLIED
      10.13.8.115         123        10.13.0.9         123   17   OUT     SYN/NONE    YES         32  IMPLIED
      10.13.8.119       37227      10.13.8.115       18192    6    IN  ESTABLISHED    YES       3540  IMPLIED
      10.13.8.115       45688      10.13.7.119          53   17   OUT     SYN/NONE    YES         37  IMPLIED
      10.13.8.115       39115    216.200.241.8         443    6   OUT  ESTABLISHED    YES       3597  IMPLIED
      10.13.7.119       39252      10.13.8.115          22    6    IN  ESTABLISHED     NO       3599        2
      10.13.8.119       36950      10.13.8.115       18192    6    IN  ESTABLISHED    YES       3494  IMPLIED
-------------------------------------------------------------------------------------------------------------------------------
    Concurrent: 9         Limit: Automatic
-------------------------------------------------------------------------------------------------------------------------------
           Top Source IPs       Top Destination IPs              Top Services         Connection States
        10.13.8.115 ( 6 )        10.13.8.115 ( 3 )              18192 ( 2 )      ESTABLISHED ( 77% )
        10.13.8.119 ( 2 )          10.13.0.9 ( 3 )                 53 ( 1 )         SYN/NONE ( 22% )
        10.13.7.119 ( 1 )      216.200.241.8 ( 1 )              49154 ( 1 )                      ---
                      ---        10.13.8.119 ( 1 )                443 ( 1 )                      ---
                      ---        10.13.7.119 ( 1 )                389 ( 1 )                      ---
                      ---                      ---                257 ( 1 )                      ---
                      ---                      ---                 22 ( 1 )                      ---
                      ---                      ---                123 ( 1 )                      ---
                      ---                      ---                      ---                      ---
                      ---                      ---                      ---                      ---
-------------------------------------------------------------------------------------------------------------------------------
      Worker Distribution                Top Rules
                fw_1: 55%            IMPLIED ( 8 )
                fw_0: 44%                  2 ( 1 )
                      ---                      ---
                      ---                      ---
                      ---                      ---
                      ---                      ---
                      ---                      ---
                      ---                      ---
                      ---                      ---
                      ---                      ---
Expert@Firewall-1#
```
