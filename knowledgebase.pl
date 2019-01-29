
%  NAME: ARYAN MEHRA  2017A7PS0077P
%        AYUSH JAIN   2017A7PS0093P

%This file is a prolog source code for the knowledge base that can be
% customised indeppendent of the firewall engine.



% ************************ ADAPTER  **************************

% The following is our definition to handle the range
% aspect of various inputs. This function will be used again and again
% later too.
range(Low, High, Var) :- between(Low, High, Var).

%The following statement handles the case when
% the input for the adapter is 'any'
adapterAllow(X) :- (X = "any" ->true; false).

% The following statement handles the case when
% the input for the adapter is a range of letters
% which is currently set from A to H

adapterAllow(X):-
    char_code("A",Low),
    char_code("H",High),
    char_code(X, Var),
    range(Low, High, Var).

% The following statement handles the case when specific values are
% allowed like 'A' and 'B' for the given case
adapterAllow(X) :- ((X="A";X="B")->true; false).





% ********************** ETHERNET PROTOCOLS *********************

% As a sample we use PPP over Ethernet PPPoE Discovery Stage
% (34915), Session Stage (33915) and IBM SNA Service on Ethernet
% (32981) as allowed network types in their decimal representation

etherproto(X):- ((X=34915;X=34916;X=32981) ->true;false).


% As an example of allowing range we have used "Normal Range" for
% Ethernet VLANs from 2 to 1001 chanels


ethervid(Y):- range(2,1001,Y).

% Here we take a specific value of VLAN ID number without range
ethervid(Y):- (Y=8888 ->true;false).




% ********************* IPv4 protocol  ************************

% This function coverts IP address to integer values so that we can
% compare them later.
dotted_IP_address_to_int([],[],0).
dotted_IP_address_to_int([Inhead|Tail],[Expval|Tail1], Sum):-
    dotted_IP_address_to_int(Tail ,Tail1, Sum1),
    atom_number(Inhead, Remtail),
    atom_number(Expval, Exp1),
    Mult is 256**Exp1,
    Sum is (Sum1 + (Remtail * Mult)).

% This function checks the range for the IP Address between certain
% limts that can be set by the user.
ip_range(K):- split_string(K,".","",SplitListIP),
    split_string("192.168.10.0",".","",SplitLowerIP),
    split_string("192.168.10.255",".","",SplitUpperIP),
    dotted_IP_address_to_int(SplitListIP,["3", "2", "1", "0"],ListIPInt),
    dotted_IP_address_to_int(SplitLowerIP,["3", "2", "1", "0"],LowerIPInt),
    dotted_IP_address_to_int(SplitUpperIP,["3", "2", "1", "0"],UpperIPInt),
    range(LowerIPInt,UpperIPInt,ListIPInt).

% The following code blocks specific IP address
% by returning a false for them in case they are source
ipv4src(X):-
    ((X="198.2.18.64" ; X="198.4.33.12") -> false;true),
    (ip_range(X) -> false;true).

% The following code blocks specific IP address
% by returning a false for them in case they are destination
ipv4dst(Y):-
    ((Y="173.6.2.33" ; Y="45.7.43.12") -> false;true),
    (ip_range(Y) -> false;true).

% The following clause blocks a specified protocol and currently the
% option for not allowing is set for TCP
ipproto(Z):-  (Z="TCP" -> false;true).




% ******************** TCP/UDP Port protocol ******************

% This is the normal range function that will help us check whether the
% port is in the desired range or not. This has been implemented before
% already
% range(Low, High, Var) :- between(Low, High, Var).


% This function enables us to check a range of port values. These can be
% set to 0 in place of 2 and 100 if only single values need to be parsed
tcpudprangecheck(X):- range(2,100,X).

% This enables single values to be checked and this can be customised by
% the user. This can be set to 0 if range of values is being parsed
% already
tcpudpsingletoncheck(X):- (X=888 ->true;false).

% The following predicate checks the range and enables the engine to run
% independent of the values of allowed range provided here. This
% predicate will aloow both range and singleton functionality as it is
% OR of both of them given above
tcpudpportallow(X):- (range(0,65535,X),tcpudprangecheck(X));tcpudpsingletoncheck(X).


%************************ ICMP Protocols *******************

% The value for traceroute type protocol is 30. We have taken that as an
% example.
icmp_proto_type(X):- (X=30 ->true;false).
%protocol is unreachable wherein the code is 2.
icmp_message_code(X):- (X = 2->true;false).

icmp_check(X):-icmp_proto_type(X);icmp_message_code(X).


%*************************  IMCP Protocols *****************

















