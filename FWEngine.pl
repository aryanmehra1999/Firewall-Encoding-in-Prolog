

%  NAME: ARYAN MEHRA  2017A7PS0077P
%        AYUSH JAIN   2017A7PS0093P


:-[knowledgebase].

etherprotoFW(T):- atom_number(T,Q), etherproto(Q).
ethervidFW(R):- atom_number(R,M),ethervid(M).
tcpudpFW(S):- atom_number(S,J),tcpudpportallow(J).
icmpFW(W):- atom_number(W,K),icmp_check(K).

% This is the engine statement that calls the reject and drop functions
% It also finally returns true and prints "Accept" if all conditions are
% met successfully

firewall(A):- split_string(A," ","",B),
    B=[Adapt|T1],T1=[Etherpro|T2],
    T2=[Ethervlan|T3],
    T3=[Srcadd|T4],
    T4=[Dstadd|T5],
    T5=[Proto|T6],
    T6=[Port|T7],
    T7=[Icmp|_],
    (reject1(Adapt,Etherpro,Ethervlan,Srcadd,Proto,Icmp),
     drop1(Adapt,Etherpro,Ethervlan,Srcadd,Proto,Icmp,Port,Dstadd)),
    adapterAllow(Adapt),
    etherprotoFW(Etherpro),
    ethervidFW(Ethervlan),
    ipv4src(Srcadd),
    ipv4dst(Dstadd),
    ipproto(Proto),
    tcpudpFW(Port),
    icmpFW(Icmp),
    write('Accepted').

% This clause handles the rejection messages according to chosen
% conditions

reject1(X,Y,Z,P,Q,R):- (not(adapterAllow(X))->write("Reject: Adapter not Supported!"),nl;true),
    (not(etherprotoFW(Y))->write("Reject: Ethernet Protocol number/code is wrong!"),nl;true),
    (not(ethervidFW(Z))->write('Reject: Ethernet VLAN ID is wrong!'),nl;true),
    (not(ipv4src(P))->write('Reject: IP source address not allowed!'),nl;true),
    (not(ipproto(Q))->write('Reject: IP Protocol is not allowed !'),nl;true),
    (not(icmpFW(R))->write('Reject: ICMP Message code or protocol is denied !'),nl;true);true.

% This clause handles the drop conditions without any specific error
% message.

drop1(A,B,C,D,E,F,X,Y):-
    adapterAllow(A),
    etherprotoFW(B),
    ethervidFW(C),
    ipv4src(D),
    ipproto(E),
    icmpFW(F),
    ((not(tcpudpFW(X))->write('Packet Dropped '),nl);
    (not(ipv4dst(Y))->write('Packet Dropped '),nl));true.

