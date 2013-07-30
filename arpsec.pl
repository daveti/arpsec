%
% System configuration -- configuration for the ARP prover

% Security parameter (epochs a system should be considered in a good state)
security_parmeter(5).

not(P) :- (call(P) -> fail ; true).

% Dyanmic function definitions
:- dynamic(trust_statement/2).
:- dynamic(binding_statement/4).

%
% Starter data

% Systems (S) whose values has been vetted by trust_statement at time (T)
% trust_statement(S,#T) 
trust_statement(sys1,11).
trust_statement(sys2,10).

% Bindinbgs Systems (S) identify network address M is on media address N at time (T)
% trust_statement(S,M,N,#T) 
binding_statement(sys1,net130_203_22_1,media00_22_55_95_63_80,11).
binding_statement(sys2,net130_203_22_30,media00_17_f2_d3_62_6f,11).
binding_statement(sys2,net130_203_22_1,mediaaa_bb_cc_dd_ee_ff,13).
binding_statement(sys3,net130_203_22_114,mediaa8_20_66_05_81_2f,11).
binding_statement(sys4,net130_203_22_128,media00_03_ba_2f_cd_f5,11).
binding_statement(sys5,net130_203_22_144,media00_1b_21_20_b3_ff,11).
binding_statement(sys6,net130_203_22_152,media00_3_ba_16_b0_5e,11).
binding_statement(sys7,net169_254_51_253,mediae8_9d_87_53_2f_27,11).
binding_statement(sys8,net169_254_170_251,media00_11_24_db_4d_fa,11).

%
% Definition of rules

% Defines the period at which a particular system (S) is trusted at time (T)
% trusted(S,#T)
trusted(X,Y) :- 
	security_parmeter(K),	% (using the security parameter K)
	trust_statement(X,Z), 	% A trust statement for system X was made at time Z
	Y#>=#Z, 				% time Z (of the trust statement) was before Y (now)
	Y#<#Z+K.				% time Z was no more than K epochs before Y (now)

% Defines the correct binding between network address N and media address M, at time T, if any
% binding (X,Y,T)
valid_binding(X,Y,T) :-
	valid_statement(X,Y,T,V),	% There exists a valid binding statement
	not(superceded(X,T,V)).		% That has not been superceded

% Defines if the binding for network address X, superceded at time T issued at time V 
% valid_binding_statement_at(N,M,T,V)
superceded(X,T,V) :-
	valid_statement(X,_,T,V2),	% There exists some other statement at V2
	V2#>#V,						% after the binding statement at V
	T#>=#V2.					% but before the current time T

% Defines if the binding statement X,Y at time V valid at time
% valid_binding_statement_at(N,M,T,V)
valid_statement(X,Y,T,V) :-
	binding_statement(S,X,Y,V),	% A binding statement was made by system S at time V
	trusted(S,T), 				% S is trusted at time T
	trusted(S,V), 				% S is trusted at time V
	security_parmeter(K),		% (using the security parameter K)
	T#>=#V,						% T (now) is at or after the statement was made (V)
	T#<#V+K.					% time V was no more than K epochs before T

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% HISTORICAL STUFF

binding(X,Y,T) :- 
	good_binding(X,Y,T),	% a valid binding
	not(invalid(X,Y,Y)).	% another valid binding 

% Defines if the binding was valid at a given time
% valid_binding_statement(S,N,M,T)
good_binding(X,Y,T) :-
	valid_binding_statement(S,X,Y,V),	% A binding statement was made by system S1 at time V1
	security_parmeter(K),				% (using the security parameter K)
	trusted(S,T), 						% S is trusted at time T
	T#>=#V,								% T (now) is after the statement was made (V)
	T#<#V+K.							% time V was no more than K epochs before T (now)
	
invalid(X,Y,T) :-
	valid_binding_statement(_,X,Y1,V1),
	Y\==Y1,
	T#=<#V1.

% Defines if the binding statement at time T was from a system trusted at time T valid at time V
% valid_binding_statement_at(S,N,M,T,V)
valid_binding_statement_at(S,X,Y,T) :- 
	valid_binding_statement(S,X,Y,T),
	security_parmeter(K),				% (using the security parameter K)
	trusted(S,V), 						% S is trusted at time V
	T#>=#V,								% T (now) is after the statement was made (V)
	T#<#V+K.							% 

% Defines if the binding statement at time T was from a system trusted at time T
% valid_binding_statement(S,N,M,T)
valid_binding_statement(S,X,Y,T) :- 
	binding_statement(S,X,Y,T),		% X,Y binding was made by system S at time T
	trusted(S,T). 					% S is trusted at time T
