%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU Lesser General Public License
%% as published by the Free Software Foundation; either version
%% 3 of the License, or (at your option) any later version.

-module(scg_ipoe).

-behavior(gen_server).

-compile([{parse_transform, do},
	  {parse_transform, cut}]).

%% API
-export([validate_options/1, context_new/3, lookup/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include_lib("ergw_aaa/include/diameter_3gpp_ts29_212.hrl").
-include("include/ergw.hrl").

-import(ergw_aaa_session, [to_session/1]).

-define(DIAMETER_APP_ID_GX, diameter_3gpp_ts29_212:id()).

%%====================================================================
%% API
%%====================================================================

validate_options(Options) ->
    lager:debug("SCG IPoE Options: ~p", [Options]),
    gtp_context:validate_options(fun validate_option/2, Options, []).

validate_option(protocol, ipoe) ->
    ipoe;
validate_option(Opt, Value) ->
    gtp_context:validate_option(Opt, Value).

context_new(PortName, MSv4, MSv6) ->
    {ok, ?MODULE, InterfaceOpts} = ergw:handler(PortName, ipoe),
    gen_server:start_link(?MODULE, [PortName, MSv4, MSv6, InterfaceOpts], [{debug, [trace, log]}]).

lookup(PortName, {{_,_,_,_},_} = MSv4) ->
    TEID = ms2int(MSv4),
    gtp_context_reg:lookup_teid(PortName, 'gtp-c', TEID).

%% ===================================================================
%% gen_server callbacks
%% ===================================================================

init([PortName, MSv4, MSv6, #{data_paths := DPs, rules := Rules, aaa := AAAOpts}]) ->
    process_flag(trap_exit, true),

    Version = ipoe,
    CntlPort = #gtp_port{name = PortName, type = ipoe},
    DataPort = gtp_socket_reg:lookup(hd(DPs)),
    TEID = ms2int(MSv4),
    IP = ms2ip(MSv4),

    lager:info("DataPort: ~p", [DataPort]),

    Context = #context{
		 version            = Version,
		 control_interface  = ?MODULE,
		 control_port       = CntlPort,
		 local_control_tei  = TEID,
		 remote_control_ip  = IP,
		 remote_control_tei = TEID,
		 data_port          = DataPort,
		 local_data_tei     = TEID,
		 remote_data_ip     = IP,
		 remote_data_tei    = TEID,
		 ms_v4              = MSv4,
		 ms_v6              = MSv6
		},

    State = #{
      context   => Context,
      version   => Version,
      interface => ?MODULE,
      rules     => Rules,
      aaa_opts  => AAAOpts},

    SessionOpts = [{'Accouting-Update-Fun', fun accounting_update/2},
		   {'Interim-Accounting', undefined}],
    {ok, Session} = ergw_aaa_session_sup:new_session(self(), to_session(SessionOpts)),
    gen_server:cast(self(), start),
    {ok, State#{'Session' => Session}}.

handle_call(get_accounting, _From, #{context := Context} = State) ->
    Counter = get_accounting(Context),
    {reply, Counter, State};

handle_call(terminate_context, _From, State) ->
    close_pdn_context(State),
    {stop, normal, ok, State};

handle_call({activate_pcc_rules, UL, DL}, _From, #{context := Context} = State) ->
    gtp_dp:activate_pcc_rules(Context, UL, DL),
    {reply, ok, State}.

handle_cast(start, #{context := ContextPending, aaa_opts := AAAopts,
		    'Session' := Session} = State0) ->

    gtp_context:terminate_colliding_context(ContextPending),

    SessionOpts = init_session(ContextPending, AAAopts),
    %% SessionOpts = init_session_qos(ReqQoSProfile, SessionOpts1),

    authenticate(ContextPending, Session, SessionOpts),

    ActiveSessionOpts0 = ergw_aaa_session:get(Session),
    lager:info("ActiveSessionOpts: ~p", [ActiveSessionOpts0]),

    {ActiveSessionOpts, State} = diameter_gx(ActiveSessionOpts0, ContextPending, State0),

    gtp_context:remote_context_register_new(ContextPending),
    Context = dp_create_pdp_context(ContextPending),
    gtp_context:apply_session_policy(ActiveSessionOpts, Context, State),

    ergw_aaa_session:start(Session, #{}),

    {noreply, State#{context => Context}};

handle_cast({packet_in, _GtpPort, _IP, _Port, _Msg}, State) ->
    lager:warning("packet_in not handled (yet): ~p", [_Msg]),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Helper functions
%%%===================================================================

ms2ip({{_,_,_,_} = IP, _}) ->
    IP;
ms2ip({_,_,_,_} = IP) ->
    IP.

ms2int(MS) ->
    IP = ms2ip(MS),
    <<Int:32>> = gtp_c_lib:ip2bin(IP),
    Int.

authenticate(Context, Session, SessionOpts) ->
    lager:info("SessionOpts: ~p", [SessionOpts]),

    case ergw_aaa_session:authenticate(Session, SessionOpts) of
	success ->
	    lager:info("AuthResult: success"),
	    ok;

	Other ->
	    lager:info("AuthResult: ~p", [Other]),

	    throw(#ctx_err{level = ?FATAL,
			   reply = user_authentication_failed,
			   context = Context})
    end.

get_accounting(Context) ->
    case gtp_dp:get_accounting(Context) of
	{ok, #counter{rx = {RcvdBytes, RcvdPkts},
		      tx = {SendBytes, SendPkts}}} ->
	    Acc = [{'InPackets',  RcvdPkts},
		   {'OutPackets', SendPkts},
		   {'InOctets',   RcvdBytes},
		   {'OutOctets',  SendBytes}],
	    to_session(Acc);
	_Other ->
	    lager:warning("got unexpected accounting: ~p", [_Other]),
	    to_session([])
    end.

accounting_update(GTP, SessionOpts) ->
    lager:debug("accounting_update(~p, ~p)", [GTP, SessionOpts]),
    Counter = gen_server:call(GTP, get_accounting),
    ergw_aaa_session:merge(SessionOpts, Counter).

close_pdn_context(#{context := Context, 'Session' := Session}) ->
    SessionOpts = get_accounting(Context),
    lager:debug("Accounting Opts: ~p", [SessionOpts]),
    ergw_aaa_session:stop(Session, SessionOpts),

    dp_delete_pdp_context(Context).

init_session_ipv4(#context{ms_v4 = {MSv4, _}}, Session) ->
    Session#{'Framed-IP-Address' => MSv4};
init_session_ipv4(_, Session) ->
    Session.

init_session_ipv6(#context{ms_v6 = {IPv6, 128}}, Session) ->
    Session#{'Framed-Interface-Id' => IPv6};
init_session_ipv6(#context{ms_v6 = {_, _} = MSv6}, Session) ->
    Session#{'Framed-IPv6-Prefix' => MSv6};
init_session_ipv6(_, Session) ->
    Session.

init_session(Context, #{'Username' := #{default := Username},
			'Password' := #{default := Password}}) ->
    Session0 =
	#{'Username'		=> Username,
	  'Password'		=> Password,
	  'Service-Type'	=> 'Framed-User',
	  'Framed-Protocol'	=> 'PPP',
	  'PCC-Groups'		=> [<<"default">>]
	 },
    Session1 = init_session_ipv4(Context, Session0),
    init_session_ipv6(Context, Session1).

dp_args(#context{ms_v4 = {MSv4,_}}) ->
    MSv4;
dp_args(_) ->
    undefined.

dp_create_pdp_context(Context) ->
    Args = dp_args(Context),
    gtp_dp:create_pdp_context(Context, Args).

dp_delete_pdp_context(Context) ->
    Args = dp_args(Context),
    gtp_dp:delete_pdp_context(Context, Args).

%%%===================================================================
%%% DIAMETER functions
%%%===================================================================

gx_request(Type, #{sid := SId, cc_req := Req} = State0) ->
    Avps = #{'Session-Id'          => SId,
	     'Auth-Application-Id' => ?DIAMETER_APP_ID_GX,
	     'CC-Request-Type'     => Type,
	     'CC-Request-Number'   => Req},
    State = State0#{cc_req => Req + 1},
    {Avps, State}.

diameter_gx(ActiveSessionOpts, Context, State0) ->
    State1 = State0#{
	       sid    => diameter:session_id("erGW"),
	       cc_req => 0
	      },
    {Avps0, State} = gx_request(?'DIAMETER_GX_CC-REQUEST-TYPE_INITIAL_REQUEST', State1),
    Avps1 = gx_context(Context, Avps0),
    Avps2 = gx_session(ActiveSessionOpts, Avps1),
    lager:warning("Avps: ~p", [Avps2]),

    {ActiveSessionOpts, State}.

gx_context(_Context, Avps) ->
    Avps.

gx_session(_K, _V, Avps) ->
    Avps.

gx_session(Session, Avps) ->
    maps:fold(fun gx_session/3, Avps, Session).

