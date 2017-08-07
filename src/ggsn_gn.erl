%% Copyright 2015, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(ggsn_gn).

-behaviour(gtp_api).

-compile({parse_transform, cut}).

-export([validate_options/1, init/2, request_spec/3,
	 handle_request/4, handle_response/4,
	 handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2]).

%% shared API's
-export([init_session/3, init_session_from_gtp_req/3]).

-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").
-include_lib("ergw_aaa/include/diameter_3gpp_ts29_212.hrl").
-include("include/ergw.hrl").
-include("include/3gpp.hrl").

-import(ergw_aaa_session, [to_session/1]).

-define(T3, 10 * 1000).
-define(N3, 5).

-define(DIAMETER_APP_ID_GX, diameter_3gpp_ts29_212:id()).

%%====================================================================
%% API
%%====================================================================

-define('Cause',					{cause, 0}).
-define('IMSI',						{international_mobile_subscriber_identity, 0}).
-define('Recovery',					{recovery, 0}).
-define('Tunnel Endpoint Identifier Data I',		{tunnel_endpoint_identifier_data_i, 0}).
-define('Tunnel Endpoint Identifier Control Plane',	{tunnel_endpoint_identifier_control_plane, 0}).
-define('NSAPI',					{nsapi, 0}).
-define('End User Address',				{end_user_address, 0}).
-define('Access Point Name',				{access_point_name, 0}).
-define('Protocol Configuration Options',		{protocol_configuration_options, 0}).
-define('SGSN Address for signalling',			{gsn_address, 0}).
-define('SGSN Address for user traffic',		{gsn_address, 1}).
-define('MSISDN',					{ms_international_pstn_isdn_number, 0}).
-define('Quality of Service Profile',			{quality_of_service_profile, 0}).
-define('IMEI',						{imei, 0}).

-define(CAUSE_OK(Cause), (Cause =:= request_accepted orelse
			  Cause =:= new_pdp_type_due_to_network_preference orelse
			  Cause =:= new_pdp_type_due_to_single_address_bearer_only)).

request_spec(v1, _Type, Cause)
  when Cause /= undefined andalso not ?CAUSE_OK(Cause) ->
    [];

request_spec(v1, create_pdp_context_request, _) ->
    [{?'Tunnel Endpoint Identifier Data I',		mandatory},
     {?'NSAPI',						mandatory},
     {?'SGSN Address for signalling',			mandatory},
     {?'SGSN Address for user traffic',			mandatory},
     {?'Quality of Service Profile',			mandatory}];

request_spec(v1, update_pdp_context_request, _) ->
    [{?'Tunnel Endpoint Identifier Data I',		mandatory},
     {?'NSAPI',						mandatory},
     {?'SGSN Address for signalling',			mandatory},
     {?'SGSN Address for user traffic',			mandatory},
     {?'Quality of Service Profile',			mandatory}];

request_spec(v1, _, _) ->
    [].

validate_options(Options) ->
    lager:debug("GGSN Gn/Gp Options: ~p", [Options]),
    gtp_context:validate_options(fun validate_option/2, Options, []).

validate_option(Opt, Value) ->
    gtp_context:validate_option(Opt, Value).

init(_Opts, State) ->
    SessionOpts = [{'Accouting-Update-Fun', fun accounting_update/2}],
    {ok, Session} = ergw_aaa_session_sup:new_session(self(), to_session(SessionOpts)),
    {ok, State#{'Session' => Session}}.

handle_call(get_accounting, _From, #{context := Context} = State) ->
    Counter = get_accounting(Context),
    {reply, Counter, State};

handle_call(delete_context, From, #{context := Context} = State) ->
    delete_context(From, Context),
    {noreply, State};

handle_call(terminate_context, _From, #{context := Context} = State) ->
    dp_delete_pdp_context(Context),
    pdp_release_ip(Context),
    {stop, normal, ok, State};

handle_call({activate_pcc_rules, UL, DL}, _From, #{context := Context} = State) ->
    gtp_dp:activate_pcc_rules(Context, UL, DL),
    {reply, ok, State};

handle_call({path_restart, Path}, _From,
	    #{context := #context{path = Path}} = State) ->
    close_pdp_context(State),
    {stop, normal, ok, State};
handle_call({path_restart, _Path}, _From, State) ->
    {reply, ok, State}.

handle_cast({packet_in, _GtpPort, _IP, _Port, #gtp{type = error_indication}}, State) ->
    close_pdp_context(State),
    {stop, normal, State};

handle_cast({packet_in, _GtpPort, _IP, _Port, _Msg}, State) ->
    lager:warning("packet_in not handled (yet): ~p", [_Msg]),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

%% resent request
handle_request(_ReqKey, _Msg, true, State) ->
%% resent request
    {noreply, State};

handle_request(_ReqKey,
	       #gtp{type = create_pdp_context_request,
		    ie = #{
		      ?'Quality of Service Profile' := ReqQoSProfile
		     } = IEs} = Request, _Resent,
	       #{context := Context0,
		 aaa_opts := AAAopts,
		 'Session' := Session} = State0) ->

    EUA = maps:get(?'End User Address', IEs, undefined),

    Context1 = update_context_from_gtp_req(IEs, Context0),
    ContextPreAuth = gtp_path:bind(Request, Context1),

    gtp_context:terminate_colliding_context(ContextPreAuth),

    SessionOpts0 = init_session(IEs, ContextPreAuth, AAAopts),
    SessionOpts1 = init_session_from_gtp_req(IEs, AAAopts, SessionOpts0),
    SessionOpts = init_session_qos(ReqQoSProfile, SessionOpts1),

    authenticate(ContextPreAuth, Session, SessionOpts, Request),
    {ContextVRF, VRFOpts} = select_vrf(ContextPreAuth),

    ActiveSessionOpts0 = ergw_aaa_session:get(Session),
    ActiveSessionOpts1 = apply_vrf_session_defaults(VRFOpts, ActiveSessionOpts0),
    lager:info("ActiveSessionOpts: ~p", [ActiveSessionOpts1]),

    ContextPending = assign_ips(ActiveSessionOpts1, EUA, ContextVRF),
    {ActiveSessionOpts, State} = diameter_gx(Request, ActiveSessionOpts1, ContextPending, State0),

    gtp_context:remote_context_register_new(ContextPending),
    Context = dp_create_pdp_context(ContextPending),
    gtp_context:apply_session_policy(ActiveSessionOpts, Context, State),

    ResponseIEs = create_pdp_context_response(ActiveSessionOpts, IEs, Context),
    Reply = response(create_pdp_context_response, Context, ResponseIEs, Request),

    ergw_aaa_session:start(Session, #{}),

    {reply, Reply, State#{context => Context}};

handle_request(_ReqKey,
	       #gtp{type = update_pdp_context_request,
		    ie = #{?'Quality of Service Profile' := ReqQoSProfile
			  } = IEs} = Request, _Resent,
	       #{context := OldContext} = State0) ->

    Context0 = update_context_from_gtp_req(IEs, OldContext),
    Context = gtp_path:bind(Request, Context0),

    State1 = if Context /= OldContext ->
		     gtp_context:remote_context_update(OldContext, Context),
		     apply_context_change(Context, OldContext, State0);
		true ->
		     State0
	     end,

    ResponseIEs0 = [#cause{value = request_accepted},
		    #charging_id{id = <<0,0,0,1>>},
		    ReqQoSProfile],
    ResponseIEs = tunnel_endpoint_elements(Context, ResponseIEs0),
    Reply = response(update_pdp_context_response, Context, ResponseIEs, Request),
    {reply, Reply, State1};

handle_request(_ReqKey,
	       #gtp{type = ms_info_change_notification_request, ie = IEs} = Request,
	       _Resent, #{context := OldContext} = State) ->

    Context = update_context_from_gtp_req(IEs, OldContext),

    ResponseIEs0 = [#cause{value = request_accepted}],
    ResponseIEs = copy_ies_to_response(IEs, ResponseIEs0, [?'IMSI', ?'IMEI']),
    Response = response(ms_info_change_notification_response, Context, ResponseIEs, Request),
    {reply, Response, State#{context => Context}};

handle_request(_ReqKey,
	       #gtp{type = delete_pdp_context_request, ie = _IEs}, _Resent,
	       #{context := Context} = State) ->
    close_pdp_context(State),
    Reply = response(delete_pdp_context_response, Context, request_accepted),
    {stop, Reply, State};

handle_request(ReqKey, _Msg, _Resent, State) ->
    gtp_context:request_finished(ReqKey),
    {noreply, State}.

handle_response(From, timeout, #gtp{type = delete_pdp_context_request}, State) ->
    close_pdp_context(State),
    gen_server:reply(From, {error, timeout}),
    {stop, State};

handle_response(From,
		#gtp{type = delete_pdp_context_response,
		     ie = #{?'Cause' := #cause{value = Cause}}} = Response,
		_Request,
		#{context := Context0} = State) ->
    Context = gtp_path:bind(Response, Context0),
    close_pdp_context(State),
    gen_server:reply(From, {ok, Cause}),
    {stop, State#{context := Context}}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

response(Cmd, #context{remote_control_tei = TEID}, Response) ->
    {Cmd, TEID, Response}.

response(Cmd, Context, IEs0, #gtp{ie = #{?'Recovery' := Recovery}}) ->
    IEs = gtp_v1_c:build_recovery(Context, Recovery /= undefined, IEs0),
    response(Cmd, Context, IEs).

authenticate(Context, Session, SessionOpts, Request) ->
    lager:info("SessionOpts: ~p", [SessionOpts]),

    case ergw_aaa_session:authenticate(Session, SessionOpts) of
	success ->
	    lager:info("AuthResult: success"),
	    ok;

	Other ->
	    lager:info("AuthResult: ~p", [Other]),

	    Reply1 = response(create_pdp_context_response, Context,
			      [#cause{value = user_authentication_failed}], Request),
	    throw(#ctx_err{level = ?FATAL,
			   reply = Reply1,
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

pdp_alloc(#end_user_address{pdp_type_organization = 1,
			    pdp_type_number = 16#21,
			    pdp_address = Address}) ->
    IP4 = case Address of
	      << >> ->
		  {0,0,0,0};
	      <<_:4/bytes>> ->
		  gtp_c_lib:bin2ip(Address)
	  end,
    {IP4, undefined};

pdp_alloc(#end_user_address{pdp_type_organization = 1,
			    pdp_type_number = 16#57,
			    pdp_address = Address}) ->
    IP6 = case Address of
	      << >> ->
		  {{0,0,0,0,0,0,0,0},64};
	      <<_:16/bytes>> ->
		  {gtp_c_lib:bin2ip(Address),128}
	  end,
    {undefined, IP6};
pdp_alloc(#end_user_address{pdp_type_organization = 1,
			    pdp_type_number = 16#8D,
			    pdp_address = Address}) ->
    case Address of
	<< IP4:4/bytes, IP6:16/bytes >> ->
	    {gtp_c_lib:bin2ip(IP4), {gtp_c_lib:bin2ip(IP6), 128}};
	<< IP6:16/bytes >> ->
	    {{0,0,0,0}, {gtp_c_lib:bin2ip(IP6), 128}};
	<< IP4:4/bytes >> ->
	    {gtp_c_lib:bin2ip(IP4), {{0,0,0,0,0,0,0,0},64}};
 	<<  >> ->
	    {{0,0,0,0}, {{0,0,0,0,0,0,0,0},64}}
   end;

pdp_alloc(_) ->
    {undefined, undefined}.

encode_eua({IPv4,_}, undefined) ->
    encode_eua(1, 16#21, gtp_c_lib:ip2bin(IPv4), <<>>);
encode_eua(undefined, {IPv6,_}) ->
    encode_eua(1, 16#57, <<>>, gtp_c_lib:ip2bin(IPv6));
encode_eua({IPv4,_}, {IPv6,_}) ->
    encode_eua(1, 16#8D, gtp_c_lib:ip2bin(IPv4), gtp_c_lib:ip2bin(IPv6)).

encode_eua(Org, Number, IPv4, IPv6) ->
    #end_user_address{pdp_type_organization = Org,
		      pdp_type_number = Number,
		      pdp_address = <<IPv4/binary, IPv6/binary >>}.

pdp_release_ip(#context{vrf = VRF, ms_v4 = MSv4, ms_v6 = MSv6}) ->
    vrf:release_pdp_ip(VRF, MSv4, MSv6).

close_pdp_context(#{context := Context, 'Session' := Session} = State) ->
    SessionOpts = get_accounting(Context),
    lager:debug("Accounting Opts: ~p", [SessionOpts]),
    ergw_aaa_session:stop(Session, SessionOpts),
    diameter_gx(delete_pdp_context, SessionOpts, Context, State),

    dp_delete_pdp_context(Context),
    pdp_release_ip(Context).

apply_context_change(NewContext0, OldContext, State) ->
    NewContextPending = gtp_path:bind(NewContext0),
    NewContext = dp_update_pdp_context(NewContextPending, OldContext),
    gtp_path:unbind(OldContext),
    State#{context => NewContext}.

select_vrf(#context{apn = APN} = Context) ->
    case ergw:vrf(APN) of
	{ok, {VRF, VRFOpts}} ->
	    {Context#context{vrf = VRF}, VRFOpts};
	_ ->
	    throw(#ctx_err{level = ?FATAL,
			   reply = missing_or_unknown_apn,
			   context = Context})
    end.

copy_vrf_session_defaults(K, Value, Opts)
    when K =:= 'MS-Primary-DNS-Server';
	 K =:= 'MS-Secondary-DNS-Server';
	 K =:= 'MS-Primary-NBNS-Server';
	 K =:= 'MS-Secondary-NBNS-Server' ->
    Opts#{K => gtp_c_lib:ip2bin(Value)};
copy_vrf_session_defaults(_K, _V, Opts) ->
    Opts.

apply_vrf_session_defaults(VRFOpts, Session) ->
    Defaults = maps:fold(fun copy_vrf_session_defaults/3, #{}, VRFOpts),
    maps:merge(Defaults, Session).

map_attr('APN', #{?'Access Point Name' := #access_point_name{apn = APN}}) ->
    unicode:characters_to_binary(lists:join($., APN));
map_attr('IMSI', #{?'IMSI' := #international_mobile_subscriber_identity{imsi = IMSI}}) ->
    IMSI;
map_attr('IMEI', #{?'IMEI' := #imei{imei = IMEI}}) ->
    IMEI;
map_attr('MSISDN', #{?'MSISDN' := #ms_international_pstn_isdn_number{
				     msisdn = {isdn_address, _, _, 1, MSISDN}}}) ->
    MSISDN;
map_attr(Value, _) when is_binary(Value); is_list(Value) ->
    Value;
map_attr(Value, _) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
map_attr(Value, _) ->
    io_lib:format("~w", [Value]).

map_username(_IEs, Username, _) when is_binary(Username) ->
    Username;
map_username(_IEs, [], Acc) ->
    iolist_to_binary(lists:reverse(Acc));
map_username(IEs, [H | Rest], Acc) ->
    Part = map_attr(H, IEs),
    map_username(IEs, Rest, [Part | Acc]).

init_session(IEs,
	     #context{control_port = #gtp_port{ip = LocalIP}},
	     #{'Username' := #{default := Username},
	       'Password' := #{default := Password}}) ->
    MappedUsername = map_username(IEs, Username, []),
    #{'Username'		=> MappedUsername,
      'Password'		=> Password,
      'Service-Type'		=> 'Framed-User',
      'Framed-Protocol'		=> 'GPRS-PDP-Context',
      '3GPP-GGSN-Address'	=> LocalIP,
      'PCC-Groups'              => [<<"default">>]
     }.

copy_ppp_to_session({pap, 'PAP-Authentication-Request', _Id, Username, Password}, Session0) ->
    Session = Session0#{'Username' => Username, 'Password' => Password},
    maps:without(['CHAP-Challenge', 'CHAP_Password'], Session);
copy_ppp_to_session({chap, 'CHAP-Challenge', _Id, Value, _Name}, Session) ->
    Session#{'CHAP_Challenge' => Value};
copy_ppp_to_session({chap, 'CHAP-Response', _Id, Value, Name}, Session0) ->
    Session = Session0#{'CHAP_Password' => Value, 'Username' => Name},
    maps:without(['Password'], Session);
copy_ppp_to_session(_, Session) ->
    Session.

copy_to_session(_, #protocol_configuration_options{config = {0, Options}},
		#{'Username' := #{from_protocol_opts := true}}, Session) ->
    lists:foldr(fun copy_ppp_to_session/2, Session, Options);
copy_to_session(_, #access_point_name{apn = APN}, _AAAopts, Session) ->
    Session#{'Called-Station-Id' => unicode:characters_to_binary(lists:join($., APN))};
copy_to_session(_, #ms_international_pstn_isdn_number{
		   msisdn = {isdn_address, _, _, 1, MSISDN}}, _AAAopts, Session) ->
    Session#{'Calling-Station-Id' => MSISDN};
copy_to_session(_, #international_mobile_subscriber_identity{imsi = IMSI}, _AAAopts, Session) ->
    case itu_e212:split_imsi(IMSI) of
	{MCC, MNC, _} ->
	    Session#{'3GPP-IMSI' => IMSI,
		     '3GPP-IMSI-MCC-MNC' => <<MCC/binary, MNC/binary>>};
	_ ->
	    Session#{'3GPP-IMSI' => IMSI}
    end;
copy_to_session(_, #end_user_address{pdp_type_organization = 0,
				  pdp_type_number = 1}, _AAAopts, Session) ->
    Session#{'3GPP-PDP-Type' => 'PPP'};
copy_to_session(_, #end_user_address{pdp_type_organization = 1,
				  pdp_type_number = 16#57,
				  pdp_address = Address}, _AAAopts, Session0) ->
    Session = Session0#{'3GPP-PDP-Type' => 'IPv4'},
    case Address of
	<<_:4/bytes>> -> Session#{'Framed-IP-Address' => gtp_c_lib:bin2ip(Address)};
	_             -> Session
    end;
copy_to_session(_, #end_user_address{pdp_type_organization = 1,
				  pdp_type_number = 16#21,
				  pdp_address = Address}, _AAAopts, Session0) ->
    Session = Session0#{'3GPP-PDP-Type' => 'IPv6'},
    case Address of
	<<_:16/bytes>> -> Session#{'Framed-IPv6-Prefix' => {gtp_c_lib:bin2ip(Address), 128}};
	_              -> Session
    end;
copy_to_session(_, #end_user_address{pdp_type_organization = 1,
				  pdp_type_number = 16#8D,
				  pdp_address = Address}, _AAAopts, Session0) ->
    Session = Session0#{'3GPP-PDP-Type' => 'IPv4v6'},
    case Address of
	<< IP4:4/bytes >> ->
	    Session#{'Framed-IP-Address'  => gtp_c_lib:bin2ip(IP4)};
	<< IP6:16/bytes >> ->
	    Session#{'Framed-IPv6-Prefix' => {gtp_c_lib:bin2ip(IP6), 128}};
	<< IP4:4/bytes, IP6:16/bytes >> ->
	    Session#{'Framed-IP-Address'  => gtp_c_lib:bin2ip(IP4),
		     'Framed-IPv6-Prefix' => {gtp_c_lib:bin2ip(IP6), 128}};
	_ ->
	    Session
   end;

copy_to_session(_, #gsn_address{instance = 0, address = IP}, _AAAopts, Session) ->
    Session#{'3GPP-SGSN-Address' => gtp_c_lib:bin2ip(IP)};
copy_to_session(_, #nsapi{instance = 0, nsapi = NSAPI}, _AAAopts, Session) ->
    Session#{'3GPP-NSAPI' => NSAPI};
copy_to_session(_, #selection_mode{mode = Mode}, _AAAopts, Session) ->
    Session#{'3GPP-Selection-Mode' => Mode};
copy_to_session(_, #charging_characteristics{value = Value}, _AAAopts, Session) ->
    Session#{'3GPP-Charging-Characteristics' => Value};
copy_to_session(_, #routeing_area_identity{mcc = MCC, mnc = MNC}, _AAAopts, Session) ->
    Session#{'3GPP-SGSN-MCC-MNC' => <<MCC/binary, MNC/binary>>};
copy_to_session(_, #imei{imei = IMEI}, _AAAopts, Session) ->
    Session#{'3GPP-IMEISV' => IMEI};
copy_to_session(_, #rat_type{rat_type = Type}, _AAAopts, Session) ->
    Session#{'3GPP-RAT-Type' => Type};
copy_to_session(_, #user_location_information{} = IE, _AAAopts, Session) ->
    Value = gtp_packet:encode_v1_uli(IE),
    Session#{'3GPP-User-Location-Info' => Value};
copy_to_session(_, #ms_time_zone{timezone = TZ, dst = DST}, _AAAopts, Session) ->
    Session#{'3GPP-MS-TimeZone' => {TZ, DST}};
copy_to_session(_, _, _AAAopts, Session) ->
    Session.

init_session_from_gtp_req(IEs, AAAopts, Session) ->
    maps:fold(copy_to_session(_, _, AAAopts, _), Session, IEs).

init_session_qos(#quality_of_service_profile{
		    priority = RequestedPriority,
		    data = RequestedQoS}, Session) ->
    %% TODO: use config setting to init default class....
    {NegotiatedPriority, NegotiatedQoS} = negotiate_qos(RequestedPriority, RequestedQoS),
    Session#{'3GPP-Allocation-Retention-Priority' => NegotiatedPriority,
	     '3GPP-GPRS-Negotiated-QoS-Profile'   => NegotiatedQoS}.

negotiate_qos_prio(X) when X > 0 andalso X =< 3 ->
    X;
negotiate_qos_prio(_) ->
    2.

negotiate_qos(ReqPriority, ReqQoSProfileData) ->
    NegPriority = negotiate_qos_prio(ReqPriority),
    case '3gpp_qos':decode(ReqQoSProfileData) of
	Profile when is_binary(Profile) ->
	    {NegPriority, ReqQoSProfileData};
	#qos{traffic_class = 0} ->			%% MS to Network: Traffic Class: Subscribed
	    %% 3GPP TS 24.008, Sect. 10.5.6.5,
	    QoS = #qos{
		     delay_class			= 4,		%% best effort
		     reliability_class			= 3,		%% Unacknowledged GTP/LLC,
		     %% Ack RLC, Protected data
		     peak_throughput			= 2,		%% 2000 oct/s (2 kBps)
		     precedence_class			= 3,		%% Low priority
		     mean_throughput			= 31,		%% Best effort
		     traffic_class			= 4,		%% Background class
		     delivery_order			= 2,		%% Without delivery order
		     delivery_of_erroneorous_sdu	= 3,		%% Erroneous SDUs are not delivered
		     max_sdu_size			= 1500,		%% 1500 octets
		     max_bit_rate_uplink		= 16,		%% 16 kbps
		     max_bit_rate_downlink		= 16,		%% 16 kbps
		     residual_ber			= 7,		%% 10^-5
		     sdu_error_ratio			= 4,		%% 10^-4
		     transfer_delay			= 300,		%% 300ms
		     traffic_handling_priority		= 3,		%% Priority level 3
		     guaranteed_bit_rate_uplink		= 0,		%% 0 kbps
		     guaranteed_bit_rate_downlink	= 0,		%% 0 kbps
		     signaling_indication		= 0,		%% unknown
		     source_statistics_descriptor	= 0},		%% Not optimised for signalling traffic
	    {NegPriority, '3gpp_qos':encode(QoS)};
	_ ->
	    {NegPriority, ReqQoSProfileData}
    end.

get_context_from_req(_, #gsn_address{instance = 0, address = CntlIP}, Context) ->
    Context#context{remote_control_ip = gtp_c_lib:bin2ip(CntlIP)};
get_context_from_req(_, #gsn_address{instance = 1, address = DataIP}, Context) ->
    Context#context{remote_data_ip = gtp_c_lib:bin2ip(DataIP)};
get_context_from_req(_, #tunnel_endpoint_identifier_data_i{instance = 0, tei = DataTEI}, Context) ->
    Context#context{remote_data_tei = DataTEI};
get_context_from_req(_, #tunnel_endpoint_identifier_control_plane{instance = 0, tei = CntlTEI}, Context) ->
    Context#context{remote_control_tei = CntlTEI};
get_context_from_req(?'Access Point Name', #access_point_name{apn = APN}, Context) ->
    Context#context{apn = APN};
get_context_from_req(?'IMSI', #international_mobile_subscriber_identity{imsi = IMSI}, Context) ->
    Context#context{imsi = IMSI};
get_context_from_req(?'IMEI', #imei{imei = IMEI}, Context) ->
    Context#context{imei = IMEI};
get_context_from_req(?'MSISDN', #ms_international_pstn_isdn_number{
				   msisdn = {isdn_address, _, _, 1, MSISDN}}, Context) ->
    Context#context{msisdn = MSISDN};
%% get_context_from_req(#nsapi{instance = 0, nsapi = NSAPI}, #context{state = State} = Context) ->
%%     Context#context{state = State#context_state{nsapi = NSAPI}};
get_context_from_req(_, _, Context) ->
    Context.

update_context_from_gtp_req(Request, Context) ->
    maps:fold(fun get_context_from_req/3, Context, Request).

enter_ie(_Key, Value, IEs)
  when is_list(IEs) ->
    [Value|IEs].
%% enter_ie(Key, Value, IEs)
%%   when is_map(IEs) ->
%%     IEs#{Key := Value}.

copy_ies_to_response(_, ResponseIEs, []) ->
    ResponseIEs;
copy_ies_to_response(RequestIEs, ResponseIEs0, [H|T]) ->
    ResponseIEs =
	case RequestIEs of
	    #{H := Value} ->
		enter_ie(H, Value, ResponseIEs0);
	    _ ->
		ResponseIEs0
	end,
    copy_ies_to_response(RequestIEs, ResponseIEs, T).

send_request(#context{control_port = GtpPort,
		      remote_control_tei = RemoteCntlTEI,
		      remote_control_ip = RemoteCntlIP},
	     T3, N3, Type, RequestIEs, ReqInfo) ->
    Msg = #gtp{version = v1, type = Type, tei = RemoteCntlTEI, ie = RequestIEs},
    gtp_context:send_request(GtpPort, RemoteCntlIP, T3, N3, Msg, ReqInfo).

%% delete_context(From, #context_state{nsapi = NSAPI} = Context) ->
delete_context(From, Context) ->
    NSAPI = 5,
    RequestIEs0 = [#nsapi{nsapi = NSAPI},
		   #teardown_ind{value = 1}],
    RequestIEs = gtp_v1_c:build_recovery(Context, false, RequestIEs0),
    send_request(Context, ?T3, ?N3, delete_pdp_context_request, RequestIEs, From).

dp_args(#context{ms_v4 = {MSv4,_}}) ->
    MSv4;
dp_args(_) ->
    undefined.

dp_create_pdp_context(Context) ->
    Args = dp_args(Context),
    gtp_dp:create_pdp_context(Context, Args).

dp_update_pdp_context(#context{remote_data_ip  = RemoteDataIP, remote_data_tei = RemoteDataTEI
			      } = New,
		      #context{remote_data_ip  = RemoteDataIP, remote_data_tei = RemoteDataTEI}) ->
    New;
dp_update_pdp_context(NewContext, OldContext) ->
    dp_delete_pdp_context(OldContext),
    dp_create_pdp_context(NewContext).

dp_delete_pdp_context(Context) ->
    Args = dp_args(Context),
    gtp_dp:delete_pdp_context(Context, Args).

session_ipv4_alloc(#{'Framed-IP-Address' := {255,255,255,255}}, ReqMSv4) ->
    ReqMSv4;
session_ipv4_alloc(#{'Framed-IP-Address' := {255,255,255,254}}, _ReqMSv4) ->
    {0,0,0,0};
session_ipv4_alloc(#{'Framed-IP-Address' := {_,_,_,_} = IPv4}, _ReqMSv4) ->
    IPv4;
session_ipv4_alloc(_SessionOpts, ReqMSv4) ->
    ReqMSv4.

session_ipv6_alloc(#{'Framed-IPv6-Prefix' := {{_,_,_,_,_,_,_,_}, _} = IPv6}, _ReqMSv6) ->
    IPv6;
session_ipv6_alloc(_SessionOpts, ReqMSv6) ->
    ReqMSv6.

session_ip_alloc(SessionOpts, {ReqMSv4, ReqMSv6}) ->
    MSv4 = session_ipv4_alloc(SessionOpts, ReqMSv4),
    MSv6 = session_ipv6_alloc(SessionOpts, ReqMSv6),
    {MSv4, MSv6}.

assign_ips(SessionOps, EUA, #context{vrf = VRF, local_control_tei = LocalTEI} = Context) ->
    {ReqMSv4, ReqMSv6} = session_ip_alloc(SessionOps, pdp_alloc(EUA)),
    {ok, MSv4, MSv6} = vrf:allocate_pdp_ip(VRF, LocalTEI, ReqMSv4, ReqMSv6),
    Context#context{ms_v4 = MSv4, ms_v6 = MSv6}.

ppp_ipcp_conf_resp(Verdict, Opt, IPCP) ->
    maps:update_with(Verdict, fun(O) -> [Opt|O] end, [Opt], IPCP).

ppp_ipcp_conf(#{'MS-Primary-DNS-Server' := DNS}, {ms_dns1, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_dns1, gtp_c_lib:ip2bin(DNS)}, IPCP);
ppp_ipcp_conf(#{'MS-Secondary-DNS-Server' := DNS}, {ms_dns2, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_dns2, gtp_c_lib:ip2bin(DNS)}, IPCP);
ppp_ipcp_conf(#{'MS-Primary-NBNS-Server' := DNS}, {ms_wins1, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_wins1, gtp_c_lib:ip2bin(DNS)}, IPCP);
ppp_ipcp_conf(#{'MS-Secondary-NBNS-Server' := DNS}, {ms_wins2, <<0,0,0,0>>}, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Nak', {ms_wins2, gtp_c_lib:ip2bin(DNS)}, IPCP);

ppp_ipcp_conf(_SessionOpts, Opt, IPCP) ->
    ppp_ipcp_conf_resp('CP-Configure-Reject', Opt, IPCP).

pdp_ppp_pco(SessionOpts, {pap, 'PAP-Authentication-Request', Id, _Username, _Password}, Opts) ->
    [{pap, 'PAP-Authenticate-Ack', Id, maps:get('Reply-Message', SessionOpts, <<>>)}|Opts];
pdp_ppp_pco(SessionOpts, {chap, 'CHAP-Response', Id, _Value, _Name}, Opts) ->
    [{chap, 'CHAP-Success', Id, maps:get('Reply-Message', SessionOpts, <<>>)}|Opts];
pdp_ppp_pco(SessionOpts, {ipcp,'CP-Configure-Request', Id, CpReqOpts}, Opts) ->
    CpRespOpts = lists:foldr(ppp_ipcp_conf(SessionOpts, _, _), #{}, CpReqOpts),
    maps:fold(fun(K, V, O) -> [{ipcp, K, Id, V} | O] end, Opts, CpRespOpts);

pdp_ppp_pco(#{'3GPP-IPv6-DNS-Servers' := DNS}, {?'PCO-DNS-Server-IPv6-Address', <<>>}, Opts) ->
    lager:info("Apply IPv6 DNS Servers PCO Opt: ~p", [DNS]),
    Opts;
pdp_ppp_pco(SessionOpts, {?'PCO-DNS-Server-IPv4-Address', <<>>}, Opts) ->
    lists:foldr(fun(Key, O) ->
			case maps:find(Key, SessionOpts) of
			    {ok, DNS} ->
				[{?'PCO-DNS-Server-IPv4-Address', gtp_c_lib:ip2bin(DNS)} | O];
			    _ ->
				O
			end
		end, Opts, ['MS-Secondary-DNS-Server', 'MS-Primary-DNS-Server']);
pdp_ppp_pco(_SessionOpts, PPPReqOpt, Opts) ->
    lager:info("Apply PPP Opt: ~p", [PPPReqOpt]),
    Opts.

pdp_pco(SessionOpts, #{?'Protocol Configuration Options' :=
			   #protocol_configuration_options{config = {0, PPPReqOpts}}}, IE) ->
    case lists:foldr(pdp_ppp_pco(SessionOpts, _, _), [], PPPReqOpts) of
	[]   -> IE;
	Opts -> [#protocol_configuration_options{config = {0, Opts}} | IE]
    end;
pdp_pco(_SessionOpts, _RequestIEs, IE) ->
    IE.

pdp_qos_profile(#{'3GPP-Allocation-Retention-Priority' := NegotiatedPriority,
		  '3GPP-GPRS-Negotiated-QoS-Profile'   := NegotiatedQoS}, IE) ->
    [#quality_of_service_profile{priority = NegotiatedPriority, data = NegotiatedQoS} | IE];
pdp_qos_profile(_SessionOpts, IE) ->
    IE.

tunnel_endpoint_elements(#context{control_port = #gtp_port{ip = CntlIP},
				  local_control_tei = CntlTEI,
				  data_port = #gtp_port{ip = DataIP},
				  local_data_tei = DataTEI}, IEs) ->
    [#tunnel_endpoint_identifier_data_i{tei = DataTEI},
     #tunnel_endpoint_identifier_control_plane{tei = CntlTEI},
     #gsn_address{instance = 0, address = gtp_c_lib:ip2bin(CntlIP)},   %% for Control Plane
     #gsn_address{instance = 1, address = gtp_c_lib:ip2bin(DataIP)}    %% for User Traffic
     | IEs].

create_pdp_context_response(SessionOpts, RequestIEs,
			    #context{ms_v4 = MSv4, ms_v6 = MSv6} = Context) ->
    IE0 = [#cause{value = request_accepted},
	   #reordering_required{required = no},
	   #charging_id{id = <<0,0,0,1>>},
	   encode_eua(MSv4, MSv6)],
    IE1 = pdp_qos_profile(SessionOpts, IE0),
    IE2 = pdp_pco(SessionOpts, RequestIEs, IE1),
    tunnel_endpoint_elements(Context, IE2).

%%%===================================================================
%%% DIAMETER functions
%%%===================================================================

gx_request(Type, #{sid := SId, cc_req := Req} = State0) ->
    Avps = #{'Session-Id'          => SId,
	     'Auth-Application-Id' => ?DIAMETER_APP_ID_GX,
	     'CC-Request-Type'     => Type,
	     'CC-Request-Number'   => Req,
	     'IP-CAN-Type'         => [?'DIAMETER_GX_IP-CAN-TYPE_3GPP-GPRS'],
	     'QoS-Negotiation'     => [?'DIAMETER_GX_QOS-NEGOTIATION_NO_QOS_NEGOTIATION'],
	     'QoS-Upgrade'         => [?'DIAMETER_GX_QOS-UPGRADE_QOS_UPGRADE_NOT_SUPPORTED']
	    },
    State = State0#{cc_req => Req + 1},
    {Avps, State}.

diameter_gx(Request, SessionOpts0, Context, State0) ->
    State1 = State0#{
	       sid    => diameter:session_id("erGW"),
	       cc_req => 0
	      },
    DiamReqType =
	case Request of
	    #gtp{type = create_pdp_context_request} ->
		?'DIAMETER_GX_CC-REQUEST-TYPE_INITIAL_REQUEST';
	    %% #gtp{type = update_pdp_context_request} ->
	    %% 	?'DIAMETER_GX_CC-REQUEST-TYPE_UPDATE_REQUEST';
	    delete_pdp_context ->
		?'DIAMETER_GX_CC-REQUEST-TYPE_TERMINATION_REQUEST'
	end,
    {Avps0, State} = gx_request(DiamReqType, State1),
    Avps1 = gx_gtp_req(Request, Avps0),
    Avps2 = gx_context(Context, Avps1),
    Avps = gx_session(SessionOpts0, Avps2),
    lager:warning("Avps: ~p", [Avps]),

    DiamReq = ['CCR' | to_list(Avps)],
    case ergw_aaa_gx:call(DiamReq) of
	{ok, {'CCA', CCA}} ->
	    case get_result_code(CCA) of
		?'DIAMETER_BASE_RESULT-CODE_SUCCESS' ->
		    SessionOpts = cca2session(CCA, SessionOpts0),
		    {SessionOpts, State}
	    end;

	Other ->
	    lager:error("Unexpected DIAMETER Gx result: ~p", [Other]),
	    {SessionOpts0, State}
    end.

get_result_code(#{'Experimental-Result' :=
		      #{'Vendor-Id' := ?VENDOR_ID_3GPP,
			'Experimental-Result-Code' := Code}}) ->
    Code;
get_result_code(#{'Result-Code' := Code}) ->
    Code;
get_result_code(_) ->
    ?'DIAMETER_BASE_RESULT-CODE_UNABLE_TO_COMPLY'.

%% GTP Req: {15,0} : {15,0,<<1>>}
%% GTP Req: {end_user_address,0} : {end_user_address,0,1,141,<<>>}
%% GTP Req: {gsn_address,0} : {gsn_address,0,<<172,20,16,180>>}
%% GTP Req: {gsn_address,1} : {gsn_address,1,<<172,20,16,180>>}
%% GTP Req: {nsapi,0} : {nsapi,0,15}
%% GTP Req: {protocol_configuration_options,0} : {protocol_configuration_options,0,{0,[{ipcp,'CP-Configure-Request',2,[{ms_dns1,<<0,0,0,0>>},{ms_dns2,<<0,0,0,0>>}]},{3,<<>>}]}}
%% GTP Req: {quality_of_service_profile,0} : {quality_of_service_profile,0,3,<<0,0,0,0,0,0,0,0,0,0,0>>}
%% GTP Req: {tunnel_endpoint_identifier_control_plane,0} : {tunnel_endpoint_identifier_control_plane,0,1627416944}
%% GTP Req: {tunnel_endpoint_identifier_data_i,0} : {tunnel_endpoint_identifier_data_i,0,1627416944}

rat_type(1) -> ?'DIAMETER_GX_RAT-TYPE_UTRAN';			%% UTRAN
rat_type(2) -> ?'DIAMETER_GX_RAT-TYPE_GERAN';			%% GERAN
rat_type(3) -> ?'DIAMETER_GX_RAT-TYPE_WLAN';			%% WLAN
rat_type(4) -> ?'DIAMETER_GX_RAT-TYPE_GAN';			%% GAN
rat_type(5) -> ?'DIAMETER_GX_RAT-TYPE_HSPA_EVOLUTION';		%% HSPA Evolution
rat_type(6) -> ?'DIAMETER_GX_RAT-TYPE_EUTRAN';			%% E-UTRAN
rat_type(0) -> ?'DIAMETER_GX_RAT-TYPE_VIRTUAL'.			%% VIRTUAL

repeated(Key, Value, Avps) ->
    maps:update_with(Key, fun(V) -> [Value|V] end, [Value], Avps).

%% choice(B, True, _False)
%%   when B == true; B == 1 ->
%%     True;
%% choice(_, _True, False) ->
%%     False.

framed_ip(Key, {IP,_}, Avps) ->
    Avps#{Key => [[gtp_c_lib:ip2bin(IP)]]};
framed_ip(_Key, _, Avps) ->
    Avps.

bin2hex(Bin) ->
    [ io_lib:format("~2.16.0B", [X]) || <<X>> <= Bin ].

gx_gtp_flags('No QoS negotiation', Avps) ->
    Avps#{'QoS-Negotiation' => [?'DIAMETER_GX_QOS-NEGOTIATION_QOS_NEGOTIATION_SUPPORTED']};
gx_gtp_flags('Upgrade QoS Supported', Avps) ->
    Avps#{'QoS-Upgrade' => [?'DIAMETER_GX_QOS-UPGRADE_QOS_UPGRADE_SUPPORTED']};
gx_gtp_flags(_, Avps) ->
    Avps.

gx_gtp_req(?'MSISDN', #ms_international_pstn_isdn_number{
		       msisdn = {isdn_address, _, _, 1, MSISDN}}, Avps) ->
    SI = #{'Subscription-Id-Type' => ?'DIAMETER_GX_SUBSCRIPTION-ID-TYPE_END_USER_E164',
	   'Subscription-Id-Data' => MSISDN},
    repeated('Subscription-Id', SI, Avps);
gx_gtp_req({common_flags, 0}, #common_flags{flags = Flags}, Avps) ->
    lists:foldl(fun gx_gtp_flags/2, Avps, Flags);
gx_gtp_req({routeing_area_identity, 0}, RAI, Avps) ->
    Avps#{'RAI' => [bin2hex(gtp_packet:encode_v1_rai(RAI))]};
gx_gtp_req(_K, _V, Avps) ->
    lager:warning("GTP Req: ~p : ~p", [_K, _V]),
    Avps.

gx_gtp_req(#gtp{ie = IEs}, Avps) ->
    maps:fold(fun gx_gtp_req/3, Avps, IEs);
gx_gtp_req(_, Avps) ->
    Avps.

gx_context(#context{control_port = #gtp_port{ip = LocalIP},
		    ms_v4 = MSv4, ms_v6 = MSv6}, Avps0) ->
    Avps1 = framed_ip('Framed-IP-Address', MSv4, Avps0),
    Avps2 = framed_ip('Framed-IPv6-Prefix', MSv6, Avps1),
    Avps2#{'3GPP-GGSN-Address' => [gtp_c_lib:ip2bin(LocalIP)]}.

gx_session('APN', APN, Avps) ->
    Avps#{'Called-Station-Id' => [APN]};
gx_session('3GPP-IMSI', IMSI, Avps) ->
    SI = #{'Subscription-Id-Type' => ?'DIAMETER_GX_SUBSCRIPTION-ID-TYPE_END_USER_IMSI',
	   'Subscription-Id-Data' => IMSI},
    repeated('Subscription-Id', SI, Avps);
gx_session('3GPP-SGSN-Address', IP, Avps) ->
    Avps#{'3GPP-SGSN-Address' => [IP]};
gx_session('3GPP-Selection-Mode', Mode, Avps) ->
    Avps#{'3GPP-Selection-Mode' => [integer_to_list(Mode)]};
gx_session('3GPP-Charging-Characteristics', Value, Avps) ->
    Avps#{'3GPP-Charging-Characteristics' => [Value]};
gx_session('3GPP-SGSN-MCC-MNC', MCCMNC, Avps) ->
    Avps#{'3GPP-SGSN-MCC-MNC' => [MCCMNC]};
gx_session('3GPP-RAT-Type', Type, Avps) ->
    Avps#{'RAT-Type' => [rat_type(Type)],
	  '3GPP-RAT-Type' => [<<Type>>]};
gx_session('3GPP-IMEISV', IMEI, Avps) ->
    UE = #{'User-Equipment-Info-Type' =>
	       ?'DIAMETER_GX_USER-EQUIPMENT-INFO-TYPE_IMEISV',
	   'User-Equipment-Info-Value' => IMEI},
    Avps#{'User-Equipment-Info' => [UE]};
gx_session('3GPP-User-Location-Info', Value, Avps) ->
    Avps#{'3GPP-User-Location-Info' => [Value]};
gx_session('3GPP-MS-TimeZone', {TZ, DST}, Avps) ->
    Avps#{'3GPP-MS-TimeZone' => [<<TZ:8, DST:8>>]};

gx_session('PCC-Rules', _V, Avps) ->
    lager:error("PCC-Rules: ~p", [_V]),
    Avps;
gx_session('PCC-Groups', _V, Avps) ->
    lager:error("PCC-Groups: ~p", [_V]),
    Avps;

gx_session(_K, _V, Avps) ->
    Avps.

gx_session(Session, Avps) ->
    maps:fold(fun gx_session/3, Avps, Session).

%% #{'Auth-Application-Id' => 16777238,
%%   'CC-Request-Number' => 0,
%%   'CC-Request-Type' => 1,
%%   'Charging-Rule-Install' =>
%%       [#{'Charging-Rule-Name' => <<"service01">>},
%%        #{'Charging-Rule-Name' => <<"service02">>},
%%        #{'Charging-Rule-Name' => <<"service03">>}],
%%   'Origin-Host' => <<"dmock.example.net">>,
%%   'Origin-Realm' => <<"example.net">>,
%%   'Origin-State-Id' => 1563780711,
%%   'Result-Code' => 2001,
%%   'Session-Id' => <<"erGW;1563785886;1;test@vlx174-tpmd">>,
%%   'Usage-Monitoring-Information' =>
%%       #{'Granted-Service-Unit' =>
%% 	    [#{'CC-Time' => 600},
%% 	     #{'CC-Input-Octets' => 1000,
%% 	       'CC-Output-Octets' => 1000,
%% 	       'CC-Total-Octets' => 1000}],
%% 	'Monitoring-Key' => <<"default">>,
%% 	'Usage-Monitoring-Level' => 0}}

rule_action(install, Key, Rule, Session) ->
    maps:update_with(Key, fun(V) -> [Rule|V] end, [Rule], Session);
rule_action(remove, Key, Rule, Session) ->
    maps:update_with(Key, fun(V) -> lists:delete(Rule, V) end, [], Session).

rule_to_session(Action, 'Charging-Rule-Base-Name', Bases, Session)
  when is_list(Bases) ->
    lists:foldl(rule_action(Action, 'PCC-Groups', _, _), Session, Bases);
rule_to_session(Action, 'Charging-Rule-Base-Name', Base, Session)
  when is_binary(Base) ->
    rule_action(Action, 'PCC-Groups', Base, Session);

rule_to_session(Action, 'Charging-Rule-Name', Bases, Session)
  when is_list(Bases) ->
    lists:foldl(rule_action(Action, 'PCC-Rules', _, _), Session, Bases);
rule_to_session(Action, 'Charging-Rule-Name', Base, Session)
  when is_binary(Base) ->
    rule_action(Action, 'PCC-Rules', Base, Session);
rule_to_session(_, _, _, Session) ->
    Session.

rule_to_session(Action, Values, Session) ->
    maps:fold(rule_to_session(Action, _, _, _), Session, Values).

to_session('Charging-Rule-Install', Value, Session) ->
    lists:foldl(rule_to_session(install, _, _), Session, Value);
to_session('Charging-Rule-Remove', Value, Session) ->
    lists:foldl(rule_to_session(remove, _, _), Session, Value);
to_session(_, _, Session) ->
    Session.

cca2session(CCA, Session) ->
    maps:fold(fun to_session/3, Session, CCA).

to_list({Key, [A | _] = Avps}) when is_map(A) ->
    {Key, lists:map(fun to_list/1, Avps)};
to_list({Key, Avps}) when is_map(Avps) ->
    {Key, lists:map(fun to_list/1, maps:to_list(Avps))};
to_list(Avps) when is_map(Avps) ->
    lists:map(fun to_list/1, maps:to_list(Avps));
to_list(Avp) ->
    Avp.
