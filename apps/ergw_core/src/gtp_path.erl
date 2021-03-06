%% Copyright 2015, 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_path).

-behaviour(gen_statem).

-compile({parse_transform, cut}).
-compile({no_auto_import,[register/2]}).

%% API
-export([start_link/4, all/1,
	 handle_request/2, handle_response/4,
	 bind/1, bind/2, unbind/1, icmp_error/2, path_restart/2,
	 get_handler/2, info/1, sync_state/3]).

%% Validate environment Variables
-export([validate_options/1, setopts/1]).

-ignore_xref([start_link/4,
	      path_restart/2,
	      handle_response/4,		% used from callback handler
	      sync_state/3
	      ]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, handle_event/4,
	 terminate/3, code_change/4]).

-ifdef(TEST).
-export([ping/1, ping/3, set/3, stop/1, maybe_new_path/3]).
-endif.

-include_lib("kernel/include/logger.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("include/ergw.hrl").

-record(peer, {state    :: up | down | suspect,
	       contexts :: non_neg_integer()
	      }).

%% echo_timer is the status of the echo send to the remote peer
-record(state, {peer       :: #peer{},                     %% State of remote peer
		recovery   :: 'undefined' | non_neg_integer(),
		echo       :: 'stopped' | 'echo_to_send' | 'awaiting_response'}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Socket, Version, RemoteIP, Args) ->
    Opts = [{hibernate_after, 5000},
	    {spawn_opt,[{fullsweep_after, 0}]}],
    gen_statem:start_link(?MODULE, [Socket, Version, RemoteIP, Args], Opts).

setopts(Opts0) ->
    Opts = validate_options(Opts0),
    ergw_core_config:put(path_management, Opts).

getopts() ->
    case ergw_core_config:get([path_management], []) of
	{ok, Opts0} = Args when is_map(Opts0) ->
	    Args;
	{ok, Opts0} when is_list(Opts0) ->
	    Opts = validate_options(Opts0),
	    ergw_core_config:put(path_management, Opts),
	    {ok, Opts}
    end.

maybe_new_path(Socket, Version, RemoteIP) ->
    case get(Socket, Version, RemoteIP) of
	Path when is_pid(Path) ->
	    Path;
	_ ->
	    {ok, Args} = getopts(),
	    {ok, Path} = gtp_path_sup:new_path(Socket, Version, RemoteIP, Args),
	    Path
    end.

handle_request(#request{socket = Socket, ip = IP} = ReqKey, #gtp{version = Version} = Msg) ->
    Path = maybe_new_path(Socket, Version, IP),
    gen_statem:cast(Path, {handle_request, ReqKey, Msg}).

handle_response(Path, Request, Ref, Response) ->
    gen_statem:cast(Path, {handle_response, Request, Ref, Response}).

bind(Tunnel) ->
    monitor_path_recovery(bind_path(Tunnel)).

bind(#gtp{ie = #{{recovery, 0} :=
		     #recovery{restart_counter = RestartCounter}}
	 } = Request, Tunnel) ->
    bind_path_recovery(RestartCounter, bind_path(Request, Tunnel));
bind(#gtp{ie = #{{v2_recovery, 0} :=
		     #v2_recovery{restart_counter = RestartCounter}}
	 } = Request, Tunnel) ->
    bind_path_recovery(RestartCounter, bind_path(Request, Tunnel));
bind(Request, Tunnel) ->
    bind_path_recovery(undefined, bind_path(Request, Tunnel)).

unbind(#tunnel{socket = Socket, version = Version, remote = #fq_teid{ip = RemoteIP}}) ->
    case get(Socket, Version, RemoteIP) of
	Path when is_pid(Path) ->
	    gen_statem:call(Path, {unbind, self()});
	_ ->
	    ok
    end.

icmp_error(Socket, IP) ->
    icmp_error(Socket, v1, IP),
    icmp_error(Socket, v2, IP).

icmp_error(Socket, Version, IP) ->
    case get(Socket, Version, IP) of
	Path when is_pid(Path) ->
	    gen_statem:cast(Path, icmp_error);
	_ ->
	    ok
    end.

path_restart(Key, RestartCounter) ->
    case gtp_path_reg:lookup(Key) of
	Path when is_pid(Path) ->
	    gen_statem:cast(Path, {path_restart, RestartCounter});
	_ ->
	    ok
    end.

get(#socket{name = SocketName}, Version, IP) ->
    gtp_path_reg:lookup({SocketName, Version, IP}).

all(Path) ->
    gen_statem:call(Path, all).

info(Path) ->
    gen_statem:call(Path, info).

get_handler(#socket{type = 'gtp-u'}, _) ->
    gtp_v1_u;
get_handler(#socket{type = 'gtp-c'}, v1) ->
    gtp_v1_c;
get_handler(#socket{type = 'gtp-c'}, v2) ->
    gtp_v2_c.

sync_state(Key, OldState, State) ->
    error(badarg, [Key, OldState, State]).

-ifdef(TEST).
ping(Path) ->
    gen_statem:call(Path, '$ping').

ping(Socket, Version, IP) ->
    case get(Socket, Version, IP) of
	Path when is_pid(Path) ->
	    ping(Path);
	_ ->
	    {error, no_found}
    end.

set(Path, Opt, Value) ->
    gen_statem:call(Path, {'$set', Opt, Value}).

stop(Path) ->
    gen_statem:call(Path, '$stop').

-endif.

%%%===================================================================
%%% Options Validation
%%%===================================================================

%% Timer value: echo    = echo interval when peer is up.

-define(Defaults, [
    {t3, 10 * 1000},                  % echo retry interval
    {n3,  5},                         % echo retry count
    {echo, 60 * 1000},                % echo ping interval
    {idle, []},
    {suspect, []},
    {down, []},
    {icmp_error_handling, immediate}  % configurable GTP path ICMP error behaviour
]).
-define(IdleDefaults, [
    {timeout, 1800 * 1000},      % time to keep the path entry when idle
    {echo,     600 * 1000}       % echo retry interval when idle
]).
-define(SuspectDefaults, [
    {timeout, 300 * 1000},       % time to keep the path entry when suspect
    {echo,     60 * 1000}        % echo retry interval when suspect
]).
-define(DownDefaults, [
    {timeout, 3600 * 1000},      % time to keep the path entry when down
    {echo,     600 * 1000}       % echo retry interval when down
]).

validate_options(Values) ->
    ergw_core_config:validate_options(fun validate_option/2, Values, ?Defaults).

validate_echo(_Opt, Value) when is_integer(Value), Value >= 60 * 1000 ->
    Value;
validate_echo(_Opt, off = Value) ->
    Value;
validate_echo(Opt, Value) ->
    erlang:error(badarg, Opt ++ [echo, Value]).

validate_timeout(_Opt, Value) when is_integer(Value), Value >= 0 ->
    Value;
validate_timeout(_Opt, infinity = Value) ->
    Value;
validate_timeout(Opt, Value) ->
    erlang:error(badarg, Opt ++ [timeout, Value]).

validate_state(State, echo, Value) ->
    validate_echo([State], Value);
validate_state(State, timeout, Value) ->
    validate_timeout([State], Value);
validate_state(State, Opt, Value) ->
    erlang:error(badarg, [State, Opt, Value]).

validate_option(t3, Value)
  when is_integer(Value) andalso Value > 0 ->
    Value;
validate_option(n3, Value)
  when is_integer(Value) andalso Value > 0 ->
    Value;
validate_option(echo, Value) ->
    validate_echo([], Value);

validate_option(Opt = idle, Values) ->
    ergw_core_config:validate_options(validate_state(Opt, _, _), Values, ?IdleDefaults);
validate_option(Opt = suspect, Values) ->
    ergw_core_config:validate_options(validate_state(Opt, _, _), Values, ?SuspectDefaults);
validate_option(Opt = down, Values) ->
    ergw_core_config:validate_options(validate_state(Opt, _, _), Values, ?DownDefaults);
validate_option(icmp_error_handling, Value)
  when Value =:= immediate; Value =:= ignore ->
    Value;
validate_option(Opt, Value) ->
    erlang:error(badarg, [Opt, Value]).

%%%===================================================================
%%% Protocol Module API
%%%===================================================================

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

callback_mode() -> [handle_event_function, state_enter].

init([#socket{name = SocketName} = Socket, Version, RemoteIP, Args]) ->
    RegKey = {SocketName, Version, RemoteIP},
    gtp_path_reg:register(RegKey, up),

    State = #state{peer = #peer{state = up, contexts = 0},
		   echo = stopped},

    Data0 = maps:with([t3, n3, echo, idle, suspect, down, icmp_error_handling], Args),
    Data = Data0#{
	     %% Path Info Keys
	     socket     => Socket, % #socket{}
	     version    => Version, % v1 | v2
	     handler    => get_handler(Socket, Version),
	     ip         => RemoteIP,
	     reg_key    => RegKey,
	     time       => 0,

	     contexts   => #{},
	     monitors   => #{}
	},

    ?LOG(debug, "State: ~p Data: ~p", [State, Data]),
    {ok, State, Data}.

handle_event(enter, #state{peer = Old}, #state{peer = Peer}, Data)
  when Old /= Peer ->
    peer_state_change(Old, Peer, Data),
    OldState = peer_state(Old),
    NewState = peer_state(Peer),
    {keep_state_and_data, enter_peer_state_action(OldState, NewState, Data)};

handle_event(enter, #state{echo = Old}, #state{peer = Peer, echo = Echo}, Data)
  when Old /= Echo ->
    State = peer_state(Peer),
    {keep_state_and_data, enter_state_echo_action(State, Data)};

handle_event(enter, _OldState, _State, _Data) ->
    keep_state_and_data;

handle_event({timeout, stop_echo}, stop_echo, State, Data) ->
    {next_state, State#state{echo = stopped}, Data, [{{timeout, echo}, cancel}]};

handle_event({timeout, echo}, start_echo, #state{echo = EchoT} = State0, Data)
  when EchoT =:= stopped;
       EchoT =:= idle ->
    State = send_echo_request(State0, Data),
    {next_state, State, Data};
handle_event({timeout, echo}, start_echo, _State, _Data) ->
    keep_state_and_data;

handle_event({timeout, peer}, down, State, Data) ->
    ring_path_restart(undefined, Data),
    {next_state, peer_state(down, State), Data};

handle_event({timeout, peer}, stop, _State, #{reg_key := RegKey}) ->
    gtp_path_reg:unregister(RegKey),
    {stop, normal};

handle_event({call, From}, all, _State, #{contexts := CtxS} = _Data) ->
    Reply = maps:keys(CtxS),
    {keep_state_and_data, [{reply, From, Reply}]};

handle_event({call, From}, {MonOrBind, Pid}, #state{peer = #peer{state = down}}, _Data)
  when MonOrBind == monitor; MonOrBind == bind ->
    Path = self(),
    proc_lib:spawn(fun() -> gtp_context:path_restart(Pid, Path) end),
    {keep_state_and_data, [{reply, From, {ok, undefined}}]};

handle_event({call, From}, {monitor, Pid}, #state{recovery = RstCnt} = State, Data) ->
    register_monitor(Pid, State, Data, [{reply, From, {ok, RstCnt}}]);

handle_event({call, From}, {bind, Pid}, #state{recovery = RstCnt} = State, Data) ->
    register_bind(Pid, State, Data, [{reply, From, {ok, RstCnt}}]);

handle_event({call, From}, {bind, Pid, RstCnt}, State, Data0) ->
    {Verdict, New, Data} = cas_restart_counter(RstCnt, Data0),
    case Verdict of
	_ when Verdict == initial; Verdict == current ->
	    register_bind(Pid, State#state{recovery = New}, Data, [{reply, From, ok}]);
	peer_restart  ->
	    %% try again after state change
	    ring_path_restart(RstCnt, Data),
	    {keep_state, Data, [postpone]};
	_ ->
	    {keep_state, Data, [{reply, From, Verdict}]}
    end;

handle_event({call, From}, {unbind, Pid}, State, Data) ->
    unregister(Pid, State, Data, [{reply, From, ok}]);

handle_event({call, From}, info, #state{peer = #peer{contexts = CtxCnt}} = State,
	     #{socket := #socket{name = SocketName},
	       version := Version, ip := IP} = Data) ->
    Reply = #{path => self(), socket => SocketName, tunnels => CtxCnt,
	      version => Version, ip => IP, state => State, data => Data},
    {keep_state_and_data, [{reply, From, Reply}]};

handle_event(cast, {handle_request, ReqKey, #gtp{type = echo_request} = Msg0},
	     State, #{socket := Socket, handler := Handler} = Data) ->
    ?LOG(debug, "echo_request: ~p", [Msg0]),
    try gtp_packet:decode_ies(Msg0) of
	Msg = #gtp{} ->
	    ResponseIEs = Handler:build_recovery(echo_response, Socket, true, []),
	    Response = Msg#gtp{type = echo_response, ie = ResponseIEs},
	    ergw_gtp_c_socket:send_response(ReqKey, Response, false),

	    handle_recovery_ie(Msg, State, Data)
    catch
	Class:Error ->
	    ?LOG(error, "GTP decoding failed with ~p:~p for ~p",
		 [Class, Error, Msg0]),
	    keep_state_and_data
    end;

handle_event(cast, {handle_response, echo_request, ReqRef, _Msg}, #state{echo = SRef}, _)
  when ReqRef /= SRef ->
    keep_state_and_data;

handle_event(cast,{handle_response, echo_request, _, #gtp{} = Msg}, State, Data) ->
    handle_recovery_ie(Msg, State#state{echo = idle}, Data);

handle_event(cast,{handle_response, echo_request, _, _Msg}, State, Data) ->
    {next_state, peer_state(suspect, State), Data};

handle_event(cast, {path_restart, RstCnt}, #state{recovery = RstCnt} = _State, _Data) ->
    keep_state_and_data;
handle_event(cast, {path_restart, RstCnt}, State, Data) ->
    path_restart(RstCnt, State, Data);

handle_event(cast, icmp_error, _, #{icmp_error_handling := ignore}) ->
    keep_state_and_data;

handle_event(cast, icmp_error, State, Data) ->
    {next_state, peer_state(suspect, State), Data};

handle_event(info,{'DOWN', _MonitorRef, process, Pid, _Info}, State, Data) ->
    unregister(Pid, State, Data, []);

handle_event({timeout, 'echo'}, _, #state{echo = idle} = State0, Data) ->
    ?LOG(debug, "handle_event timeout: ~p", [Data]),
    State = send_echo_request(State0, Data),
    {next_state, State, Data};

handle_event({timeout, 'echo'}, _, _State, _Data) ->
    ?LOG(debug, "handle_event timeout: ~p", [_Data]),
    keep_state_and_data;

%% test support
handle_event({call, From}, '$ping', State0, Data) ->
    State = send_echo_request(State0, Data),
    {next_state, State, Data, [{{timeout, echo}, cancel}, {reply, From, ok}]};

handle_event({call, From}, {'$set', Opt, Value}, _State, Data) ->
    {keep_state, maps:put(Opt, Value, Data), {reply, From, maps:get(Opt, Data, undefined)}};

handle_event({call, From}, '$stop', _State, #{reg_key := RegKey}) ->
    gtp_path_reg:unregister(RegKey),
    {stop_and_reply, normal, [{reply, From, ok}]};

handle_event({call, From}, Request, _State, _Data) ->
    ?LOG(warning, "handle_event(call,...): ~p", [Request]),
    {keep_state_and_data, [{reply, From, ok}]};

handle_event(cast, Msg, _State, _Data) ->
    ?LOG(error, "~p: ~w: handle_event(cast, ...): ~p", [self(), ?MODULE, Msg]),
    keep_state_and_data;

handle_event(info, Info, _State, _Data) ->
    ?LOG(error, "~p: ~w: handle_event(info, ...): ~p", [self(), ?MODULE, Info]),
    keep_state_and_data.

terminate(_Reason, _State, _Data) ->
    %% TODO: kill all PDP Context on this path
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%%===================================================================
%%% special enter state handlers
%%%===================================================================

peer_state(#peer{state = down}) -> down;
peer_state(#peer{state = up, contexts = 0}) -> idle;
peer_state(#peer{state = up}) -> busy;
peer_state(#peer{state = suspect}) -> suspect.

peer_state_change(#peer{state = State}, #peer{state = State}, _) ->
    ok;
peer_state_change(_, #peer{state = State}, #{reg_key := RegKey}) ->
    gtp_path_reg:state(RegKey, State).

%%%===================================================================
%%% Internal functions
%%%===================================================================

enter_peer_state_action(State, State, _Data) ->
    [];
enter_peer_state_action(_, State, Data) ->
    [enter_state_timeout_action(State, Data),
     enter_state_echo_action(State, Data)].

enter_state_timeout_action(idle, #{idle := #{timeout := Timeout}}) when is_integer(Timeout) ->
    {{timeout, peer}, Timeout, stop};
enter_state_timeout_action(suspect, #{suspect := #{timeout := Timeout}}) when is_integer(Timeout) ->
    {{timeout, peer}, Timeout, down};
enter_state_timeout_action(down, #{down := #{timeout := Timeout}}) when is_integer(Timeout) ->
    {{timeout, peer}, Timeout, stop};
enter_state_timeout_action(_State, _Data) ->
    {{timeout, peer}, cancel}.

enter_state_echo_action(busy, #{echo := EchoInterval}) when is_integer(EchoInterval) ->
    {{timeout, echo}, EchoInterval, start_echo};
enter_state_echo_action(idle, #{idle := #{echo := EchoInterval}})
  when is_integer(EchoInterval) ->
    {{timeout, echo}, EchoInterval, start_echo};
enter_state_echo_action(suspect, #{suspect := #{echo := EchoInterval}})
  when is_integer(EchoInterval) ->
    {{timeout, echo}, EchoInterval, start_echo};
enter_state_echo_action(down, #{down := #{echo := EchoInterval}})
  when is_integer(EchoInterval) ->
    {{timeout, echo}, EchoInterval, start_echo};
enter_state_echo_action(_, _) ->
    {{timeout, stop_echo}, 0, stop_echo}.

foreach_context(none, _Fun) ->
    ok;
foreach_context({Pid, _, Iter}, Fun) ->
    Fun(Pid),
    foreach_context(maps:next(Iter), Fun).

peer_state(PState, #state{peer = Peer} = State) ->
    State#state{peer = Peer#peer{state = PState}}.

peer_contexts(Contexts, #state{peer = Peer} = State) ->
    State#state{peer = Peer#peer{contexts = Contexts}}.

cas_restart_counter(Counter, #{time := Time0, reg_key := Key} = Data) ->
    case gtp_path_db_vnode:cas_restart_counter(Key, Counter, Time0 + 1) of
	{ok, #{result := Result}} ->
	    {Verdict, New, Time} =
		lists:foldl(
		  fun({_Location, {_, _, T1} = R}, {_, _, T2})
			when T1 > T2 -> R;
		     (_, A) -> A
		  end,
		  {fail, Counter, Time0}, Result),
	    {Verdict, New, Data#{time => Time}};
	_Res ->
	    {fail, Counter, Data}
    end.

handle_restart_counter(RestartCounter, State0, Data0) ->
    State = peer_state(up, State0),
    {Verdict, New, Data} = cas_restart_counter(RestartCounter, Data0),
    case Verdict of
	_ when Verdict == initial; Verdict == current ->
	    {next_state, State#state{recovery = New}, Data};
	peer_restart  ->
	    ring_path_restart(RestartCounter, Data),
	    {next_state, State, Data};
	_ ->
	    {keep_state, Data}
    end.

handle_recovery_ie(#gtp{version = v1,
			ie = #{{recovery, 0} :=
				   #recovery{restart_counter =
						 RestartCounter}}}, State, Data) ->
    handle_restart_counter(RestartCounter, State, Data);

handle_recovery_ie(#gtp{version = v2,
			ie = #{{v2_recovery, 0} :=
				   #v2_recovery{restart_counter =
						    RestartCounter}}}, State, Data) ->
    handle_restart_counter(RestartCounter, State, Data);
handle_recovery_ie(#gtp{}, State, Data) ->
    {next_state, peer_state(up, State), Data}.

update_contexts(State0, #{socket := Socket, version := Version, ip := IP} = Data0,
		CtxS, Actions) ->
    Cnt = maps:size(CtxS),
    ergw_prometheus:gtp_path_contexts(Socket, IP, Version, Cnt),
    State = peer_contexts(Cnt, State0),
    Data = Data0#{contexts => CtxS},
    {next_state, State, Data, Actions}.

register_monitor(Pid, State, #{contexts := CtxS, monitors := Mons} = Data, Actions)
  when is_map_key(Pid, CtxS), is_map_key(Pid, Mons) ->
    ?LOG(debug, "~s: monitor(~p)", [?MODULE, Pid]),
    {next_state, State, Data, Actions};
register_monitor(Pid, State, #{monitors := Mons} = Data, Actions) ->
    ?LOG(debug, "~s: monitor(~p)", [?MODULE, Pid]),
    MRef = erlang:monitor(process, Pid),
    {next_state, State, Data#{monitors => maps:put(Pid, MRef, Mons)}, Actions}.

%% register_bind/5
register_bind(Pid, MRef, State, #{contexts := CtxS} = Data, Actions) ->
    update_contexts(State, Data, maps:put(Pid, MRef, CtxS), Actions).

%% register_bind/4
register_bind(Pid, State, #{monitors := Mons} = Data, Actions)
  when is_map_key(Pid, Mons)  ->
    ?LOG(debug, "~s: register(~p)", [?MODULE, Pid]),
    MRef = maps:get(Pid, Mons),
    register_bind(Pid, MRef, State, Data#{monitors => maps:remove(Pid, Mons)}, Actions);
register_bind(Pid, State, #{contexts := CtxS} = Data, Actions)
  when is_map_key(Pid, CtxS) ->
    {next_state, State, Data, Actions};
register_bind(Pid, State, Data, Actions) ->
    ?LOG(debug, "~s: register(~p)", [?MODULE, Pid]),
    MRef = erlang:monitor(process, Pid),
    register_bind(Pid, MRef, State, Data, Actions).

unregister(Pid, State, #{contexts := CtxS} = Data, Actions)
  when is_map_key(Pid, CtxS) ->
    MRef = maps:get(Pid, CtxS),
    erlang:demonitor(MRef, [flush]),
    update_contexts(State, Data, maps:remove(Pid, CtxS), Actions);
unregister(Pid, State, #{monitors := Mons} = Data, Actions)
  when is_map_key(Pid, Mons) ->
    MRef = maps:get(Pid, Mons),
    erlang:demonitor(MRef, [flush]),
    {next_state, State, Data#{monitors => maps:remove(Pid, Mons)}, Actions};
unregister(_Pid, _, _Data, Actions) ->
    {keep_state_and_data, Actions}.

bind_path(#gtp{version = Version}, Tunnel) ->
    bind_path(Tunnel#tunnel{version = Version}).

bind_path(#tunnel{socket = Socket, version = Version,
		  remote = #fq_teid{ip = RemoteCntlIP}} = Tunnel) ->
    Path = maybe_new_path(Socket, Version, RemoteCntlIP),
    Tunnel#tunnel{path = Path}.

monitor_path_recovery(#tunnel{path = Path} = Tunnel) ->
    {ok, PathRestartCounter} = gen_statem:call(Path, {monitor, self()}),
    Tunnel#tunnel{remote_restart_counter = PathRestartCounter}.

bind_path_recovery(RestartCounter, #tunnel{path = Path} = Tunnel)
  when is_integer(RestartCounter) ->
    %% TBD: bind could return `old` for request that "race" with a restart
    _ = gen_statem:call(Path, {bind, self(), RestartCounter}),
    Tunnel#tunnel{remote_restart_counter = RestartCounter};
bind_path_recovery(_RestartCounter, #tunnel{path = Path} = Tunnel) ->
    {ok, PathRestartCounter} = gen_statem:call(Path, {bind, self()}),
    Tunnel#tunnel{remote_restart_counter = PathRestartCounter}.

send_echo_request(State, #{socket := Socket, handler := Handler, ip := DstIP,
			   t3 := T3, n3 := N3}) ->
    Msg = Handler:build_echo_request(),
    Ref = erlang:make_ref(),
    CbInfo = {?MODULE, handle_response, [self(), echo_request, Ref]},
    ergw_gtp_c_socket:send_request(Socket, any, DstIP, ?GTP1c_PORT, T3, N3, Msg, CbInfo),
    State#state{echo = Ref}.

ring_path_restart(RestartCounter, #{reg_key := Key}) ->
    {ok, Ring} = riak_core_ring_manager:get_my_ring(),
    erpc:multicast(riak_core_ring:all_members(Ring),
		   ?MODULE, path_restart, [Key, RestartCounter]).

path_restart(RestartCounter, State, #{contexts := CtxS} = Data) ->
    Path = self(),
    ResF =
	fun() ->
		foreach_context(maps:next(maps:iterator(CtxS)),
				gtp_context:path_restart(_, Path))
	end,
    proc_lib:spawn(ResF),
    update_contexts(State#state{recovery = RestartCounter}, Data, #{}, []).
