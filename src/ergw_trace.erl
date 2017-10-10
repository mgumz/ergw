%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(ergw_trace).

-behaviour(gen_event).

%% API
-export([start_link/0, add_handler/1, trace/1, start_tracer/1]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2,
	 handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {file}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_event:start_link({local, ?SERVER}).

add_handler(File) ->
    gen_event:add_handler(?SERVER, ?MODULE, [File]).

start_tracer(Config) ->
    lager:debug("TRACE: ~p", [proplists:get_value('trace-file', Config)]),
    case proplists:get_value('trace-file', Config) of
	undefined ->
	    ok;
	File ->
	    R = ergw_sup:start_tracer(File),
	    lager:debug("TRACE: ~p", [R]),
	    ok
    end.

trace(Packet) ->
    case whereis(?SERVER) of
	Pid when is_pid(Pid) ->
	    gen_event:notify(?SERVER, {trace, Packet});
	_ ->
	    ok
    end.

%%%===================================================================
%%% gen_event callbacks
%%%===================================================================

init([File]) ->
    lager:debug("Starting TRACE handler"),
    case filelib:ensure_dir(filename:dirname(File)) of
	ok ->
	    case file:open(File, [write, raw]) of
		{ok, Io} ->
		    Header = << (pcapng_shb())/binary, (pcapng_ifd(<<"ERGW">>))/binary >>,
		    file:write(Io, Header),
		    {ok, #state{file = Io}};
		{error, _} = Other ->
		    lager:error("Starting TRACE handler failed with ~p", [Other]),
		    Other
	    end;
	{error, _} = Other ->
	    lager:error("Starting TRACE handler failed with ~p", [Other]),
	    Other
    end.

handle_event({trace, Packet},
	     #state{file = Io} = State) ->
    Dump = format_pcapng(Packet),
    file:write(Io, Dump),
    {ok, State};
handle_event(_Event, State) ->
    lager:error("TRACE handler: ~p", [_Event]),
    {ok, State}.

handle_call(_Request, State) ->
    Reply = ok,
    {ok, Reply, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Reason, #state{file = Io}) ->
    file:close(Io),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-define(PCAPNG_VERSION_MAJOR, 1).
-define(PCAPNG_VERSION_MINOR, 0).
-define(LINKTYPE_ETHERNET, 1).
-define(LINKTYPE_RAW, 101).

format_pcapng(Msg) ->
    TStamp = os:system_time(micro_seconds),
    Len = size(Msg),
    pcapng:encode({epb, 0, TStamp, Len, [], Msg}).

pcapng_shb() ->
    pcapng:encode({shb, {?PCAPNG_VERSION_MAJOR, ?PCAPNG_VERSION_MINOR},
                   [{os, <<"CAROS">>}, {userappl, <<"ERGW">>}]}).

pcapng_ifd(Name) ->
    pcapng:encode({ifd, ?LINKTYPE_ETHERNET, 65535,
                   [{name,    Name},
                    {tsresol, <<6>>},
                    {os,      <<"CAROS">>}]}).
