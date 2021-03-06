%% Copyright 2015, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_v1_c).

-behaviour(gtp_protocol).

%% API
-export([gtp_msg_type/1,
	 get_handler/2,
	 build_response/1,
	 build_echo_request/0,
	 validate_teid/2,
	 type/0, port/0,
	 get_context_id/1, update_context_id/2,
	 get_cause/1, get_common_flags/1,
	 find_sender_teid/1,
	 load_class/1]).

%% support functions
-export([build_recovery/4]).

-include_lib("gtplib/include/gtp_packet.hrl").
-include("include/ergw.hrl").

-define('Cause',					{cause, 0}).
-define('Recovery',					{recovery, 0}).
-define('Access Point Name',				{access_point_name, 0}).
-define('IMSI',						{international_mobile_subscriber_identity, 0}).
-define('IMEI',						{imei, 0}).
-define('NSAPI',					{nsapi, 0}).
-define('Common Flags',                                 {common_flags, 0}).
-define('Extended Common Flags',			{extended_common_flags, 0}).

%%====================================================================
%% API
%%====================================================================

%% build_recovery/4
%%
%% At least one GGSN implementation is brain dead enough to
%% ignore TS 29.060, Section 11.1.1 and reject messages with an
%% unexpected but otherwise correct (Recovery) IE.
%% Make sure that only message that are explicitely expected to
%% contain a Recovery IE to have one.
%%
build_recovery(Cmd, TnlOrSock, NewPeer, IEs)
  when
      %% Path Management Messages
      %% Cmd =:= echo_request;
      Cmd =:= echo_response;
      %% Tunnel Management Messages
      Cmd =:= create_pdp_context_request;
      Cmd =:= create_pdp_context_response;
      Cmd =:= update_pdp_context_request;
      Cmd =:= update_pdp_context_response;
      %% MBMS Messages
      Cmd =:= create_mbms_context_request;
      Cmd =:= create_mbms_context_response;
      Cmd =:= update_mbms_context_request;
      Cmd =:= update_mbms_context_response;
      Cmd =:= delete_mbms_context_request;
      Cmd =:= delete_mbms_context_response;
      Cmd =:= mbms_session_start_request;
      Cmd =:= mbms_session_start_response ->
    build_recovery(TnlOrSock, NewPeer, IEs);
build_recovery(_Cmd, _TnlOrSock, _NewPeer, IEs) ->
    IEs.

%% build_recovery/3
build_recovery(#socket{}, NewPeer, IEs) when NewPeer == true ->
    add_recovery(IEs);
build_recovery(#tunnel{remote_restart_counter = RemoteRestartCounter}, NewPeer, IEs)
  when NewPeer == true orelse
       RemoteRestartCounter == undefined ->
    add_recovery(IEs);
build_recovery(_, _, IEs) ->
    IEs.

type() -> 'gtp-c'.
port() -> ?GTP1c_PORT.

build_echo_request() ->
    #gtp{version = v1, type = echo_request, tei = 0, ie = []}.

build_response({Type, TEI, IEs}) ->
    #gtp{version = v1, type = gtp_msg_response(Type), tei = TEI, ie = map_reply_ies(IEs)};
build_response({Type, IEs}) ->
    #gtp{version = v1, type = gtp_msg_response(Type), tei = 0, ie = map_reply_ies(IEs)}.

gtp_msg_type(echo_request)					-> request;
gtp_msg_type(echo_response)					-> response;
gtp_msg_type(version_not_supported)				-> other;
gtp_msg_type(node_alive_request)				-> request;
gtp_msg_type(node_alive_response)				-> response;
gtp_msg_type(redirection_request)				-> request;
gtp_msg_type(redirection_response)				-> response;
gtp_msg_type(create_pdp_context_request)			-> request;
gtp_msg_type(create_pdp_context_response)			-> response;
gtp_msg_type(update_pdp_context_request)			-> request;
gtp_msg_type(update_pdp_context_response)			-> response;
gtp_msg_type(delete_pdp_context_request)			-> request;
gtp_msg_type(delete_pdp_context_response)			-> response;
gtp_msg_type(initiate_pdp_context_activation_request)		-> request;
gtp_msg_type(initiate_pdp_context_activation_response)		-> response;
gtp_msg_type(error_indication)					-> other;
gtp_msg_type(pdu_notification_request)				-> request;
gtp_msg_type(pdu_notification_response)				-> response;
gtp_msg_type(pdu_notification_reject_request)			-> request;
gtp_msg_type(pdu_notification_reject_response)			-> response;
gtp_msg_type(supported_extension_headers_notification)		-> other;
gtp_msg_type(send_routeing_information_for_gprs_request)	-> request;
gtp_msg_type(send_routeing_information_for_gprs_response)	-> response;
gtp_msg_type(failure_report_request)				-> request;
gtp_msg_type(failure_report_response)				-> response;
gtp_msg_type(note_ms_gprs_present_request)			-> request;
gtp_msg_type(note_ms_gprs_present_response)			-> response;
gtp_msg_type(identification_request)				-> request;
gtp_msg_type(identification_response)				-> response;
gtp_msg_type(sgsn_context_request)				-> request;
gtp_msg_type(sgsn_context_response)				-> response;
gtp_msg_type(sgsn_context_acknowledge)				-> other;
gtp_msg_type(forward_relocation_request)			-> request;
gtp_msg_type(forward_relocation_response)			-> response;
gtp_msg_type(forward_relocation_complete)			-> other;
gtp_msg_type(relocation_cancel_request)				-> request;
gtp_msg_type(relocation_cancel_response)			-> response;
gtp_msg_type(forward_srns_context)				-> other;
gtp_msg_type(forward_relocation_complete_acknowledge)		-> other;
gtp_msg_type(forward_srns_context_acknowledge)			-> other;
gtp_msg_type(ran_information_relay)				-> other;
gtp_msg_type(mbms_notification_request)				-> request;
gtp_msg_type(mbms_notification_response)			-> response;
gtp_msg_type(mbms_notification_reject_request)			-> request;
gtp_msg_type(mbms_notification_reject_response)			-> response;
gtp_msg_type(create_mbms_context_request)			-> request;
gtp_msg_type(create_mbms_context_response)			-> response;
gtp_msg_type(update_mbms_context_request)			-> request;
gtp_msg_type(update_mbms_context_response)			-> response;
gtp_msg_type(delete_mbms_context_request)			-> request;
gtp_msg_type(delete_mbms_context_response)			-> response;
gtp_msg_type(mbms_registration_request)				-> request;
gtp_msg_type(mbms_registration_response)			-> response;
gtp_msg_type(mbms_de_registration_request)			-> request;
gtp_msg_type(mbms_de_registration_response)			-> response;
gtp_msg_type(mbms_session_start_request)			-> request;
gtp_msg_type(mbms_session_start_response)			-> response;
gtp_msg_type(mbms_session_stop_request)				-> request;
gtp_msg_type(mbms_session_stop_response)			-> response;
gtp_msg_type(mbms_session_update_request)			-> request;
gtp_msg_type(mbms_session_update_response)			-> response;
gtp_msg_type(ms_info_change_notification_request)		-> request;
gtp_msg_type(ms_info_change_notification_response)		-> response;
gtp_msg_type(data_record_transfer_request)			-> request;
gtp_msg_type(data_record_transfer_response)			-> response;
gtp_msg_type(_)							-> other.

gtp_msg_response(echo_request)					-> echo_response;
gtp_msg_response(node_alive_request)				-> node_alive_response;
gtp_msg_response(redirection_request)				-> redirection_response;
gtp_msg_response(create_pdp_context_request)			-> create_pdp_context_response;
gtp_msg_response(update_pdp_context_request)			-> update_pdp_context_response;
gtp_msg_response(delete_pdp_context_request)			-> delete_pdp_context_response;
gtp_msg_response(initiate_pdp_context_activation_request)	-> initiate_pdp_context_activation_response;
gtp_msg_response(pdu_notification_request)			-> pdu_notification_response;
gtp_msg_response(pdu_notification_reject_request)		-> pdu_notification_reject_response;
gtp_msg_response(send_routeing_information_for_gprs_request)	-> send_routeing_information_for_gprs_response;
gtp_msg_response(failure_report_request)			-> failure_report_response;
gtp_msg_response(note_ms_gprs_present_request)			-> note_ms_gprs_present_response;
gtp_msg_response(identification_request)			-> identification_response;
gtp_msg_response(sgsn_context_request)				-> sgsn_context_response;
gtp_msg_response(forward_relocation_request)			-> forward_relocation_response;
gtp_msg_response(relocation_cancel_request)			-> relocation_cancel_response;
gtp_msg_response(mbms_notification_request)			-> mbms_notification_response;
gtp_msg_response(mbms_notification_reject_request)		-> mbms_notification_reject_response;
gtp_msg_response(create_mbms_context_request)			-> create_mbms_context_response;
gtp_msg_response(update_mbms_context_request)			-> update_mbms_context_response;
gtp_msg_response(delete_mbms_context_request)			-> delete_mbms_context_response;
gtp_msg_response(mbms_registration_request)			-> mbms_registration_response;
gtp_msg_response(mbms_de_registration_request)			-> mbms_de_registration_response;
gtp_msg_response(mbms_session_start_request)			-> mbms_session_start_response;
gtp_msg_response(mbms_session_stop_request)			-> mbms_session_stop_response;
gtp_msg_response(mbms_session_update_request)			-> mbms_session_update_response;
gtp_msg_response(ms_info_change_notification_request)		-> ms_info_change_notification_response;
gtp_msg_response(data_record_transfer_request)			-> data_record_transfer_response;
gtp_msg_response(Response)					-> Response.

get_handler(#socket{name = SocketName}, _Msg) ->
    ergw_core:handler(SocketName, gn);
get_handler(_Socket, _Msg) ->
    {error, {mandatory_ie_missing, ?'Access Point Name'}}.

validate_teid(MsgType, 0)
 when MsgType =:= create_pdp_context_request;
      MsgType =:= create_mbms_context_request;
      MsgType =:= identification_request;
      MsgType =:= sgsn_context_request;
      MsgType =:= echo_request;
      MsgType =:= forward_relocation_request;
      MsgType =:= pdu_notification_request;
      MsgType =:= mbms_notification_request;
      MsgType =:= relocation_cancel_request;
      MsgType =:= mbms_registration_request;
      MsgType =:= mbms_session_start_request;
      MsgType =:= ms_info_change_notification_request ->
    ok;
validate_teid(MsgType, 0) ->
    case gtp_msg_type(MsgType) of
	request ->
	    throw({error, not_found});
	_ ->
	    ok
    end;
validate_teid(_MsgType, _TEID) ->
    ok.


get_element(Key, IEs, Pos, Default) ->
    case maps:find(Key, IEs) of
	{ok, Rec} ->
	    element(Pos, Rec);
	_ ->
	    Default
    end.

get_common_flags(IEs) ->
    get_element(?'Common Flags', IEs, #common_flags.flags, []).

get_ext_common_flags(IEs) ->
    get_element(?'Extended Common Flags', IEs, #extended_common_flags.flags, []).

get_context_id(#gtp{version = v1, ie = IEs}) ->
    NSAPI = get_element(?'NSAPI', IEs, #nsapi.nsapi, '_'),
    UIMSI = proplists:get_bool('Unauthenticated IMSI', get_ext_common_flags(IEs)),
    %% order of key selection, first match terminates:
    %%   1. prefer IMEI if unauthenticated IMSI
    %%   2. use IMSI
    %%   3. use IMEI
    case {UIMSI, IEs} of
	{true, #{?'IMEI' := #imei{imei = IMEI}}} ->
	    {imei, IMEI, NSAPI};
	{_, #{?'IMSI' := #international_mobile_subscriber_identity{imsi = IMSI}}} ->
	    {imsi, IMSI, NSAPI};
	{_, #{?'IMEI' := #imei{imei = IMEI}}} ->
	    {imei, IMEI, NSAPI};
	_ ->
	    undefined
    end.

update_context_id(Msg, Context) ->
    case get_context_id(Msg) of
	{_, _, NSAPI} = Id when is_integer(NSAPI) ->
	    Context#context{context_id = Id};
	_ ->
	    Context
    end.

get_cause(#{?Cause := #cause{value = Cause}}) ->
    Cause;
get_cause(_) ->
    undefined.

load_class(#gtp{type = Type})
  when Type =:= create_pdp_context_request;
       Type =:= create_mbms_context_request ->
    create;
load_class(#gtp{type = Type})
  when Type =:= delete_pdp_context_request;
       Type =:= delete_mbms_context_request ->
    delete;
load_class(#gtp{type = g_pdu}) ->
    data;
load_class(_) ->
    other.

find_sender_teid(#gtp{
		    ie = #{{tunnel_endpoint_identifier_control_plane,0} :=
			       #tunnel_endpoint_identifier_control_plane{tei = TEID}}}) ->
    TEID;
find_sender_teid(_) ->
    undefined.

%%%===================================================================
%%% Internal functions
%%%===================================================================

add_ie(_Key, IE, IEs) when is_list(IEs) -> [IE|IEs];
add_ie(Key, IE, IEs) when is_map(IEs) -> maps:put(Key, IE, IEs).

add_recovery(IEs) ->
    RCnt = gtp_config:get_restart_counter(),
    add_ie('Recovery', #recovery{restart_counter = RCnt}, IEs).

map_reply_ies(IEs) when is_list(IEs) ->
    [map_reply_ie(IE) || IE <- IEs];
map_reply_ies(IEs) when is_map(IEs) ->
    maps:map(fun(_K, IE) -> map_reply_ie(IE) end, IEs);
map_reply_ies(IE) ->
    [map_reply_ie(IE)].

map_reply_ie(request_accepted) ->
    #cause{value = request_accepted};
map_reply_ie(not_found) ->
    #cause{value = non_existent};
map_reply_ie({mandatory_ie_missing, _}) ->
    #cause{value = mandatory_ie_missing};
map_reply_ie(system_failure) ->
    #cause{value = system_failure};
map_reply_ie(missing_or_unknown_apn) ->
    #cause{value = missing_or_unknown_apn};
map_reply_ie(no_resources_available) ->
    #cause{value = no_resources_available};
map_reply_ie(rejected) ->
    #cause{value = no_resources_available};
map_reply_ie(all_dynamic_addresses_are_occupied) ->
    #cause{value = all_dynamic_pdp_addresses_are_occupied};
map_reply_ie(all_dynamic_pdp_addresses_are_occupied) ->
    #cause{value = all_dynamic_pdp_addresses_are_occupied};
map_reply_ie(new_pdn_type_due_to_network_preference) ->
    #cause{value = new_pdp_type_due_to_network_preference};
map_reply_ie(new_pdn_type_due_to_single_address_bearer_only) ->
    #cause{value = new_pdp_type_due_to_single_address_bearer_only};
map_reply_ie(preferred_pdn_type_not_supported) ->
    #cause{value = unknown_pdp_address_or_pdp_type};
map_reply_ie(user_authentication_failed) ->
    #cause{value = user_authentication_failed};
map_reply_ie(IE)
  when is_tuple(IE) ->
    IE.
