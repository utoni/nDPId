#!/usr/bin/env sh

RRDDIR="${1}"
OUTDIR="${2}"
RRDARGS="--width=800 --height=400"

if [ -z "${RRDDIR}" ]; then
	printf '%s: Missing RRD directory which contains nDPIsrvd/Collectd files.\n' "${0}"
	exit 1
fi

if [ -z "${OUTDIR}" ]; then
	printf '%s: Missing Output directory which contains HTML files.\n' "${0}"
	exit 1
fi

if [ $(ls -al ${RRDDIR}/gauge-flow_*.rrd | wc -l) -ne 105 ]; then
	printf '%s: Missing some *.rrd files.\n' "${0}"
	exit 1
fi

if [ ! -r "${OUTDIR}/index.html" -o ! -r "${OUTDIR}/flows.html" -o ! -r "${OUTDIR}/other.html" -o ! -r "${OUTDIR}/detections.html" -o ! -r "${OUTDIR}/categories.html" ]; then
	printf '%s: Missing some *.html files.\n' "${0}"
	exit 1
fi

TIME_PAST_HOUR="--start=-3600 --end=-0"
TIME_PAST_12HOURS="--start=-43200 --end=-0"
TIME_PAST_DAY="--start=-86400 --end=-0"
TIME_PAST_WEEK="--start=-604800 --end=-0"
TIME_PAST_MONTH="--start=-2419200 --end=-0"
TIME_PAST_3MONTHS="--start=-8035200 --end=-0"
TIME_PAST_YEAR="--start=-31536000 --end=-0"

rrdtool_graph_colorize_missing_data() {
	printf 'CDEF:offline=%s,UN,INF,* AREA:offline#B3B3B311:' "${1}"
}

rrdtool_graph_print_cur_min_max_avg() {
	printf 'GPRINT:%s:LAST:Current\:%%8.2lf ' "${1}"
	printf 'GPRINT:%s:MIN:Minimum\:%%8.2lf ' "${1}"
	printf 'GPRINT:%s:MAX:Maximum\:%%8.2lf ' "${1}"
	printf 'GPRINT:%s:AVERAGE:Average\:%%8.2lf\\n' "${1}"
}

rrdtool_graph() {
	TITLE="${1}"
	shift
	YAXIS_NAME="${1}"
	shift
	OUTPNG="${1}"
	shift

	rrdtool graph ${RRDARGS} -t "${TITLE} (past hour)"     -v ${YAXIS_NAME} -Y ${TIME_PAST_HOUR}    "${OUTPNG}_past_hour.png"    ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past 12 hours)" -v ${YAXIS_NAME} -Y ${TIME_PAST_12HOURS} "${OUTPNG}_past_12hours.png" ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past day)"      -v ${YAXIS_NAME} -Y ${TIME_PAST_DAY}     "${OUTPNG}_past_day.png"     ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past week)"     -v ${YAXIS_NAME} -Y ${TIME_PAST_WEEK}    "${OUTPNG}_past_week.png"    ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past month)"    -v ${YAXIS_NAME} -Y ${TIME_PAST_MONTH}   "${OUTPNG}_past_month.png"   ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past 3 months)" -v ${YAXIS_NAME} -Y ${TIME_PAST_3MONTHS} "${OUTPNG}_past_month.png"   ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past year)"     -v ${YAXIS_NAME} -Y ${TIME_PAST_YEAR}    "${OUTPNG}_past_year.png"    ${*}
}

rrdtool_graph Flows Amount "${OUTDIR}/flows" \
	DEF:flows_new=${RRDDIR}/gauge-flow_new_count.rrd:value:AVERAGE \
        DEF:flows_end=${RRDDIR}/gauge-flow_end_count.rrd:value:AVERAGE \
        DEF:flows_idle=${RRDDIR}/gauge-flow_idle_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data flows_new) \
	AREA:flows_new#54EC48::STACK \
	AREA:flows_end#ECD748::STACK \
	AREA:flows_idle#EC9D48::STACK \
        LINE2:flows_new#24BC14:"New." \
	$(rrdtool_graph_print_cur_min_max_avg flows_new) \
        LINE2:flows_end#C9B215:"End." \
	$(rrdtool_graph_print_cur_min_max_avg flows_end) \
        LINE2:flows_idle#CC7016:"Idle" \
	$(rrdtool_graph_print_cur_min_max_avg flows_idle)
rrdtool_graph Detections Amount "${OUTDIR}/detections" \
	DEF:flows_detected=${RRDDIR}/gauge-flow_detected_count.rrd:value:AVERAGE \
	DEF:flows_guessed=${RRDDIR}/gauge-flow_guessed_count.rrd:value:AVERAGE \
	DEF:flows_not_detected=${RRDDIR}/gauge-flow_not_detected_count.rrd:value:AVERAGE \
	DEF:flows_detection_update=${RRDDIR}/gauge-flow_detection_update_count.rrd:value:AVERAGE \
	DEF:flows_risky=${RRDDIR}/gauge-flow_risky_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data flows_detected) \
	AREA:flows_detected#00bfff::STACK \
	AREA:flows_detection_update#a1b8c4::STACK \
	AREA:flows_guessed#ffff4d::STACK \
	AREA:flows_not_detected#ffa64d::STACK \
	AREA:flows_risky#ff4000::STACK \
	LINE2:flows_detected#0000ff:"Detected........" \
	$(rrdtool_graph_print_cur_min_max_avg flows_detected) \
	LINE2:flows_guessed#cccc00:"Guessed........." \
	$(rrdtool_graph_print_cur_min_max_avg flows_guessed) \
	LINE2:flows_not_detected#ff8000:"Not-Detected...." \
	$(rrdtool_graph_print_cur_min_max_avg flows_not_detected) \
	LINE2:flows_detection_update#4f6e7d:"Detection-Update" \
	$(rrdtool_graph_print_cur_min_max_avg flows_detection_update) \
	LINE2:flows_risky#b32d00:"Risky..........." \
	$(rrdtool_graph_print_cur_min_max_avg flows_risky)
rrdtool_graph "Traffic (IN/OUT)" Bytes "${OUTDIR}/traffic" \
	DEF:total_src_bytes=${RRDDIR}/gauge-flow_src_total_bytes.rrd:value:AVERAGE \
	DEF:total_dst_bytes=${RRDDIR}/gauge-flow_dst_total_bytes.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data total_src_bytes) \
	AREA:total_src_bytes#00cc99:"Total-Bytes-Source2Dest":STACK \
	$(rrdtool_graph_print_cur_min_max_avg total_src_bytes) \
	STACK:total_dst_bytes#669999:"Total-Bytes-Dest2Source" \
	$(rrdtool_graph_print_cur_min_max_avg total_dst_bytes)
rrdtool_graph Layer3-Flows Amount "${OUTDIR}/layer3" \
        DEF:layer3_ip4=${RRDDIR}/gauge-flow_l3_ip4_count.rrd:value:AVERAGE \
	DEF:layer3_ip6=${RRDDIR}/gauge-flow_l3_ip6_count.rrd:value:AVERAGE \
	DEF:layer3_other=${RRDDIR}/gauge-flow_l3_other_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data layer3_ip4) \
	AREA:layer3_ip4#73d97d::STACK \
	AREA:layer3_ip6#66b3ff::STACK \
	AREA:layer3_other#bea1c4::STACK \
        LINE2:layer3_ip4#21772a:"IPv4." \
	$(rrdtool_graph_print_cur_min_max_avg layer3_ip4) \
	LINE2:layer3_ip6#0066cc:"IPv6." \
	$(rrdtool_graph_print_cur_min_max_avg layer3_ip6) \
	LINE2:layer3_other#92629d:"Other" \
	$(rrdtool_graph_print_cur_min_max_avg layer3_other)
rrdtool_graph Layer4-Flows Amount "${OUTDIR}/layer4" \
        DEF:layer4_tcp=${RRDDIR}/gauge-flow_l4_tcp_count.rrd:value:AVERAGE \
        DEF:layer4_udp=${RRDDIR}/gauge-flow_l4_udp_count.rrd:value:AVERAGE \
        DEF:layer4_icmp=${RRDDIR}/gauge-flow_l4_icmp_count.rrd:value:AVERAGE \
	DEF:layer4_other=${RRDDIR}/gauge-flow_l4_other_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data layer4_tcp) \
	AREA:layer4_tcp#73d97d::STACK \
	AREA:layer4_udp#66b3ff::STACK \
	AREA:layer4_icmp#ee5d9a::STACK \
	AREA:layer4_other#bea1c4::STACK \
        LINE2:layer4_tcp#21772a:"TCP.." \
	$(rrdtool_graph_print_cur_min_max_avg layer4_tcp) \
        LINE2:layer4_udp#0066cc:"UDP.." \
	$(rrdtool_graph_print_cur_min_max_avg layer4_udp) \
        LINE2:layer4_icmp#d01663:"ICMP." \
	$(rrdtool_graph_print_cur_min_max_avg layer4_icmp) \
	LINE2:layer4_other#83588d:"Other" \
	$(rrdtool_graph_print_cur_min_max_avg layer4_other)
rrdtool_graph Flow-Breeds Amount "${OUTDIR}/breed" \
	DEF:breed_safe=${RRDDIR}/gauge-flow_breed_safe_count.rrd:value:AVERAGE \
	DEF:breed_acceptable=${RRDDIR}/gauge-flow_breed_acceptable_count.rrd:value:AVERAGE \
	DEF:breed_fun=${RRDDIR}/gauge-flow_breed_fun_count.rrd:value:AVERAGE \
	DEF:breed_unsafe=${RRDDIR}/gauge-flow_breed_unsafe_count.rrd:value:AVERAGE \
	DEF:breed_potentially_dangerous=${RRDDIR}/gauge-flow_breed_potentially_dangerous_count.rrd:value:AVERAGE \
	DEF:breed_dangerous=${RRDDIR}/gauge-flow_breed_dangerous_count.rrd:value:AVERAGE \
	DEF:breed_unrated=${RRDDIR}/gauge-flow_breed_unrated_count.rrd:value:AVERAGE \
	DEF:breed_unknown=${RRDDIR}/gauge-flow_breed_unknown_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data breed_safe) \
	AREA:breed_safe#4dff4d::STACK \
	AREA:breed_acceptable#c2ff33::STACK \
	AREA:breed_fun#ffe433::STACK \
	AREA:breed_unsafe#ffb133::STACK \
	AREA:breed_potentially_dangerous#ff5f33::STACK \
	AREA:breed_dangerous#e74b5b::STACK \
	AREA:breed_unrated#a5aca0::STACK \
	AREA:breed_unknown#d7c1cc::STACK \
	LINE2:breed_safe#00e600:"Safe................." \
	$(rrdtool_graph_print_cur_min_max_avg breed_safe) \
	LINE2:breed_acceptable#8fce00:"Acceptable..........." \
	$(rrdtool_graph_print_cur_min_max_avg breed_acceptable) \
	LINE2:breed_fun#e6c700:"Fun.................." \
	$(rrdtool_graph_print_cur_min_max_avg breed_fun) \
	LINE2:breed_unsafe#e68e00:"Unsafe..............." \
	$(rrdtool_graph_print_cur_min_max_avg breed_unsafe) \
	LINE2:breed_potentially_dangerous#e63200:"Potentially-Dangerous" \
	$(rrdtool_graph_print_cur_min_max_avg breed_potentially_dangerous) \
	LINE2:breed_dangerous#c61b2b:"Dangerous............" \
	$(rrdtool_graph_print_cur_min_max_avg breed_dangerous) \
	LINE2:breed_unrated#7e8877:"Unrated.............." \
	$(rrdtool_graph_print_cur_min_max_avg breed_unrated) \
	LINE2:breed_unknown#ae849a:"Unknown.............." \
	$(rrdtool_graph_print_cur_min_max_avg breed_unknown)
rrdtool_graph Flow-Categories 'Amount(SUM)' "${OUTDIR}/categories" \
	DEF:cat_ads=${RRDDIR}/gauge-flow_category_advertisment_count.rrd:value:AVERAGE \
	DEF:cat_chat=${RRDDIR}/gauge-flow_category_chat_count.rrd:value:AVERAGE \
	DEF:cat_cloud=${RRDDIR}/gauge-flow_category_cloud_count.rrd:value:AVERAGE \
	DEF:cat_collab=${RRDDIR}/gauge-flow_category_collaborative_count.rrd:value:AVERAGE \
	DEF:cat_xfer=${RRDDIR}/gauge-flow_category_data_transfer_count.rrd:value:AVERAGE \
	DEF:cat_db=${RRDDIR}/gauge-flow_category_database_count.rrd:value:AVERAGE \
	DEF:cat_dl=${RRDDIR}/gauge-flow_category_download_count.rrd:value:AVERAGE \
	DEF:cat_mail=${RRDDIR}/gauge-flow_category_email_count.rrd:value:AVERAGE \
	DEF:cat_fs=${RRDDIR}/gauge-flow_category_file_sharing_count.rrd:value:AVERAGE \
	DEF:cat_game=${RRDDIR}/gauge-flow_category_game_count.rrd:value:AVERAGE \
	DEF:cat_mal=${RRDDIR}/gauge-flow_category_malware_count.rrd:value:AVERAGE \
	DEF:cat_med=${RRDDIR}/gauge-flow_category_media_count.rrd:value:AVERAGE \
	DEF:cat_min=${RRDDIR}/gauge-flow_category_mining_count.rrd:value:AVERAGE \
	DEF:cat_mus=${RRDDIR}/gauge-flow_category_music_count.rrd:value:AVERAGE \
	DEF:cat_net=${RRDDIR}/gauge-flow_category_network_count.rrd:value:AVERAGE \
	DEF:cat_prod=${RRDDIR}/gauge-flow_category_productivity_count.rrd:value:AVERAGE \
	DEF:cat_rem=${RRDDIR}/gauge-flow_category_remote_access_count.rrd:value:AVERAGE \
	DEF:cat_rpc=${RRDDIR}/gauge-flow_category_rpc_count.rrd:value:AVERAGE \
	DEF:cat_shop=${RRDDIR}/gauge-flow_category_shopping_count.rrd:value:AVERAGE \
	DEF:cat_soc=${RRDDIR}/gauge-flow_category_social_network_count.rrd:value:AVERAGE \
	DEF:cat_soft=${RRDDIR}/gauge-flow_category_software_update_count.rrd:value:AVERAGE \
	DEF:cat_str=${RRDDIR}/gauge-flow_category_streaming_count.rrd:value:AVERAGE \
	DEF:cat_sys=${RRDDIR}/gauge-flow_category_system_count.rrd:value:AVERAGE \
	DEF:cat_ukn=${RRDDIR}/gauge-flow_category_unknown_count.rrd:value:AVERAGE \
	DEF:cat_vid=${RRDDIR}/gauge-flow_category_video_count.rrd:value:AVERAGE \
	DEF:cat_voip=${RRDDIR}/gauge-flow_category_voip_count.rrd:value:AVERAGE \
	DEF:cat_vpn=${RRDDIR}/gauge-flow_category_vpn_count.rrd:value:AVERAGE \
	DEF:cat_web=${RRDDIR}/gauge-flow_category_web_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data cat_ads) \
	AREA:cat_ads#f1c232:"Advertisment..........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_ads) \
	STACK:cat_chat#6fa8dc:"Chat..................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_chat) \
	STACK:cat_cloud#2986cc:"Cloud.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_cloud) \
	STACK:cat_collab#3212aa:"Collaborative.........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_collab) \
	STACK:cat_xfer#16537e:"Data-Transfer.........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_xfer) \
	STACK:cat_db#cc0000:"Database..............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_db) \
	STACK:cat_dl#6a329f:"Download..............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_dl) \
	STACK:cat_mail#3600cc:"Mail..................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_mail) \
	STACK:cat_fs#c90076:"File-Sharing..........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_fs) \
	STACK:cat_game#00ff26:"Game..................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_game) \
	STACK:cat_mal#f44336:"Malware................" \
	$(rrdtool_graph_print_cur_min_max_avg cat_mal) \
	STACK:cat_med#ff8300:"Media.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_med) \
	STACK:cat_min#ff0000:"Mining................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_min) \
	STACK:cat_mus#00fff0:"Music.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_mus) \
	STACK:cat_net#ddff00:"Network................" \
	$(rrdtool_graph_print_cur_min_max_avg cat_net) \
	STACK:cat_prod#29ff00:"Productivity..........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_prod) \
	STACK:cat_rem#b52c2c:"Remote-Access.........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_rem) \
	STACK:cat_rpc#e15a5a:"Remote-Procedure-Call.." \
	$(rrdtool_graph_print_cur_min_max_avg cat_rpc) \
	STACK:cat_shop#0065ff:"Shopping..............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_shop) \
	STACK:cat_soc#8fce00:"Social-Network........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_soc) \
	STACK:cat_soft#007a0d:"Software-Update........" \
	$(rrdtool_graph_print_cur_min_max_avg cat_soft) \
	STACK:cat_str#ff00b8:"Streaming.............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_str) \
	STACK:cat_sys#f4ff00:"System................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_sys) \
	STACK:cat_ukn#999999:"Unknown................" \
	$(rrdtool_graph_print_cur_min_max_avg cat_ukn) \
	STACK:cat_vid#518820:"Video.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_vid) \
	STACK:cat_voip#ffc700:"Voice-Over-IP.........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_voip) \
	STACK:cat_vpn#378035:"Virtual-Private-Network" \
	$(rrdtool_graph_print_cur_min_max_avg cat_vpn) \
	STACK:cat_web#00fffb:"Web...................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_web)
rrdtool_graph JSON 'Lines' "${OUTDIR}/json_lines" \
	DEF:json_lines=${RRDDIR}/gauge-json_lines.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data json_lines) \
	AREA:json_lines#4dff4d::STACK \
	LINE2:json_lines#00e600:"JSON-lines" \
	$(rrdtool_graph_print_cur_min_max_avg json_lines)
rrdtool_graph JSON 'Bytes' "${OUTDIR}/json_bytes" \
	DEF:json_bytes=${RRDDIR}/gauge-json_bytes.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data json_bytes) \
	AREA:json_bytes#4dff4d::STACK \
	LINE2:json_bytes#00e600:"JSON-bytes" \
	$(rrdtool_graph_print_cur_min_max_avg json_bytes)
rrdtool_graph Events 'Amouunt' "${OUTDIR}/events" \
	DEF:init=${RRDDIR}/gauge-init_count.rrd:value:AVERAGE \
	DEF:reconnect=${RRDDIR}/gauge-reconnect_count.rrd:value:AVERAGE \
	DEF:shutdown=${RRDDIR}/gauge-shutdown_count.rrd:value:AVERAGE \
	DEF:status=${RRDDIR}/gauge-status_count.rrd:value:AVERAGE \
	DEF:packet=${RRDDIR}/gauge-packet_count.rrd:value:AVERAGE \
	DEF:packet_flow=${RRDDIR}/gauge-packet_flow_count.rrd:value:AVERAGE \
	DEF:new=${RRDDIR}/gauge-flow_new_count.rrd:value:AVERAGE \
	DEF:end=${RRDDIR}/gauge-flow_end_count.rrd:value:AVERAGE \
	DEF:idle=${RRDDIR}/gauge-flow_idle_count.rrd:value:AVERAGE \
	DEF:update=${RRDDIR}/gauge-flow_update_count.rrd:value:AVERAGE \
	DEF:detection_update=${RRDDIR}/gauge-flow_detection_update_count.rrd:value:AVERAGE \
	DEF:guessed=${RRDDIR}/gauge-flow_guessed_count.rrd:value:AVERAGE \
	DEF:detected=${RRDDIR}/gauge-flow_detected_count.rrd:value:AVERAGE \
	DEF:not_detected=${RRDDIR}/gauge-flow_not_detected_count.rrd:value:AVERAGE \
	DEF:analyse=${RRDDIR}/gauge-flow_analyse_count.rrd:value:AVERAGE \
	DEF:error=${RRDDIR}/gauge-error_count_sum.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data init) \
	AREA:init#f1c232:"Init..................." \
	$(rrdtool_graph_print_cur_min_max_avg init) \
	STACK:reconnect#63bad9:"Reconnect.............." \
	$(rrdtool_graph_print_cur_min_max_avg reconnect) \
	STACK:shutdown#3a6f82:"Shutdown..............." \
	$(rrdtool_graph_print_cur_min_max_avg shutdown) \
	STACK:status#b7cbd1:"Status................." \
	$(rrdtool_graph_print_cur_min_max_avg status) \
	STACK:packet#0aff3f:"Packet................." \
	$(rrdtool_graph_print_cur_min_max_avg packet) \
	STACK:packet_flow#00c72b:"Packet-Flow............" \
	$(rrdtool_graph_print_cur_min_max_avg packet_flow) \
	STACK:new#c76700:"New...................." \
	$(rrdtool_graph_print_cur_min_max_avg new) \
	STACK:end#c78500:"End...................." \
	$(rrdtool_graph_print_cur_min_max_avg end) \
	STACK:idle#c7a900:"Idle..................." \
	$(rrdtool_graph_print_cur_min_max_avg idle) \
	STACK:update#c7c400:"Updates................" \
	$(rrdtool_graph_print_cur_min_max_avg update) \
	STACK:detection_update#a2c700:"Detection-Updates......" \
	$(rrdtool_graph_print_cur_min_max_avg detection_update) \
	STACK:guessed#7bc700:"Guessed................" \
	$(rrdtool_graph_print_cur_min_max_avg guessed) \
	STACK:detected#00c781:"Detected..............." \
	$(rrdtool_graph_print_cur_min_max_avg detected) \
	STACK:not_detected#00bdc7:"Not-Detected..........." \
	$(rrdtool_graph_print_cur_min_max_avg not_detected) \
	STACK:analyse#1400c7:"Analyse................" \
	$(rrdtool_graph_print_cur_min_max_avg analyse) \
	STACK:error#c70000:"Error.................." \
	$(rrdtool_graph_print_cur_min_max_avg error)
rrdtool_graph Error-Events 'Amouunt' "${OUTDIR}/error_events" \
	DEF:error_0=${RRDDIR}/gauge-error_0_count.rrd:value:AVERAGE \
	DEF:error_1=${RRDDIR}/gauge-error_1_count.rrd:value:AVERAGE \
	DEF:error_2=${RRDDIR}/gauge-error_2_count.rrd:value:AVERAGE \
	DEF:error_3=${RRDDIR}/gauge-error_3_count.rrd:value:AVERAGE \
	DEF:error_4=${RRDDIR}/gauge-error_4_count.rrd:value:AVERAGE \
	DEF:error_5=${RRDDIR}/gauge-error_5_count.rrd:value:AVERAGE \
	DEF:error_6=${RRDDIR}/gauge-error_6_count.rrd:value:AVERAGE \
	DEF:error_7=${RRDDIR}/gauge-error_7_count.rrd:value:AVERAGE \
	DEF:error_8=${RRDDIR}/gauge-error_8_count.rrd:value:AVERAGE \
	DEF:error_9=${RRDDIR}/gauge-error_9_count.rrd:value:AVERAGE \
	DEF:error_10=${RRDDIR}/gauge-error_10_count.rrd:value:AVERAGE \
	DEF:error_11=${RRDDIR}/gauge-error_11_count.rrd:value:AVERAGE \
	DEF:error_12=${RRDDIR}/gauge-error_12_count.rrd:value:AVERAGE \
	DEF:error_13=${RRDDIR}/gauge-error_13_count.rrd:value:AVERAGE \
	DEF:error_14=${RRDDIR}/gauge-error_14_count.rrd:value:AVERAGE \
	DEF:error_15=${RRDDIR}/gauge-error_15_count.rrd:value:AVERAGE \
	DEF:error_16=${RRDDIR}/gauge-error_16_count.rrd:value:AVERAGE \
	DEF:error_unknown=${RRDDIR}/gauge-error_unknown_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data error_0) \
	AREA:error_0#ff6a00:"Unknown-datalink-layer-packet............................" \
	$(rrdtool_graph_print_cur_min_max_avg error_0) \
	STACK:error_1#bf7540:"Unknown-L3-protocol......................................" \
	$(rrdtool_graph_print_cur_min_max_avg error_1) \
	STACK:error_2#ffd500:"Unsupported-datalink-layer..............................." \
	$(rrdtool_graph_print_cur_min_max_avg error_2) \
	STACK:error_3#bfaa40:"Packet-too-short........................................." \
	$(rrdtool_graph_print_cur_min_max_avg error_3) \
	STACK:error_4#bfff00:"Unknown-packet-type......................................" \
	$(rrdtool_graph_print_cur_min_max_avg error_4) \
	STACK:error_5#9fbf40:"Packet-header-invalid...................................." \
	$(rrdtool_graph_print_cur_min_max_avg error_5) \
	STACK:error_6#55ff00:"IP4-packet-too-short....................................." \
	$(rrdtool_graph_print_cur_min_max_avg error_6) \
	STACK:error_7#6abf40:"Packet-smaller-than-IP4-header..........................." \
	$(rrdtool_graph_print_cur_min_max_avg error_7) \
	STACK:error_8#00ff15:"nDPI-IPv4/L4-payload-detection-failed...................." \
	$(rrdtool_graph_print_cur_min_max_avg error_8) \
	STACK:error_9#40bf4a:"IP6-packet-too-short....................................." \
	$(rrdtool_graph_print_cur_min_max_avg error_9) \
	STACK:error_10#00ff80:"Packet-smaller-than-IP6-header..........................." \
	$(rrdtool_graph_print_cur_min_max_avg error_10) \
	STACK:error_11#40bf80:"nDPI-IPv6/L4-payload-detection-failed...................." \
	$(rrdtool_graph_print_cur_min_max_avg error_11) \
	STACK:error_12#00ffea:"TCP-packet-smaller-than-expected........................." \
	$(rrdtool_graph_print_cur_min_max_avg error_12) \
	STACK:error_13#40bfb5:"UDP-packet-smaller-than-expected........................." \
	$(rrdtool_graph_print_cur_min_max_avg error_13) \
	STACK:error_14#00aaff:"Captured-packet-size-is-smaller-than-expected-packet-size" \
	$(rrdtool_graph_print_cur_min_max_avg error_14) \
	STACK:error_15#4095bf:"Max-flows-to-track-reached..............................." \
	$(rrdtool_graph_print_cur_min_max_avg error_15) \
	STACK:error_16#0040ff:"Flow-memory-allocation-failed............................" \
	$(rrdtool_graph_print_cur_min_max_avg error_16) \
	STACK:error_unknown#4060bf:"Unknown-error............................................" \
	$(rrdtool_graph_print_cur_min_max_avg error_unknown)
rrdtool_graph Risky-Events 'Amouunt' "${OUTDIR}/risky_events" \
	DEF:risk_0=${RRDDIR}/gauge-flow_risk_0_count.rrd:value:AVERAGE \
	DEF:risk_1=${RRDDIR}/gauge-flow_risk_1_count.rrd:value:AVERAGE \
	DEF:risk_2=${RRDDIR}/gauge-flow_risk_2_count.rrd:value:AVERAGE \
	DEF:risk_3=${RRDDIR}/gauge-flow_risk_3_count.rrd:value:AVERAGE \
	DEF:risk_4=${RRDDIR}/gauge-flow_risk_4_count.rrd:value:AVERAGE \
	DEF:risk_5=${RRDDIR}/gauge-flow_risk_5_count.rrd:value:AVERAGE \
	DEF:risk_6=${RRDDIR}/gauge-flow_risk_6_count.rrd:value:AVERAGE \
	DEF:risk_7=${RRDDIR}/gauge-flow_risk_7_count.rrd:value:AVERAGE \
	DEF:risk_8=${RRDDIR}/gauge-flow_risk_8_count.rrd:value:AVERAGE \
	DEF:risk_9=${RRDDIR}/gauge-flow_risk_9_count.rrd:value:AVERAGE \
	DEF:risk_10=${RRDDIR}/gauge-flow_risk_10_count.rrd:value:AVERAGE \
	DEF:risk_11=${RRDDIR}/gauge-flow_risk_11_count.rrd:value:AVERAGE \
	DEF:risk_12=${RRDDIR}/gauge-flow_risk_12_count.rrd:value:AVERAGE \
	DEF:risk_13=${RRDDIR}/gauge-flow_risk_13_count.rrd:value:AVERAGE \
	DEF:risk_14=${RRDDIR}/gauge-flow_risk_14_count.rrd:value:AVERAGE \
	DEF:risk_15=${RRDDIR}/gauge-flow_risk_15_count.rrd:value:AVERAGE \
	DEF:risk_16=${RRDDIR}/gauge-flow_risk_16_count.rrd:value:AVERAGE \
	DEF:risk_17=${RRDDIR}/gauge-flow_risk_17_count.rrd:value:AVERAGE \
	DEF:risk_18=${RRDDIR}/gauge-flow_risk_18_count.rrd:value:AVERAGE \
	DEF:risk_19=${RRDDIR}/gauge-flow_risk_19_count.rrd:value:AVERAGE \
	DEF:risk_20=${RRDDIR}/gauge-flow_risk_20_count.rrd:value:AVERAGE \
	DEF:risk_21=${RRDDIR}/gauge-flow_risk_21_count.rrd:value:AVERAGE \
	DEF:risk_22=${RRDDIR}/gauge-flow_risk_22_count.rrd:value:AVERAGE \
	DEF:risk_23=${RRDDIR}/gauge-flow_risk_23_count.rrd:value:AVERAGE \
	DEF:risk_24=${RRDDIR}/gauge-flow_risk_24_count.rrd:value:AVERAGE \
	DEF:risk_25=${RRDDIR}/gauge-flow_risk_25_count.rrd:value:AVERAGE \
	DEF:risk_26=${RRDDIR}/gauge-flow_risk_26_count.rrd:value:AVERAGE \
	DEF:risk_27=${RRDDIR}/gauge-flow_risk_27_count.rrd:value:AVERAGE \
	DEF:risk_28=${RRDDIR}/gauge-flow_risk_28_count.rrd:value:AVERAGE \
	DEF:risk_29=${RRDDIR}/gauge-flow_risk_29_count.rrd:value:AVERAGE \
	DEF:risk_30=${RRDDIR}/gauge-flow_risk_30_count.rrd:value:AVERAGE \
	DEF:risk_31=${RRDDIR}/gauge-flow_risk_31_count.rrd:value:AVERAGE \
	DEF:risk_32=${RRDDIR}/gauge-flow_risk_32_count.rrd:value:AVERAGE \
	DEF:risk_33=${RRDDIR}/gauge-flow_risk_33_count.rrd:value:AVERAGE \
	DEF:risk_34=${RRDDIR}/gauge-flow_risk_34_count.rrd:value:AVERAGE \
	DEF:risk_35=${RRDDIR}/gauge-flow_risk_35_count.rrd:value:AVERAGE \
	DEF:risk_36=${RRDDIR}/gauge-flow_risk_36_count.rrd:value:AVERAGE \
	DEF:risk_37=${RRDDIR}/gauge-flow_risk_37_count.rrd:value:AVERAGE \
	DEF:risk_38=${RRDDIR}/gauge-flow_risk_38_count.rrd:value:AVERAGE \
	DEF:risk_39=${RRDDIR}/gauge-flow_risk_39_count.rrd:value:AVERAGE \
	DEF:risk_40=${RRDDIR}/gauge-flow_risk_40_count.rrd:value:AVERAGE \
	DEF:risk_41=${RRDDIR}/gauge-flow_risk_41_count.rrd:value:AVERAGE \
	DEF:risk_42=${RRDDIR}/gauge-flow_risk_42_count.rrd:value:AVERAGE \
	DEF:risk_43=${RRDDIR}/gauge-flow_risk_43_count.rrd:value:AVERAGE \
	DEF:risk_44=${RRDDIR}/gauge-flow_risk_44_count.rrd:value:AVERAGE \
	DEF:risk_45=${RRDDIR}/gauge-flow_risk_45_count.rrd:value:AVERAGE \
	DEF:risk_46=${RRDDIR}/gauge-flow_risk_46_count.rrd:value:AVERAGE \
	DEF:risk_47=${RRDDIR}/gauge-flow_risk_47_count.rrd:value:AVERAGE \
	DEF:risk_unknown=${RRDDIR}/gauge-flow_risk_unknown_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data risk_0) \
	AREA:risk_0#ff0000:"XSS-Attack..............................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_1) \
	STACK:risk_1#ff5500:"SQL-Injection............................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_2) \
	STACK:risk_2#ffaa00:"RCE-Injection............................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_3) \
	STACK:risk_3#ffff00:"Binary-App-Transfer......................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_4) \
	STACK:risk_4#aaff00:"Known-Proto-on-Non-Std-Port.............................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_5) \
	STACK:risk_5#55ff00:"Self-signed-Cert........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_6) \
	STACK:risk_6#00ff55:"Obsolete-TLS-v1.1-or-older..............................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_7) \
	STACK:risk_7#00ffaa:"Weak-TLS-Cipher.........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_8) \
	STACK:risk_8#00ffff:"TLS-Cert-Expired........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_9) \
	STACK:risk_9#00aaff:"TLS-Cert-Mismatch........................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_10) \
	STACK:risk_10#0055ff:"HTTP-Suspicious-User-Agent..............................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_11) \
	STACK:risk_11#0000ff:"HTTP-Numeric-IP-Address.................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_12) \
	STACK:risk_12#5500ff:"HTTP-Suspicious-URL......................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_13) \
	STACK:risk_13#aa00ff:"HTTP-Suspicious-Header..................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_14) \
	STACK:risk_14#ff00ff:"TLS-probably-Not-Carrying-HTTPS.........................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_15) \
	STACK:risk_15#ff00aa:"Suspicious-DGA-Domain-name..............................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_16) \
	STACK:risk_16#ff0055:"Malformed-Packet........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_17) \
	STACK:risk_17#602020:"SSH-Obsolete-Client-Version/Cipher......................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_18) \
	STACK:risk_18#603a20:"SSH-Obsolete-Server-Version/Cipher......................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_19) \
	STACK:risk_19#605520:"SMB-Insecure-Version....................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_20) \
	STACK:risk_20#506020:"TLS-Suspicious-ESNI-Usage................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_21) \
	STACK:risk_21#356020:"Unsafe-Protocol.........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_22) \
	STACK:risk_22#206025:"Suspicious-DNS-Traffic..................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_23) \
	STACK:risk_23#206040:"Missing-SNI-TLS-Extension................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_24) \
	STACK:risk_24#20605a:"HTTP-Suspicious-Content.................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_25) \
	STACK:risk_25#204a60:"Risky-ASN................................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_26) \
	STACK:risk_26#203060:"Risky-Domain-Name........................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_27) \
	STACK:risk_27#2a2060:"Malicious-JA3-Fingerprint................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_28) \
	STACK:risk_28#452060:"Malicious-SSL-Cert/SHA1-Fingerprint......................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_29) \
	STACK:risk_29#602060:"Desktop/File-Sharing....................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_30) \
	STACK:risk_30#602045:"Uncommon-TLS-ALPN........................................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_31) \
	STACK:risk_31#df2020:"TLS-Cert-Validity-Too-Long..............................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_32) \
	STACK:risk_32#df6020:"TLS-Suspicious-Extension................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_33) \
	STACK:risk_33#df9f20:"TLS-Fatal-Alert.........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_34) \
	STACK:risk_34#dfdf20:"Suspicious-Entropy......................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_35) \
	STACK:risk_35#9fdf20:"Clear-Text-Credentials..................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_36) \
	STACK:risk_36#60df20:"Large-DNS-Packet........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_37) \
	STACK:risk_37#20df20:"Fragmented-DNS-Message..................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_38) \
	STACK:risk_38#20df60:"Text-With-Non-Printable-Chars............................" \
	$(rrdtool_graph_print_cur_min_max_avg risk_39) \
	STACK:risk_39#20df9f:"Possible-Exploit........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_40) \
	STACK:risk_40#20dfdf:"TLS-Cert-About-To-Expire................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_41) \
	STACK:risk_41#209fdf:"IDN-Domain-Name.........................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_42) \
	STACK:risk_42#2060df:"Error-Code..............................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_43) \
	STACK:risk_43#2020df:"Crawler/Bot.............................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_44) \
	STACK:risk_44#6020df:"Anonymous-Subscriber....................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_45) \
	STACK:risk_45#9f20df:"Unidirectional-Traffic..................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_46) \
	STACK:risk_46#df20df:"HTTP-Obsolete-Server....................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_47) \
	STACK:risk_47#df209f:"Unknown.................................................." \
	$(rrdtool_graph_print_cur_min_max_avg risk_unknown) \
	STACK:risk_unknown#df2060:"Unknown.................................................."
