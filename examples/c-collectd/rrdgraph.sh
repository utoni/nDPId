#!/usr/bin/env sh

RRDDIR="${1}"
OUTDIR="${2}"
RRDARGS="--width=800 --height=400 -v Amount"

if [ -z "${RRDDIR}" ]; then
	printf '%s: Missing RRD directory which contains nDPIsrvd/Collectd files.\n' "${0}"
	exit 1
fi

if [ -z "${OUTDIR}" ]; then
	printf '%s: Missing Output directory which contains HTML files.\n' "${0}"
	exit 1
fi

if [ $(ls -al ${RRDDIR}/flow_*.rrd | wc -l) -ne 54 ]; then
	printf '%s: Missing some *.rrd files.\n' "${0}"
	exit 1
fi

if [ ! -r "${OUTDIR}/index.html" -o ! -r "${OUTDIR}/flows.html" -o ! -r "${OUTDIR}/other.html" -o ! -r "${OUTDIR}/detections.html" -o ! -r "${OUTDIR}/categories.html" ]; then
	printf '%s: Missing some *.html files.\n' "${0}"
	exit 1
fi

TIME_PAST_HOUR="--start=-3600 --end=-0"
TIME_PAST_DAY="--start=-86400 --end=-0"
TIME_PAST_WEEK="--start=-604800 --end=-0"
TIME_PAST_MONTH="--start=-2419200 --end=-0"
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
	OUTPNG="${1}"
	shift

	rrdtool graph ${RRDARGS} -t "${TITLE} (past hour)"  -Y --start=-3600     --end=-0 "${OUTPNG}_past_hour.png"  ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past day)"   -Y --start=-86400    --end=-0 "${OUTPNG}_past_day.png"   ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past week)"  -Y --start=-604800   --end=-0 "${OUTPNG}_past_week.png"  ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past month)" -Y --start=-2419200  --end=-0 "${OUTPNG}_past_month.png" ${*}
	rrdtool graph ${RRDARGS} -t "${TITLE} (past year)"  -Y --start=-31536000 --end=-0 "${OUTPNG}_past_year.png"  ${*}
}

rrdtool_graph Flows "${OUTDIR}/flows" \
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
rrdtool_graph Detections "${OUTDIR}/detections" \
	DEF:flows_detected=${RRDDIR}/gauge-flow_detected_count.rrd:value:AVERAGE \
	DEF:flows_guessed=${RRDDIR}/gauge-flow_guessed_count.rrd:value:AVERAGE \
	DEF:flows_not_detected=${RRDDIR}/gauge-flow_not_detected_count.rrd:value:AVERAGE \
	DEF:flows_detection_update=${RRDDIR}/gauge-flow_detection_update_count.rrd:value:AVERAGE \
	DEF:flows_risky=${RRDDIR}/gauge-flow_risky_count.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data flows_detected) \
	AREA:flows_detected#00bfff::STACK \
	AREA:flows_guessed#ffff4d::STACK \
	AREA:flows_not_detected#ffa64d::STACK \
	AREA:flows_detection_update#a1b8c4::STACK \
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
rrdtool_graph "Traffic (IN/OUT)" "${OUTDIR}/traffic" \
        DEF:total_bytes=${RRDDIR}/gauge-flow_total_bytes.rrd:value:AVERAGE \
	$(rrdtool_graph_colorize_missing_data total_bytes) \
	AREA:total_bytes#bea1c4::STACK \
        LINE2:total_bytes#92629d:"Total-Bytes-Xfer" \
	$(rrdtool_graph_print_cur_min_max_avg total_bytes)
rrdtool_graph Layer3-Flows "${OUTDIR}/layer3" \
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
rrdtool_graph Layer4-Flows "${OUTDIR}/layer4" \
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
rrdtool_graph Flow-Breeds "${OUTDIR}/breed" \
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
rrdtool_graph Flow-Categories "${OUTDIR}/categories" \
	DEF:cat_ads=${RRDDIR}/gauge-flow_category_advertisment_count.rrd:value:AVERAGE \
	DEF:cat_chat=${RRDDIR}/gauge-flow_category_chat_count.rrd:value:AVERAGE \
	DEF:cat_cloud=${RRDDIR}/gauge-flow_category_cloud_count.rrd:value:AVERAGE \
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
	DEF:cat_oth=${RRDDIR}/gauge-flow_category_other_count.rrd:value:AVERAGE \
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
	LINE2:cat_ads#f1c232:"Advertisment..........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_ads) \
	LINE2:cat_chat#6fa8dc:"Chat..................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_chat) \
	LINE2:cat_cloud#2986cc:"Cloud.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_cloud) \
	LINE2:cat_xfer#16537e:"Data-Transfer.........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_xfer) \
	LINE2:cat_db#cc0000:"Database..............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_db) \
	LINE2:cat_dl#6a329f:"Download..............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_dl) \
	LINE2:cat_mail#3600cc:"Mail..................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_mail) \
	LINE2:cat_fs#c90076:"File-Sharing..........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_fs) \
	LINE2:cat_game#00ff26:"Game..................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_game) \
	LINE2:cat_mal#f44336:"Malware................" \
	$(rrdtool_graph_print_cur_min_max_avg cat_mal) \
	LINE2:cat_med#ff8300:"Media.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_med) \
	LINE2:cat_min#ff0000:"Mining................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_min) \
	LINE2:cat_mus#00fff0:"Music.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_mus) \
	LINE2:cat_net#ddff00:"Network................" \
	$(rrdtool_graph_print_cur_min_max_avg cat_net) \
	LINE2:cat_oth#744700:"Other.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_oth) \
	LINE2:cat_prod#29ff00:"Productivity..........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_prod) \
	LINE2:cat_rem#b52c2c:"Remote-Access.........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_rem) \
	LINE2:cat_rpc#e15a5a:"Remote-Procedure-Call.." \
	$(rrdtool_graph_print_cur_min_max_avg cat_rpc) \
	LINE2:cat_shop#0065ff:"Shopping..............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_shop) \
	LINE2:cat_soc#8fce00:"Social-Network........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_soc) \
	LINE2:cat_soft#007a0d:"Software-Update........" \
	$(rrdtool_graph_print_cur_min_max_avg cat_soft) \
	LINE2:cat_str#ff00b8:"Streaming.............." \
	$(rrdtool_graph_print_cur_min_max_avg cat_str) \
	LINE2:cat_sys#f4ff00:"System................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_sys) \
	LINE2:cat_ukn#999999:"Unknown................" \
	$(rrdtool_graph_print_cur_min_max_avg cat_ukn) \
	LINE2:cat_vid#518820:"Video.................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_vid) \
	LINE2:cat_voip#ffc700:"Voice-Over-IP.........." \
	$(rrdtool_graph_print_cur_min_max_avg cat_voip) \
	LINE2:cat_vpn#378035:"Virtual-Private-Network" \
	$(rrdtool_graph_print_cur_min_max_avg cat_vpn) \
	LINE2:cat_web#00fffb:"Web...................." \
	$(rrdtool_graph_print_cur_min_max_avg cat_web)
