#!/usr/bin/env bash
api_token="<some_api_token>"
declare -a file_array
file_array=($(/usr/bin/find "<some_directory_name>" -type f))
scan_counter_minute_current="0"
scan_counter_minute_max="4"
scan_counter_day_current="0"
scan_counter_day_max="500"
scan_report_log_file="./scan_report.log"
declare -a resource_array
scan_resource_log_file="./scan_resources.log"

/usr/bin/touch "${scan_report_log_file}" "${scan_resource_log_file}"

for file in "${file_array[@]}"
do
    if (( "${scan_counter_day_current}" >= "${scan_counter_day_max}" ))
    then
        echo "Daily rate limit of '${scan_counter_day_max}' reached. Waiting for one day..."
        /usr/bin/sleep 1d
        scan_counter_day_current="0"
    elif (( "${scan_counter_minute_current}" >= "${scan_counter_minute_max}" ))
    then
        echo "Minutely rate limit of '${scan_counter_minute_max}' requests reached. Waiting for one minute..."
        /usr/bin/sleep 1m
        scan_counter_minute_current="0"
    else
        # scan file
        echo "Scan request for file: '${file}'."
        resource=$(/usr/bin/curl --silent --show-error \
            --request POST \
            --form apikey="${api_token}" \
            --form file=@"${file}" \
            "https://www.virustotal.com/vtapi/v2/file/scan" \
            | /usr/bin/python -m json.tool \
            | /usr/bin/gawk '/resource/ { gsub("[\",]", ""); print $2 }')

        echo "${resource}" >> "${scan_resource_log_file}"
        resource_array+=("${resource}")
        (( scan_counter_minute_current++ ))
        (( scan_counter_day_current++ ))
    fi
done

for resource in "${resource_array[@]}"
do
    if (( "${scan_counter_day_current}" >= "${scan_counter_day_max}" ))
    then
        echo "Daily rate limit of '${scan_counter_day_max}' reached. Waiting for one day..."
        /usr/bin/sleep 1d
        scan_counter_day_current="0"
    elif (( "${scan_counter_minute_current}" >= "${scan_counter_minute_max}" ))
    then
        echo "Minutely rate limit of '${scan_counter_minute_max}' requests reached. Waiting for one minute..."
        /usr/bin/sleep 1m
        scan_counter_minute_current="0"
    else
        # get scan report
        echo "Get scan report for file: '${file}'."
        echo "Scan report: ${file}:" >> "${scan_report_log_file}"
        /usr/bin/curl --silent --show-error \
            --request POST \
          --form apikey="${api_token}" \
          --form resource="${resource}" \
          "https://www.virustotal.com/vtapi/v2/file/report" \
          | /usr/bin/python -m json.tool \
          | /bin/grep --before-context="2" "detected" >> "${scan_report_log_file}"
        echo -e "\n####################################################\n" >> "${scan_report_log_file}"

        (( scan_counter_minute_current++ ))
        (( scan_counter_day_current++ ))
    fi
done
