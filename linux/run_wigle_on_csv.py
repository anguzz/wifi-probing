
import csv
import requests
import json
import time
import os

# running this on a large set of requests will most likely get you rate limited pretty quick
# recommend going through prob_Request_log.csv and removing entries you don't find interesting or want to target

INPUT_CSV_FILENAME = "probe_requests_log.csv"
OUTPUT_CSV_FILENAME = "probe_requests_with_wigle_loc.csv"
WIGLE_API_BASE_URL = "https://api.wigle.net/api/v2/network/search"


WIGLE_API_NAME = ""  #add api name 
WIGLE_API_TOKEN = "" #add token name 


API_CALL_DELAY = 2  # Adjust as needed; WiGLE has daily limits


def query_wigle_for_ssid(ssid, api_name, api_token):
    """
    Queries the WiGLE API for a given SSID.
    Returns a tuple: (latitude, longitude, status_message)
    """
    if not ssid or ssid == "BROADCAST (WILDCARD)":
        return None, None, "Skipped (Broadcast or empty SSID)"

    params = {'ssid': ssid}
    auth = (api_name, api_token)

    try:
        response = requests.get(WIGLE_API_BASE_URL, params=params, auth=auth, timeout=30) 
        response.raise_for_status()  

        data = response.json()

        if data.get("success") and data.get("results"):
            first_result = data["results"][0]
            lat = first_result.get("trilat")
            lon = first_result.get("trilong")
            if lat is not None and lon is not None:
                return lat, lon, "Found"
            else:
                return None, None, "Found but no coordinates"
        elif data.get("success") and not data.get("results"):
            return None, None, f"Not Found ({data.get('message', 'No results')})"
        else:
            error_message = data.get("message", "API error or no results")
            if "too many queries" in error_message.lower():
                print(f"[WARN] WiGLE API rate limit likely hit for SSID '{ssid}'. Message: {error_message}")
                return None, None, "Rate Limit / API Error"
            if "auth failed" in error_message.lower() or "invalid credentials" in error_message.lower():
                print(f"[ERROR] WiGLE API authentication failed. Please check your API_NAME and API_TOKEN. Message: {error_message}")
                return None, None, "Authentication Failed"
            return None, None, f"API Error ({error_message})"

    except requests.exceptions.HTTPError as http_err:
        error_content = "No content"
        try:
            error_content = http_err.response.json().get("message", http_err.response.text)
        except json.JSONDecodeError:
            error_content = http_err.response.text
        print(f"[ERROR] HTTP error for SSID '{ssid}': {http_err} - {error_content}")
        if http_err.response.status_code == 401:
             return None, None, "Authentication Failed (HTTP 401)"
        if http_err.response.status_code == 404:
            return None, None, "Not Found (HTTP 404)"
        if http_err.response.status_code == 429: 
            print(f"[WARN] WiGLE API rate limit hit (HTTP 429). Consider increasing API_CALL_DELAY.")
            return None, None, "Rate Limit (HTTP 429)"
        return None, None, f"HTTP Error {http_err.response.status_code}"
    except requests.exceptions.RequestException as req_err:
        print(f"[ERROR] Request exception for SSID '{ssid}': {req_err}")
        return None, None, "Request Exception"
    except json.JSONDecodeError as json_err:
        print(f"[ERROR] Failed to decode JSON response for SSID '{ssid}': {json_err}")
        print(f"       Response content: {response.text[:200]}...")
        return None, None, "JSON Decode Error"


def process_csv(input_file, output_file, api_name, api_token):
    """
    Reads the input CSV, queries WiGLE for each SSID, and writes to the output CSV.
    """
    if api_name == "YOUR_WIGLE_API_NAME_HERE" or api_token == "YOUR_WIGLE_API_TOKEN_HERE":
        print("[CRITICAL ERROR] Please replace placeholder API credentials in the script before running.")
        return

    print(f"[INFO] Starting to process '{input_file}'...")
    
    if not os.path.exists(input_file):
        print(f"[ERROR] Input file '{input_file}' not found. Please make sure it's in the same directory or provide the correct path.")
        return

    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
             open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            try:
                header = next(reader) 
            except StopIteration:
                print(f"[ERROR] Input file '{input_file}' is empty or has no header.")
                return
                
            output_header = header + ["Latitude", "Longitude", "WiGLE_Status"]
            writer.writerow(output_header)

            try:
                ssid_column_index = header.index("SSID")
            except ValueError:
                print(f"[ERROR] 'SSID' column not found in the header of '{input_file}'. Please check the CSV format.")
                print(f"        Header found: {header}")
                return

            row_count = 0
            found_count = 0
            for row_number, row in enumerate(reader, 1):
                row_count += 1
                if not row or len(row) <= ssid_column_index:
                    print(f"[WARN] Skipping malformed or short row {row_number}: {row}")
                    writer.writerow(row + [None, None, "Skipped (Malformed Row)"])
                    continue

                ssid = row[ssid_column_index]
                print(f"[INFO] Processing row {row_number}: SSID = '{ssid}'")

                lat, lon, status = query_wigle_for_ssid(ssid, api_name, api_token)
                
                writer.writerow(row + [lat, lon, status])

                if status == "Found":
                    found_count += 1
                    print(f"  -> Found: Lat={lat}, Lon={lon}")
                else:
                    print(f"  -> WiGLE Status: {status}")
                
                if status != "Skipped (Broadcast or empty SSID)": # No need to delay for skipped SSIDs
                    print(f"  -> Waiting for {API_CALL_DELAY} seconds before next API call...")
                    time.sleep(API_CALL_DELAY)
                
                if status == "Authentication Failed" or status == "Authentication Failed (HTTP 401)":
                    print("[CRITICAL] Authentication failed. Stopping script. Please check your WiGLE API credentials.")
                    break 
                if status == "Rate Limit (HTTP 429)":
                    print("[WARN] Rate limit hit (HTTP 429). Stopping script to avoid further issues. Please try again later or increase API_CALL_DELAY.")
                    break


    except FileNotFoundError:
        print(f"[ERROR] Input file '{input_file}' not found.")
    except IOError as e:
        print(f"[ERROR] I/O error: {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
    finally:
        print(f"[INFO] Processing complete. Processed {row_count} data rows.")
        print(f"[INFO] Found location data for {found_count} SSIDs.")
        print(f"[INFO] Output saved to '{output_file}'")

if __name__ == "__main__":
    process_csv(INPUT_CSV_FILENAME, OUTPUT_CSV_FILENAME, WIGLE_API_NAME, WIGLE_API_TOKEN)
