from datetime import datetime
import pytz

def format_ist_time(utc_time=None, format_str="%d-%b-%Y %I:%M %p"):
    """
    Convert time to Indian Standard Time (IST) and format it
    
    Args:
        utc_time (datetime, optional): UTC datetime object or string. Defaults to current time.
        format_str (str, optional): Format string. Defaults to "DD-Mon-YYYY HH:MM AM/PM".
    
    Returns:
        str: Formatted time string in IST
    """
    # Get IST timezone
    ist_timezone = pytz.timezone('Asia/Kolkata')
    
    # Handle current time request
    if utc_time is None:
        # Simply return the current time in IST
        return datetime.now(ist_timezone).strftime(format_str)
    
    # Special handling for database timestamps (most likely what's in order.date)
    try:
        # If it's already a datetime object
        if isinstance(utc_time, datetime):
            # If it has no timezone, assume local time and make it aware
            if utc_time.tzinfo is None:
                local_time = ist_timezone.localize(utc_time)
                return local_time.strftime(format_str)
            else:
                # If it has a timezone, convert to IST
                return utc_time.astimezone(ist_timezone).strftime(format_str)
        
        # If it's a string, try to parse it
        elif isinstance(utc_time, str):
            # First try parsing with common SQL datetime formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"]:
                try:
                    dt = datetime.strptime(utc_time, fmt)
                    # Localize to IST - assuming the timestamp is already in local time
                    aware_dt = ist_timezone.localize(dt)
                    return aware_dt.strftime(format_str)
                except ValueError:
                    continue
            
            # Return the original string if parsing fails
            return utc_time
        
        # For any other type, convert to string
        else:
            return str(utc_time)
    
    except Exception:
        # In case of any error, return the input as string
        if isinstance(utc_time, datetime):
            return utc_time.strftime(format_str)
        return str(utc_time)
