#    (
#     \
#      )
# ##-------->           Simple GUI to interact with abuseipdb's API 
#      )                https://github.com/whatiscybersecurity    
#     /
#    (


import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests

def check_ip():
    ip_address = ip_entry.get()
    api_key = api_key_entry.get()

    if not ip_address or not api_key:
        messagebox.showwarning("Input Error", "Please provide both IP address and API key.")
        return

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()['data']

        result_text.delete(1.0, tk.END)  # Clear previous results

        # Display all available information
        result_text.insert(tk.END, f"Results for IP: {data.get('ipAddress', 'N/A')}\n", 'title')
        abuse_score = data.get('abuseConfidenceScore', 'N/A')
        abuse_color = 'bad_score' if abuse_score >= 50 else 'good_score'
        result_text.insert(tk.END, f"Abuse Confidence Score: {abuse_score}%\n", abuse_color)
        result_text.insert(tk.END, f"Total Reports: {data.get('totalReports', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"Last Reported: {data.get('lastReportedAt', 'Never')}\n", 'default')
        result_text.insert(tk.END, f"Country: {data.get('countryName', 'N/A')} ({data.get('countryCode', 'N/A')})\n", 'default')
        result_text.insert(tk.END, f"ISP: {data.get('isp', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"Domain: {data.get('domain', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"Usage Type: {data.get('usageType', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"Hostnames: {', '.join(data.get('hostnames', []))}\n", 'default')
        result_text.insert(tk.END, f"Country Code: {data.get('countryCode', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"ISP Domain: {data.get('domain', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"ISP AS Number: {data.get('asn', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"IP is Public: {data.get('isPublic', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"IP is Shared: {data.get('isShared', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"WHOIS Netblock: {data.get('netblock', 'N/A')}\n", 'default')

        if data.get('isWhitelisted', False):
            result_text.insert(tk.END, "This IP is whitelisted.\n", 'highlight')

        if int(data.get('totalReports', 0)) > 0:
            result_text.insert(tk.END, "\nReports Summary:\n", 'title')
            for category in data.get('reportCategories', []):
                result_text.insert(tk.END, f"- {category}\n", 'highlight')
        else:
            result_text.insert(tk.END, "\nNo abuse reports found for this IP.\n", 'default')

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
    except KeyError as e:
        messagebox.showerror("Error", f"Error parsing API response: {e}")

def toggle_dark_mode():
    if app.cget('bg') == 'white':
        # Switch to dark mode
        app.configure(bg='#2e2e2e')
        main_frame.configure(style="Dark.TFrame")
        result_text.configure(bg='#3c3f41', fg='#e8e6e3')
        style.configure("TLabel", background='#2e2e2e', foreground='#e8e6e3')
        style.configure("TEntry", fieldbackground='#3c3f41', foreground='#e8e6e3')
        style.configure("TButton", background='#5a5a5a', foreground='#e8e6e3')
        dark_mode_button.configure(text="Light Mode")

        # Update text colors for dark mode
        result_text.tag_config('title', foreground='#1d84b5', font=('Helvetica', 12, 'bold'))
        result_text.tag_config('highlight', foreground='#3aaf85', font=('Helvetica', 11, 'bold'))
        result_text.tag_config('default', foreground='#e8e6e3', font=('Helvetica', 11))
        result_text.tag_config('bad_score', foreground='#e74c3c', font=('Helvetica', 11, 'bold'))  # Red for bad scores
        result_text.tag_config('good_score', foreground='#27ae60', font=('Helvetica', 11, 'bold'))  # Green for good scores

    else:
        # Switch to light mode
        app.configure(bg='white')
        main_frame.configure(style="Light.TFrame")
        result_text.configure(bg='#f0f4f8', fg='#2d3e50')
        style.configure("TLabel", background='white', foreground='#2d3e50')
        style.configure("TEntry", fieldbackground='white', foreground='#2d3e50')
        style.configure("TButton", background='#5a5a5a', foreground='#2d3e50')
        dark_mode_button.configure(text="Dark Mode")

        # Update text colors for light mode
        result_text.tag_config('title', foreground='#1d84b5', font=('Helvetica', 12, 'bold'))
        result_text.tag_config('highlight', foreground='#3aaf85', font=('Helvetica', 11, 'bold'))
        result_text.tag_config('default', foreground='#2d3e50', font=('Helvetica', 11))
        result_text.tag_config('bad_score', foreground='#e74c3c', font=('Helvetica', 11, 'bold'))  # Red for bad scores
        result_text.tag_config('good_score', foreground='#27ae60', font=('Helvetica', 11, 'bold'))  # Green for good scores

# Set up the main application window
app = tk.Tk()
app.title("AbuseIPDB-API-GUI")
app.geometry('600x600')

# Use ttk widgets for a more modern look
style = ttk.Style(app)
style.theme_use('clam')  # Use a modern theme

# Initial Style Configuration
style.configure("Light.TFrame", background='white')
style.configure("Dark.TFrame", background='#2e2e2e')

# Fix the initial color of Entry fields in light mode
style.configure("TEntry", fieldbackground='white', foreground='#2d3e50')

# Main Frame
main_frame = ttk.Frame(app, padding="20 20 20 20", style="Light.TFrame")
main_frame.pack(fill=tk.BOTH, expand=True)

# API Key Entry
ttk.Label(main_frame, text="Enter your AbuseIPDB API key:", font=('Helvetica', 12)).grid(column=0, row=0, sticky=tk.W, pady=5)
api_key_entry = ttk.Entry(main_frame, width=60)
api_key_entry.grid(column=0, row=1, pady=5)

# IP Address Entry
ttk.Label(main_frame, text="Enter the IP address to check:", font=('Helvetica', 12)).grid(column=0, row=2, sticky=tk.W, pady=5)
ip_entry = ttk.Entry(main_frame, width=60)
ip_entry.grid(column=0, row=3, pady=5)

# Check Button
check_button = ttk.Button(main_frame, text="Check IP", command=check_ip)
check_button.grid(column=0, row=4, pady=10)

# Dark Mode Toggle Button
dark_mode_button = ttk.Button(main_frame, text="Dark Mode", command=toggle_dark_mode)
dark_mode_button.grid(column=0, row=5, pady=10)

# Result Text
result_text = scrolledtext.ScrolledText(main_frame, width=80, height=25, wrap=tk.WORD, bg="#f0f4f8", fg="#2d3e50", font=('Helvetica', 11))
result_text.grid(column=0, row=6, pady=10)

# Define text tags for colors
result_text.tag_config('title', foreground='#1d84b5', font=('Helvetica', 12, 'bold'))
result_text.tag_config('highlight', foreground='#3aaf85', font=('Helvetica', 11, 'bold'))
result_text.tag_config('default', foreground='#2d3e50', font=('Helvetica', 11))
result_text.tag_config('bad_score', foreground='#e74c3c', font=('Helvetica', 11, 'bold'))  # Red for bad scores
result_text.tag_config('good_score', foreground='#27ae60', font=('Helvetica', 11, 'bold'))  # Green for good scores

# Center the main frame
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_rowconfigure(6, weight=1)

# Start the main event loop
app.mainloop()
