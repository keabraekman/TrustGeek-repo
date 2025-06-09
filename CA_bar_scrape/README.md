# CA Bar Scrape

This folder is for a separate effort in the trustgeek repo. 
I got a list of the active attorneys in Los Angeles (la_attys_2025.xlsx).
This list is comprehensive and includes 58k lawyers. 
My goal is in a few steps. I want to offer web development services to these lawyers. 
Particularly the ones that are interested in starting a private practice. 
Here is the plan : 
1. If there is no email and no phone number, (we could check Linkedin), DISCARD. 
2. If they have an email, check the domain name of email. Use that to determine if that's the firm's website. Most often it is, but we need to filter the ones that are not. I am thinking of having a running list, like a python dictionary, (pickle), or csv file where we run a quick LLM query (chatgpt), to determine if the website we reach is the same as the firm. ex: domain name = gmail, firm = law firm west LA. Doesn't match, therefore we can keep.
3. The check needs to make sure the firm has a website and the website is up. Here, LLMs can be very useful. If they have a running website, DISCARD.
4. If they DO NOT have an email address, we need to google search that firm. I am thinking of a similar thing where we scrape the google results and input the LLM output (matches the firm or not). If found, discard, if not found, keep.
5. If there is no firm, then keep the lead. 
Once we get a final list, we can sort by (has email and phone, and date of admission is most recent). 


To recap :
Check 1 = No Phone no Email, DISCARD
Check 2 = IF they have an email, and the domain name is a law firm, DISCARD (LLM for decision +save results)
Check 3 = If they have a firm, and the firm has a website, DISCARD (LLM for decision +save results)

