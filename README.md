# spamintel
DIY Threat Intel: Mining your spam folder for threat intelligence gold


This repository contains two scripts:  

 * process-spam.py
 * runvt.py

I call them from cron:

```
0 *     * * *   /home/foo/bin/process-spam.py 2>&1 >>/var/log/cronlogs
10 */4  * * *   /home/foo/bin/runvt.py 2>&1 >>/var/log/cronlogs
```

This ensures my spam folder is processed every hour, and any attachments are submitted to VirusTotal.

If it's something VT hasn't seen before, runvt.py will follow up and get the results after a few hours.


#####To do

One thing I haven't yet coded is the ability to have the extracted URLs analyzed by VT.

I also need to parse the JSON returned to make the results files more easily human-readable.

