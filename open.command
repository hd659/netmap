#!/bin/bash
cd "$(dirname "$0")"
if ! curl -s -m 1 -o /dev/null http://127.0.0.1:18320/api/state; then
  nohup python3 -I server.py > server.log 2>&1 &
  sleep 1
fi
REUSED=$(/usr/bin/osascript <<'APPLESCRIPT' 2>/dev/null
if application "Google Chrome" is running then
  tell application "Google Chrome"
    repeat with w in windows
      set ti to 0
      repeat with t in tabs of w
        set ti to ti + 1
        set u to URL of t
        if u contains "127.0.0.1:18320" or u contains "localhost:18320" then
          reload t
          try
            if minimized of w is true then set minimized of w to false
          end try
          set active tab index of w to ti
          set index of w to 1
          activate
          return "REUSED"
        end if
      end repeat
    end repeat
  end tell
end if
return "NONE"
APPLESCRIPT
)
[ "$REUSED" = "REUSED" ] && exit 0
open -na "Google Chrome" --args --app=http://127.0.0.1:18320/ --window-size=1200,820
