# Troubleshooting Wrangler EPERM Error on Windows

If you're getting a `spawn EPERM` error when trying to run `npm run dev`, try these solutions:

## Solution 1: Run PowerShell as Administrator
1. Right-click on PowerShell/Command Prompt
2. Select "Run as Administrator"
3. Navigate to the backend directory: `cd "c:\Users\pc\Desktop\CyberSec - Copy\backend"`
4. Run: `npm run dev`

## Solution 2: Add Windows Defender Exclusion
1. Open Windows Security (Windows Defender)
2. Go to Virus & threat protection
3. Click "Manage settings" under Virus & threat protection settings
4. Scroll down to "Exclusions" and click "Add or remove exclusions"
5. Add these folders:
   - `C:\Users\pc\Desktop\CyberSec - Copy\backend\node_modules`
   - `C:\Users\pc\AppData\Roaming\npm` (if using global npm)
   - `C:\Users\pc\AppData\Local\npm-cache`

## Solution 3: Reinstall Wrangler
```bash
cd backend
npm uninstall wrangler
npm install wrangler --save-dev
```

## Solution 4: Use Wrangler.cmd Directly
Try running wrangler directly:
```bash
cd backend
.\node_modules\.bin\wrangler.cmd dev
```

## Solution 5: Check Antivirus Software
If you have third-party antivirus software (Norton, McAfee, etc.), temporarily disable it or add exclusions for:
- Node.js executable
- The backend project folder
- npm cache folder

## Solution 6: Clear npm Cache
```bash
npm cache clean --force
cd backend
rm -rf node_modules
npm install
```

## Alternative: Use WSL (Windows Subsystem for Linux)
If the above solutions don't work, you can use WSL:
1. Install WSL2
2. Open WSL terminal
3. Navigate to your project
4. Run `npm run dev` from WSL
