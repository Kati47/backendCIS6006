/**
 * This script determines the correct time offset for TOTP verification
 * when your system clock is incorrect but you can't change it
 */
const fs = require('fs');
const path = require('path');
const https = require('https');

/**
 * Get current time from a time server with timeout and status code checking
 * @returns {Promise<number>} Timestamp from server in milliseconds
 */
function getTimeFromWorldtimeAPI() {
  return new Promise((resolve, reject) => {
    console.log('Attempting to get time from worldtimeapi.org...');
    
    const req = https.get('https://worldtimeapi.org/api/ip', { timeout: 5000 }, (res) => {
      // Check for HTTP errors
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP error from worldtimeapi.org: ${res.statusCode}`));
        return;
      }
      
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.unixtime) {
            console.log('Got time from worldtimeapi.org:', new Date(response.unixtime * 1000).toISOString());
            resolve(response.unixtime * 1000); // Convert to milliseconds
          } else {
            reject(new Error('Invalid response from worldtimeapi.org (missing unixtime)'));
          }
        } catch (error) {
          reject(new Error(`Error parsing response: ${error.message}`));
        }
      });
    });
    
    // Handle timeout
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request to worldtimeapi.org timed out after 5 seconds'));
    });
    
    req.on('error', (err) => {
      console.log('Error accessing worldtimeapi.org:', err.message);
      reject(err);
    });
  });
}

/**
 * Get time from time.google.com as a fallback
 * @returns {Promise<number>} Timestamp from server in milliseconds
 */
function getTimeFromGoogleAPI() {
  return new Promise((resolve, reject) => {
    console.log('Attempting to get time from Google...');
    
    const req = https.get('https://time.google.com', { timeout: 5000 }, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP error from time.google.com: ${res.statusCode}`));
        return;
      }
      
      // Extract the date from response headers
      const serverDate = res.headers.date;
      if (!serverDate) {
        reject(new Error('No date header in Google time response'));
        return;
      }
      
      try {
        const serverTime = new Date(serverDate).getTime();
        console.log('Got time from time.google.com:', new Date(serverTime).toISOString());
        resolve(serverTime);
      } catch (error) {
        reject(new Error(`Error parsing date header: ${error.message}`));
      }
    });
    
    // Handle timeout
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request to time.google.com timed out after 5 seconds'));
    });
    
    req.on('error', (err) => {
      console.log('Error accessing time.google.com:', err.message);
      reject(err);
    });
  });
}

/**
 * Get time from server with retries and fallbacks
 * @returns {Promise<number>} Timestamp from server
 */
async function getTimeFromServer(maxRetries = 2) {
  const services = [
    { name: 'WorldTime API', fn: getTimeFromWorldtimeAPI },
    { name: 'Google Time', fn: getTimeFromGoogleAPI }
  ];
  
  // Try each service with retries
  for (const service of services) {
    console.log(`\nTrying ${service.name}...`);
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await service.fn();
      } catch (error) {
        console.log(`Attempt ${attempt}/${maxRetries} with ${service.name} failed: ${error.message}`);
        
        if (attempt < maxRetries) {
          // Wait before retrying (exponential backoff)
          const delay = attempt * 1000;
          console.log(`Waiting ${delay}ms before retry...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    console.log(`All attempts with ${service.name} failed, trying next service...`);
  }
  
  throw new Error('All time services failed');
}

/**
 * Calculate the time offset between system and server time
 */
async function calculateTimeOffset() {
  console.log('Calculating time offset...');
  console.log('System time:', new Date().toISOString());
  
  try {
    // Get time from server
    const serverTimeMs = await getTimeFromServer();
    
    // Get system time
    const systemTimeMs = Date.now();
    
    // Calculate offset
    const offsetMs = serverTimeMs - systemTimeMs;
    const offsetSeconds = Math.round(offsetMs / 1000);
    
    console.log(`\nServer time: ${new Date(serverTimeMs).toISOString()}`);
    console.log(`System time: ${new Date(systemTimeMs).toISOString()}`);
    console.log(`Time offset: ${offsetSeconds} seconds (${offsetMs} ms)`);
    
    return offsetSeconds;
  } catch (error) {
    console.error('\nError getting time from all servers:', error.message);
    console.log('Falling back to manual calculation...');
    return calculateOffsetManually();
  }
}

/**
 * Parse a user-provided date string with validation
 * @param {string} input - Date string in format YYYY-MM-DD HH:MM:SS
 * @returns {Date|null} Parsed date or null if invalid
 */
function parseManualDate(input) {
  // Regex to validate YYYY-MM-DD HH:MM:SS format
  const regex = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/;
  const match = input.match(regex);
  
  if (!match) {
    console.error('Invalid date format. Please use YYYY-MM-DD HH:MM:SS');
    return null;
  }
  
  const [_, year, month, day, hour, minute, second] = match;
  
  // Convert to numbers and validate ranges
  const y = parseInt(year, 10);
  const m = parseInt(month, 10) - 1; // JS months are 0-11
  const d = parseInt(day, 10);
  const h = parseInt(hour, 10);
  const min = parseInt(minute, 10);
  const s = parseInt(second, 10);
  
  // Basic validation
  if (m < 0 || m > 11 || d < 1 || d > 31 || h < 0 || h > 23 || min < 0 || min > 59 || s < 0 || s > 59) {
    console.error('Date contains values outside of valid ranges');
    return null;
  }
  
  const date = new Date(y, m, d, h, min, s);
  
  // Sanity check - date should be within reasonable range (±5 years)
  const now = Date.now();
  const fiveYearsMs = 5 * 365 * 24 * 60 * 60 * 1000;
  if (Math.abs(date.getTime() - now) > fiveYearsMs) {
    console.warn('Warning: Date is more than 5 years from current system time');
  }
  
  return date;
}

/**
 * Calculate time offset without external API
 * This is useful when we can't reach the time servers
 */
function calculateOffsetManually() {
  console.log('\nUsing manual time calculation (no internet required)...');
  
  // Get current system time
  const systemTime = new Date();
  console.log('System time:', systemTime.toISOString());
  
  return new Promise((resolve) => {
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    readline.question('\nEnter the correct current time (YYYY-MM-DD HH:MM:SS): ', answer => {
      readline.close();
      
      try {
        // Parse the provided time with our custom validation
        const manualTime = parseManualDate(answer);
        
        if (!manualTime || isNaN(manualTime.getTime())) {
          console.error('Invalid date/time format. Using 0 offset.');
          resolve(0);
          return;
        }
        
        // Calculate offset
        const offsetMs = manualTime.getTime() - systemTime.getTime();
        const offsetSeconds = Math.round(offsetMs / 1000);
        
        console.log(`\nManual time: ${manualTime.toISOString()}`);
        console.log(`System time: ${systemTime.toISOString()}`);
        console.log(`Calculated offset: ${offsetSeconds} seconds (${offsetMs} ms)`);
        
        // Additional validation for extreme offsets
        if (Math.abs(offsetSeconds) > 86400) { // More than a day
          const confirm = require('readline').createInterface({
            input: process.stdin,
            output: process.stdout
          });
          
          confirm.question(`\nWARNING: Large time offset detected (${offsetSeconds} seconds). Proceed? (y/n): `, answer => {
            confirm.close();
            if (answer.toLowerCase() === 'y') {
              resolve(offsetSeconds);
            } else {
              console.log('Operation cancelled. Using 0 offset.');
              resolve(0);
            }
          });
        } else {
          resolve(offsetSeconds);
        }
      } catch (error) {
        console.error('Error processing date:', error.message);
        console.log('Using 0 offset as fallback.');
        resolve(0);
      }
    });
  });
}

/**
 * Save offset to .env file
 * @param {number} offset - Offset in seconds
 */
function saveOffsetToEnv(offset) {
  const envPath = path.join(__dirname, '..', '.env');
  console.log(`\nSaving to .env file at: ${envPath}`);
  
  let envContent = '';
  let updatedExisting = false;
  
  try {
    if (fs.existsSync(envPath)) {
      console.log('Existing .env file found, updating...');
      envContent = fs.readFileSync(envPath, 'utf8');
      
      // Replace existing TOTP_TIME_OFFSET or add it
      if (envContent.includes('TOTP_TIME_OFFSET=')) {
        envContent = envContent.replace(/TOTP_TIME_OFFSET=.*/g, `TOTP_TIME_OFFSET=${offset}`);
        updatedExisting = true;
      } else {
        // Add a newline if the file doesn't end with one
        if (!envContent.endsWith('\n')) {
          envContent += '\n';
        }
        envContent += `TOTP_TIME_OFFSET=${offset}`;
      }
    } else {
      console.log('No .env file found, creating new file...');
      envContent = `TOTP_TIME_OFFSET=${offset}\nNODE_ENV=development`;
    }
    
    // Create backup of existing file
    if (fs.existsSync(envPath)) {
      const backupPath = `${envPath}.backup-${Date.now()}`;
      fs.copyFileSync(envPath, backupPath);
      console.log(`Created backup at ${backupPath}`);
    }
    
    fs.writeFileSync(envPath, envContent);
    console.log(`\n✅ Successfully ${updatedExisting ? 'updated' : 'created'} .env file with TOTP_TIME_OFFSET=${offset}`);
    return true;
  } catch (error) {
    console.error('\n❌ Error writing to .env file:', error.message);
    return false;
  }
}

/**
 * Main function
 */
async function main() {
  console.log('=== TOTP Time Synchronization Tool ===');
  
  // Calculate the time offset
  const offset = await calculateTimeOffset();
  
  if (offset === null) {
    console.error('Failed to calculate time offset.');
    process.exit(1);
  }
  
  // Confirm the calculated offset
  const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  readline.question(`\nUse calculated offset of ${offset} seconds? (y/n): `, answer => {
    readline.close();
    
    if (answer.toLowerCase() !== 'y') {
      console.log('Operation cancelled.');
      process.exit(0);
    }
    
    // Save offset to .env file
    if (saveOffsetToEnv(offset)) {
      console.log(`\n✅ TOTP_TIME_OFFSET=${offset} has been saved to your .env file.`);
      console.log('Restart your server for changes to take effect.');
      console.log('TOTP verification should now work properly with your authenticator app.');
    } else {
      console.log('\n⚠️ Could not save to .env file automatically.');
      console.log(`Please manually add TOTP_TIME_OFFSET=${offset} to your .env file.`);
    }
  });
}

// Run the script
console.log('Starting time synchronization setup...');
main()
  .catch(error => {
    console.error('\nFatal error running script:', error);
    process.exit(1);
  });