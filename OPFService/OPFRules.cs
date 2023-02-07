// This file is part of OpenPasswordFilter.
// 
// OpenPasswordFilter is free software; you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// OpenPasswordFilter is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with OpenPasswordFilter; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111 - 1307  USA
//

using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Xml.Schema;
using System.ComponentModel;

namespace OPFService {
    class OPFRules {

        static readonly string PROPERTY_MIN_UPPER = "min.uppercase";
        static readonly string PROPERTY_MIN_LOWER = "min.lowercase";
        static readonly string PROPERTY_MAX_REPEATS = "max.consecutive-repeats";
        static readonly string PROPERTY_MAX_LENGTH = "max.length";
        static readonly string PROPERTY_MIN_LENGTH = "min.length";
        static readonly string PROPERTY_MIN_ALPHA = "min.alpha";
        static readonly string PROPERTY_MIN_NON_ALPHA = "min.non-alpha";
        static readonly string PROPERTY_MIN_NUMERIC = "min.numeric";
        static readonly string PROPERTY_MIN_SPECIAL = "min.special";
        static readonly string PROPERTY_INSPECTION_LIMIT = "inspection.limit";

        // defaults
        static readonly int MIN_LENGTH = 8;
        static readonly int MAX_LENGTH = -1;
        static readonly int MIN_UPPER = 1;
        static readonly int MIN_LOWER = 1;
        static readonly int MIN_ALPHA = MIN_UPPER + MIN_LOWER;
        static readonly int MIN_NUMERIC = 1;
        static readonly int MIN_SPECIAL = 1;
        static readonly int MIN_NON_ALPHA = MIN_NUMERIC + MIN_SPECIAL;
        static readonly int MAX_REPEATS = 2;



        int minLength = MIN_LENGTH;
        int maxLength = MAX_LENGTH;
        int minUpper = MIN_UPPER;
        int minLower = MIN_LOWER;
        int minAlpha = MIN_ALPHA;
        int minNonAlpha = MIN_NON_ALPHA;
        int minSpecial = MIN_SPECIAL;
        int minNumeric = MIN_NUMERIC;
        int maxRepeats = MAX_REPEATS;
        int inspectionLimit = -1;

        bool foundFile = false;

        public OPFRules(string path) {


            // Make rules file optional 
            if (!File.Exists(path))
            {
                using (EventLog eventLog = new EventLog("Application"))
                {
                    eventLog.Source = "Application";
                    eventLog.WriteEntry("OpenPasswordFilter service failed to load rules " + path + ".", EventLogEntryType.Information, 101, 1);
                }
                return;
            }


            string line;
            StreamReader infilecont = new StreamReader(path);
            foundFile = true;
            int a = 1;
            Dictionary<string, string> props = new Dictionary<string, string>();


            while ((line = infilecont.ReadLine()) != null)
            {
                try
                {
                    line = line.Trim();
                    if ((line.Length == 0) || line.StartsWith("#")) {
                        // skip empty lines or lines starting with comments
                        continue;
                    }
                    string[] vals = line.Split('=');
                    props[vals[0].Trim()] = vals[1].Trim();
                    a += 1;
                }
                catch
                {
                    using (EventLog eventLog = new EventLog("Application"))
                    {
                        eventLog.Source = "Application";
                        eventLog.WriteEntry("Failed trying to ingest line number " + a.ToString() + " of " + path + ".", EventLogEntryType.Information, 101, 1);
                    }
                }
            }
            infilecont.Close();


            maxLength = GetIntVal(props, PROPERTY_MAX_LENGTH, maxLength);
            minLength = GetIntVal(props, PROPERTY_MIN_LENGTH, minLength);
            minLower = GetIntVal(props, PROPERTY_MIN_LOWER, minLower);
            minUpper = GetIntVal(props, PROPERTY_MIN_UPPER, minUpper);
            minNumeric = GetIntVal(props, PROPERTY_MIN_NUMERIC, minNumeric);
            minSpecial = GetIntVal(props, PROPERTY_MIN_SPECIAL, minSpecial);
            maxRepeats = GetIntVal(props, PROPERTY_MAX_REPEATS, maxRepeats);
            minAlpha = GetIntVal(props, PROPERTY_MIN_ALPHA, minAlpha);
            minNonAlpha = GetIntVal(props, PROPERTY_MIN_NON_ALPHA, minNonAlpha);
            inspectionLimit = GetIntVal(props, PROPERTY_INSPECTION_LIMIT, inspectionLimit);


        }

        int GetIntVal(Dictionary<string, string> d, string key, int defaultVal)
        {

            if (d.TryGetValue(key, out string val))
            {
                if ((val != null) && (val.Length > 0))
                {
                    return Int32.Parse(val);
                }
            }
            return defaultVal;
        }

        public bool CheckPassword(string password) {

            if (!foundFile)
            {
                // No rules file specified, accept any non-null password
                return (password != null) && (password.Length > 0);
            }

            // check min/max lengths
            if ((password == null) || 
                ((minLength > 0) && (password.Length < minLength)) || 
                ((maxLength > 0) && (password.Length > maxLength)))
            {
                return false;
            }

            string pwdToCheck = password;

            if ((inspectionLimit > 0) && (password.Length > inspectionLimit))
            {
                pwdToCheck = password.Substring(0, inspectionLimit);
            }

            int upperCount = 0;

            int lowerCount = 0;

            int numericCount = 0;

            int specialCount = 0;


            // We're only allowed {maxRepeat} consecutive repeated chars
            char prevCh = '\0';
            int prevCount = 0;
            bool repeatedChars = false;

            foreach (char ch in pwdToCheck)
            {
                if (Char.IsLetter(ch))
                {
                    if (Char.IsUpper(ch))
                    {
                        ++upperCount;
                    }
                    else if (Char.IsLower(ch))
                    {
                        ++lowerCount;
                    }
                }
                else if (Char.IsDigit(ch))
                {
                    ++numericCount;
                }
                else
                {
                    ++specialCount;
                }
 
                // Are we checking for consecutive repeating chars?
                if (maxRepeats > 0) {

                    if (ch == prevCh)
                    {
                        prevCount++;
                    }
                    else
                    {
                        prevCount = 0;
                    }

                    repeatedChars = repeatedChars || (prevCount > (maxRepeats - 1));
                    if (repeatedChars)
                    {
                        // Fail fast...no reason to keep checking password, we already know 
                        // we have an invalid password
                        return false;
                    }
                }
                prevCh = ch;
            }

            if ((minUpper > 0) && (upperCount < minUpper))
            {
                return false;
            }

            if ((minLower > 0) && (lowerCount < minLower))
            {
                return false;
            }

            if ((minNumeric > 0) && (numericCount < minNumeric))
            {
                return false;
            }

            if ((minSpecial > 0) && (specialCount < minSpecial))
            {
                return false;
            }

            if ((minAlpha > 0) && ((upperCount + lowerCount) < minAlpha))
            {
                return false;
            }

            if ((minNonAlpha > 0) && ((numericCount + specialCount) < minNonAlpha))
            {
                return false;
            }


            return true;

        }
    }
}
