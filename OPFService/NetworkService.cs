﻿// This file is part of OpenPasswordFilter.
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
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Diagnostics;

namespace OPFService {
    class NetworkService {
        OPFDictionary dict;
        OPFRules rules;

        public NetworkService(OPFDictionary d, OPFRules r) {
            dict = d;
            rules = r;
        }

        public void main() {
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            IPEndPoint local = new IPEndPoint(ip, 5995);
            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try {
                listener.Bind(local);
                listener.Listen(64);
                while (true) {
                    Socket client = listener.Accept();
                    new Thread(() => handle(client)).Start();
                }
            } catch (Exception e) {
                Console.WriteLine("Exception caught: {0}", e);
                using (EventLog eventLog = new EventLog("Application"))
                {
                    eventLog.Source = "Application";
                    eventLog.WriteEntry("OpenPasswordFilter service failed to bind to port 5995", EventLogEntryType.Information, 101, 1);
                }
            }
        }

        public void handle(Socket client) {
            try {
                NetworkStream netStream = new NetworkStream(client);
                StreamReader istream = new StreamReader(netStream);
                StreamWriter ostream = new StreamWriter(netStream);
                string command = istream.ReadLine();
                if (command == "test") {
                    string password = istream.ReadLine();
                    if (!rules.CheckPassword(password)) {
                        // Fail fast, no need to check dictionary
                        ostream.WriteLine("false");
                        ostream.Flush();
                        return;
                    }
                    bool containsPassword = dict.contains(password);
                    ostream.WriteLine(containsPassword ? "false" : "true");
                    ostream.Flush();
                } else {
                    using (EventLog eventLog = new EventLog("Application"))
                    {
                        eventLog.Source = "Application";
                        eventLog.WriteEntry("OpenPasswordFilter service did not recieve test command", EventLogEntryType.Information, 101, 1);
                    }
                }
            } catch (Exception e) {
                using (EventLog eventLog = new EventLog("Application"))
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    eventLog.Source = "Application";
                    eventLog.WriteEntry("OpenPasswordFilter service handle call failed to perform test", EventLogEntryType.Information, 101, 1);
                }

            }
            client.Close();
        }

    }
}
