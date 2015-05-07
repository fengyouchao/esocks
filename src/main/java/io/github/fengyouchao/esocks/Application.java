/*
 * Copyright 2015-2025 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package io.github.fengyouchao.esocks;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

import fucksocks.common.methods.NoAuthencationRequiredMethod;
import fucksocks.common.methods.SocksMethod;
import fucksocks.common.methods.UsernamePasswordMethod;
import fucksocks.server.GenericSocksProxyServer;
import fucksocks.server.Socks5Handler;
import fucksocks.server.SocksProxyServer;
import fucksocks.server.User;
import fucksocks.server.UsernamePasswordAuthenticator;
import fucksocks.server.filters.IpSessionFilter;
import fucksocks.server.filters.IpSessionFilter.Mode;
import fucksocks.server.filters.SessionFilter;



public class Application {

  /**
   * @param args
   */
  public static void main(String[] args) {
    int port = PORT;
    boolean noneAuth = true;
    int maxConnection = CONNECTION_NUMBER;
    int bufferSize = BUFFER_SIZE;
    int timeout = TIMEOUT;
    List<SessionFilter> sessionFilters = new ArrayList<>();
    List<User> users = new ArrayList<>();

    for (int i = 0; i < args.length; i++) {
      if (args[i].equals("-h")) {
        printUsage();
        System.exit(0);
      }
    }


    for (int i = 0; i < args.length; i++) {
      if (args[i].startsWith("--port=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          port = Integer.parseInt(strs[1]);
        }
      }

      if (args[i].equals("-p")) {
        if (i + 1 < args.length) {
          try {
            port = Integer.parseInt(args[i + 1]);
          } catch (Exception e) {
            System.out.println("[ERROR]:[-p] must be a number");
            System.exit(-1);
          }
        }
      }

      if (args[i].equals("-u")) {
        if (i + 1 < args.length) {
          loadUsers(users, args[i + 1]);
        }
      }

      if (args[i].startsWith("--user=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          loadUsers(users, strs[1]);
        }
      }

      if (args[i].startsWith("--none-auth=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          if (strs[1].equals("true")) {
            noneAuth = true;
          } else if (strs[1].equals("false")) {
            noneAuth = false;
          }
        }
      }

      if (args[i].startsWith("--max-connection=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          try {
            maxConnection = Integer.parseInt(strs[1]);
          } catch (Exception e) {
            System.out.println("[ERROR]:[--max-connection] must be a number");
            System.exit(-1);
          }
        }
      }

      if (args[i].startsWith("--buffer-size=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          try {
            bufferSize = Integer.parseInt(strs[1]);
          } catch (Exception e) {
            System.out.println("[ERROR]:[--buffer-size] must be a number");
            System.exit(-1);
          }
        }
      }

      if (args[i].startsWith("--white-list=") || args[i].startsWith("--black-list=")) {
        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          IpSessionFilter sessionFilter = new IpSessionFilter();
          if (args[i].startsWith("--black-list")) {
            sessionFilter.setMode(Mode.BLACK_LIST);
          }
          try {
            if (!strs[1].contains(",")) {
              if (strs[1].contains("-")) {
                sessionFilter.addIpRange(strs[1]);
              } else {
                sessionFilter.addIp(strs[1]);
              }

            } else {
              String[] whiteIpList = strs[1].split(",");
              System.out.println(strs[1]);

              for (String ipstirng : whiteIpList) {
                if (ipstirng.contains("-")) {
                  sessionFilter.addIpRange(ipstirng);
                } else {
                  sessionFilter.addIp(ipstirng);
                }
              }
            }
            sessionFilters.add(sessionFilter);
          } catch (Exception e) {
            System.out.println("[ERROR]:[" + args[i]
                + "] formate error. For example:--white-list=1.1.1.1-1.1.2.255,192.128.22.1");
            System.exit(-1);
          }
        }
      }

    }

    SocksProxyServer socksProxyServer =
        new GenericSocksProxyServer(Socks5Handler.class,
            Executors.newFixedThreadPool(maxConnection));

    UsernamePasswordAuthenticator authenticator = new UsernamePasswordAuthenticator();
    for (User user : users) {
      authenticator.addUser(user.getUsername(), user.getPassword());
    }
    SocksMethod usernamePasswordMethod = new UsernamePasswordMethod(authenticator);


    socksProxyServer.setBufferSize(bufferSize);
    socksProxyServer.setTimeout(timeout);

    for (SessionFilter filter : sessionFilters) {
      socksProxyServer.addSessionFilter(filter);
    }

    if (noneAuth) {
      socksProxyServer
          .setSupportMethods(new NoAuthencationRequiredMethod(), usernamePasswordMethod);
    } else {
      socksProxyServer.setSupportMethods(usernamePasswordMethod);
    }

    try {
      socksProxyServer.start(port);
    } catch (IOException e) {
      if (e.getMessage().equals("Address already in use")) {
        System.out.println("[ERROR]:Port[" + port
            + "] already in use.You can change port by using [-p] or [--port=NUM]");
        System.exit(-1);
      } else {
        e.printStackTrace();
      }
    }

    System.out.println("Start SOCKS5 server at port:" + port);
  }

  private static void printUsage() {
    System.out.println("Usage:");
    System.out.println("\t-p,--port=PORT:Set bind port. 1080 is default.");
    System.out.println("\t-u,--user=USERNAME:PASSWORD,USERNAME2:PASSWORD2: Add users.");
    System.out
        .println("\t--none-auth=[true|false]: Support anonymouse authentication. True is default.");
    System.out.println("\t--max-connection=NUMB: Max number of connection. 100 is default.");
    System.out.println("\t--timeout=NUM: Timeout in millisecond. 1 munite is default.");
    System.out.println("\t--buffer-size=NUM Buffer size in byte. 1MB is default");
    System.out.println("\t--white-list=IP-IP,IP Set white IP lists");
    System.out.println("\t--black-list=IP-IP,IP Set black IP lists");
  }

  private static void loadUsers(List<User> users, String usersValue) {
    String[] usersInfo = usersValue.split(",");
    for (String userStr : usersInfo) {
      String[] userInfo = userStr.split(":");
      if (userInfo.length == 2) {
        String username = userInfo[0];
        String password = userInfo[1];
        users.add(new User(username, password));
      }
    }
  }

  private static int PORT = 1080;
  private static int CONNECTION_NUMBER = 100;
  private static int BUFFER_SIZE = 1024 * 1024;
  private static final int TIMEOUT = 60000;

}
