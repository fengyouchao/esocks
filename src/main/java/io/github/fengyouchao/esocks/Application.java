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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fucksocks.client.SocksProxy;
import fucksocks.client.SocksProxyFactory;
import fucksocks.common.SSLConfiguration;
import fucksocks.common.methods.NoAuthencationRequiredMethod;
import fucksocks.common.methods.SocksMethod;
import fucksocks.common.methods.UsernamePasswordMethod;
import fucksocks.server.GenericSocksProxyServer;
import fucksocks.server.SSLSocksProxyServer;
import fucksocks.server.Socks5Handler;
import fucksocks.server.SocksProxyServer;
import fucksocks.server.manager.User;
import fucksocks.server.UsernamePasswordAuthenticator;
import fucksocks.server.filters.IPSessionFilter;
import fucksocks.server.filters.IPSessionFilter.Mode;
import fucksocks.server.filters.SessionFilter;



public class Application {

  private static final Logger logger = LoggerFactory.getLogger(Application.class);

  /**
   * @param args Arguments
   */
  public static void main(String[] args) {
    int port = PORT;
    boolean noneAuth = true;
    int maxConnection = CONNECTION_NUMBER;
    int bufferSize = BUFFER_SIZE;
    int timeout = TIMEOUT;
    List<SessionFilter> sessionFilters = new ArrayList<>();
    List<User> users = new ArrayList<>();
    SocksProxy proxy = null;
    SSLConfiguration configuration = null;

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
          port = getPort(strs[1]);
        }
      } else if (args[i].equals("-p")) {
        if (i + 1 < args.length) {
          port = getPort(args[i + 1]);
          i++;
        }
      } else if (args[i].equals("-u")) {
        if (i + 1 < args.length) {
          loadUsers(users, args[i + 1]);
          noneAuth = false;
          i++;
        }
      } else if (args[i].startsWith("--user=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          loadUsers(users, strs[1]);
          noneAuth = false;
        }
      } else if (args[i].startsWith("--none-auth=")) {
        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          if (strs[1].equals("true")) {
            noneAuth = true;
          } else if (strs[1].equals("false")) {
            noneAuth = false;
          } else {
            logger.error("[--none-auth] should be [true] or [false]");
            System.exit(-1);
          }
        }
      } else if (args[i].startsWith("--max-connection=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          try {
            maxConnection = Integer.parseInt(strs[1]);
          } catch (Exception e) {
            logger.error("[--max-connection] must be a number");
            System.exit(-1);
          }
        }
      } else if (args[i].startsWith("--buffer-size=")) {
        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          try {
            bufferSize = Integer.parseInt(strs[1]);
          } catch (Exception e) {
            logger.error("[--buffer-size] must be a number");
            System.exit(-1);
          }
        }
      } else if (args[i].startsWith("--white-list=") || args[i].startsWith("--black-list=")) {
        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          IPSessionFilter sessionFilter = new IPSessionFilter();
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
            logger.error(
                "[{}] formate error. For example:--white-list=1.1.1.1-1.1.2.255,192.128.22.1",
                args[i]);
            System.exit(-1);
          }
        }
      } else if (args[i].equals("-P")) {
        if (i + 1 < args.length) {
          String proxyConfig = args[i + 1];
          proxy = configProxy(proxyConfig);
          i++;
        }
      } else if (args[i].startsWith("--proxy=")) {

        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          proxy = configProxy(strs[1]);
        }
      } else if (args[i].startsWith("--ssl=")) {
        String[] strs = args[i].split("=");
        if (strs.length == 2) {
          configuration = SSLConfiguration.parse(strs[1]);
        }
      } else {
        logger.error("Unknown argument [{}]", args[i]);
        System.exit(-1);
      }

    }

    SocksProxyServer socksProxyServer = null;
    if (configuration == null) {
      socksProxyServer =
          new GenericSocksProxyServer(Socks5Handler.class,
              Executors.newFixedThreadPool(maxConnection));
    } else {
      socksProxyServer =
          new SSLSocksProxyServer(Socks5Handler.class, Executors.newFixedThreadPool(maxConnection),
              configuration);
    }
    UsernamePasswordAuthenticator authenticator = new UsernamePasswordAuthenticator();
    for (User user : users) {
      authenticator.addUser(user.getUsername(), user.getPassword());
    }
    SocksMethod usernamePasswordMethod = new UsernamePasswordMethod(authenticator);


    socksProxyServer.setBufferSize(bufferSize);
    socksProxyServer.setTimeout(timeout);
    if (proxy != null) {
      logger.info("Using proxy:{}", proxy);
    }
    socksProxyServer.setProxy(proxy);

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
        logger.error(
            "[ERROR]:Port[{}] already in use.You can change port by using [-p] or [--port=NUM]",
            port);
        System.exit(-1);
      } else {
        e.printStackTrace();
      }
    }

    logger.info("Start SOCKS5 server at port:{}", port);
  }

  private static int getPort(String port) {
    try {
      return Integer.parseInt(port);
    } catch (NumberFormatException e) {
      logger.error("[-p] must be a number");
      System.exit(-1);
    }
    return 1080;
  }

  private static SocksProxy configProxy(String proxyConfigs) {
    SocksProxy proxy = null;
    SocksProxy temp = null;
    String[] proxyStrings = proxyConfigs.split("->");
    for (int i = 0; i < proxyStrings.length; i++) {
      String value = proxyStrings[i];
      try {
        if (i == 0) {
          temp = SocksProxyFactory.parse(value);
          proxy = temp;
        } else {
          SocksProxy socksProxy = SocksProxyFactory.parse(value);
          temp.setChainProxy(socksProxy);
          temp = socksProxy;
        }
      } catch (Exception e) {
        e.printStackTrace();
      }

    }
    return proxy;
  }

  private static void printUsage() {
    System.out.println("Usage:");
    System.out.println("\t-p,--port=PORT\n\t\tSet bind port. 1080 is default.");
    System.out.println("\t-u,--user=USERNAME:PASSWORD,USERNAME2:PASSWORD2\n\t\tAdd users.");
    System.out
        .println("\t--none-auth=[true|false]\n\t\tSupport anonymouse authentication. False is default.");
    System.out.println("\t--max-connection=NUMB\n\t\tMax number of connection. 100 is default.");
    System.out.println("\t--timeout=NUM\n\t\tTimeout in millisecond. 1 munite is default.");
    System.out.println("\t--buffer-size=NUM\n\t\tBuffer size in byte. 1MB is default.");
    System.out.println("\t--white-list=IP-IP,IP\n\t\tSet a white IP list.");
    System.out.println("\t--black-list=IP-IP,IP\n\t\tSet a black IP list.");
    System.out
        .println("\t-P,--proxy=IP,PORT,USERNAME,PASSWORD->IP2,PORT2,USERNAME2,PASSWORD2\n\t\t"
            + "Set SOCKS5 proxy.If there is more than one proxy, esocks will regard them as proxy "
            + "chain. Esocks only support TCP proxy.");
    System.out
        .println("\t--ssl=KEY_STORE,KEY_STORE_PASSWORD,TRUST_KEY_STORE,TRUST_KEY_STORE_PASSWORD\n\t\tUse SSL.");
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
