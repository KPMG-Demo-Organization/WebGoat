/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import java.util.ArrayList;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("SqlInjectionMitigations/servers")
@Slf4j
public class Servers {

  private final LessonDataSource dataSource;

  // Allowed columns for sorting
  private static final List<String> ALLOWED_COLUMNS = List.of(
    "id",
    "hostname",
    "ip",
    "mac",
    "status",
    "description"
  );

  @AllArgsConstructor
  @Getter
  private class Server {

    private String id;
    private String hostname;
    private String ip;
    private String mac;
    private String status;
    private String description;
  }

  public Servers(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public List<Server> sort(@RequestParam String column) throws Exception {
    List<Server> servers = new ArrayList<>();

    // Validate column name against allowed list
    if (!ALLOWED_COLUMNS.contains(column)) {
      throw new IllegalArgumentException("Invalid column name");
    }

    try (var connection = dataSource.getConnection()) {
      String sql =
        "select id, hostname, ip, mac, status, description from SERVERS where status <> 'out of order' order by " + column;
      try (var statement = connection.prepareStatement(sql)) {
        try (var rs = statement.executeQuery()) {
          while (rs.next()) {
            Server server =
                new Server(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getString(4),
                    rs.getString(5),
                    rs.getString(6));
            servers.add(server);
          }
        }
      }
    }
    return servers;
  }
}
