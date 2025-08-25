/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionAttack implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionAttack(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    // Example vulnerable SQL logic for demonstration
    try (Connection connection = dataSource.getConnection();
         Statement statement = connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {

      // Vulnerable SQL: directly concatenates user input
      String sql = "SELECT * FROM users WHERE username = '" + query + "'";
      ResultSet rs = statement.executeQuery(sql);

      StringBuilder result = new StringBuilder();
      int rowCount = 0;
      while (rs.next()) {
        result.append(rs.getString("username")).append("<br>");
        rowCount++;
      }
      if (rowCount > 1) {
        return success(this)
            .feedback("sql-injection-success")
            .output("Multiple users returned:<br>" + result.toString())
            .build();
      } else if (rowCount == 1) {
        return failed(this)
            .feedback("sql-injection-failed")
            .output("User returned:<br>" + result.toString())
            .build();
      } else {
        return failed(this)
            .feedback("sql-injection-failed")
            .output("No users found.")
            .build();
      }
    } 
    catch (SQLException e) {
      return failed(this).feedback("sql-injection-error").output("SQL Error: " + e.getMessage()).build();
    }
  }
}