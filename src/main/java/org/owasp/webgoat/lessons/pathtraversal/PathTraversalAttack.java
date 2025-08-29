/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversalvulnerability;

import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import javax.servlet.http.HttpServletResponse;
import java.nio.file.Path;
import java.nio.file.Paths;

@Component
@RestController
@RequestMapping("/PathTraversal")
public class PathTraversalVulnerability {

    private static final String BASE_DIRECTORY = "/var/app/data/";

    @GetMapping("/read")
    public void readFile(@RequestParam("filename") String filename, HttpServletResponse response) throws IOException {
        // Validate user input to prevent path traversal vulnerabilities
        Path basePath = Paths.get(BASE_DIRECTORY).toAbsolutePath().normalize();
        Path filePath = basePath.resolve(filename).normalize();
        if (!filePath.startsWith(basePath)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file path");
            return;
        }
        File file = filePath.toFile();
        if (file.exists() && file.isFile()) {
            try (FileInputStream fis = new FileInputStream(file);
                 OutputStream os = response.getOutputStream()) {
                response.setContentType("text/plain");
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
        }
    }
}


