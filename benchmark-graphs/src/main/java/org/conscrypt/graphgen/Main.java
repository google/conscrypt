/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt.graphgen;

import static java.nio.file.FileVisitResult.CONTINUE;

import com.bazaarvoice.jolt.Chainr;
import com.bazaarvoice.jolt.JsonUtils;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.List;

/**
 * Utility to convert from the JMH JSON output to an HTML file.
 */
public class Main {

  public static final String JSON_TEMPLATES = "/json/templates/";
  public static final String HTML_TEMPLATES = "/html/";

  public static void main(String[] args) throws IOException, URISyntaxException {
    if (args.length != 3) {
      System.err.println("Usage: graphgen [template] [input.json] [output.html]");
      listAllResources(System.err);
      System.exit(1);
    }

    try (InputStream spec = Main.class.getResourceAsStream(JSON_TEMPLATES + args[0]);
        InputStream jmhIn = new BufferedInputStream(new FileInputStream(args[1]));
        OutputStream output = new BufferedOutputStream(new FileOutputStream(args[2]))) {
      writeHtml(output, "header.html");
      convertJmhJsonData(spec, jmhIn, output);
      writeHtml(output, "footer.html");
    }
  }

  private static void writeHtml(OutputStream out, String name) throws IOException {
    InputStream header = Main.class.getResourceAsStream(HTML_TEMPLATES + name);
    byte[] buffer = new byte[4096];
    int numRead;
    while ((numRead = header.read(buffer)) != -1) {
      out.write(buffer, 0, numRead);
    }
  }

  /**
   * Load the JSON template data and convert it.
   */
  private static void convertJmhJsonData(InputStream specIn, InputStream jmhIn, OutputStream out) throws IOException {
    List<?> chainrConfig = JsonUtils.jsonToList(specIn);
    Chainr chainr = Chainr.fromSpec(chainrConfig);
    List<Object> input = JsonUtils.jsonToList(jmhIn);
    Object jsonOutput = chainr.transform(input);
    out.write(JsonUtils.toJsonString(jsonOutput).getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Lists all the JSON templates in the Classpath.
   */
  private static void listAllResources(PrintStream err) throws IOException, URISyntaxException {
    URI uri = Main.class.getResource(JSON_TEMPLATES).toURI();

    final Path templatesPath;
    if (uri.getScheme().equals("jar")) {
      FileSystem fs = FileSystems.newFileSystem(uri, Collections.emptyMap());
      templatesPath = fs.getPath(JSON_TEMPLATES);
    } else {
      templatesPath = Paths.get(uri);
    }

    err.println("Possible templates:");
    PrintFileNames pfn = new PrintFileNames("  ", err);
    Files.walkFileTree(templatesPath, pfn);
  }

  private static class PrintFileNames extends SimpleFileVisitor<Path> {
    private final String prefix;
    private final PrintStream out;

    public PrintFileNames(String prefix, PrintStream out) {
      this.prefix = prefix;
      this.out = out;
    }

    @Override
    public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes)
        throws IOException {
      out.println(prefix + path.getFileName());
      return CONTINUE;
    }
  }
}
