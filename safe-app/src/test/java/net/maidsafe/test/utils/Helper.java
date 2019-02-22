// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.
package net.maidsafe.test.utils;


import net.maidsafe.api.Session;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


public final class Helper {

    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private Helper() {
        // Constructor intentionally empty
    }

    public static final int BYTE_SIZE = 1024;

    public static File copyConfigFiles() throws Exception {
        File generatedDir = getGeneratedDirectory();
        copyFile("log.toml", generatedDir, null);
        String appName = Session.getAppStem().get();
        copyFile("safe_core.config", generatedDir, appName);
        return  generatedDir;
    }

    private static void copyFile(final String fileName, final File destination, final String appName) throws Exception {
        File sourceFile = new File(System.getProperty("user.dir") + "/../config/" + fileName);
        StringBuilder destFileName = new StringBuilder(fileName);
        if (appName != null) {
            destFileName.insert(0, appName + ".");
        }
        final File file = new File(destination, new String(destFileName));
        final InputStream inputStream = new FileInputStream(sourceFile);
        copy(inputStream, file.getAbsoluteFile());
    }

    public static void copy(final InputStream inputStream, final File dst) throws Exception {
        try (InputStream in = inputStream) {
            try (OutputStream out = new FileOutputStream(dst)) {
                byte[] buf = new byte[BYTE_SIZE];
                int len;
                while ((len = in.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }
            }
        }
    }

    private static File getGeneratedDirectory() throws Exception {
        File generatedDir = new File("custom_config" + System.nanoTime());
        if (!generatedDir.mkdir()) {
            throw new IOException("Failed to create temp directory " + generatedDir.getName());
        }
        generatedDir.deleteOnExit();
        return generatedDir;
    }

    public static String randomAlphaNumeric(final int count) {
        StringBuilder builder = new StringBuilder();
        int c = count;
        while (c-- != 0) {
            int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

}
