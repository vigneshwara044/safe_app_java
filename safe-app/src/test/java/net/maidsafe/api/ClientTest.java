// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.
package net.maidsafe.api;


import net.maidsafe.api.model.AuthResponse;
import net.maidsafe.api.model.ContainerResponse;
import net.maidsafe.api.model.DecodeResult;
import net.maidsafe.api.model.EncryptKeyPair;
import net.maidsafe.api.model.NativeHandle;
import net.maidsafe.api.model.Request;
import net.maidsafe.safe_app.AccountInfo;
import net.maidsafe.safe_app.AppExchangeInfo;
import net.maidsafe.safe_app.AuthReq;
import net.maidsafe.safe_app.ContainerPermissions;
import net.maidsafe.safe_app.ContainersReq;
import net.maidsafe.safe_app.MDataInfo;
import net.maidsafe.safe_app.PermissionSet;
import net.maidsafe.test.utils.Helper;
import net.maidsafe.test.utils.SessionLoader;

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientTest {

    static {
        SessionLoader.load();
    }
    public static final String APP_ID = "net.maidsafe.java.test";
    public static final int LENGTH = 10;
    static final int MUTATION_LIMIT = 1000;

    private static void copyFile(final String fileName, final File destination, final String appName) throws Exception {
        File sourceFile = new File(System.getProperty("user.dir") + "/../config/" + fileName);
        String destFileName = fileName;
        if (appName != null) {
            destFileName = appName + "." + destFileName;
        }
        final File file = new File(destination, destFileName);
        final InputStream inputStream = new FileInputStream(sourceFile);
        try {
            Files.copy(inputStream, file.toPath());
        } catch (IOException e) {
            throw new java.lang.RuntimeException(e);
        }
    }

    // Create an unregistered session.
    // Generate an encryption key pair and encrypt some text.
    // Decrypt and verify the text.
    @Test
    public void unregisteredAccessTest() throws Exception {
        Session unregisteredSession = Session.createTestApp(APP_ID).get();
        EncryptKeyPair encryptKeyPair = unregisteredSession.crypto.generateEncryptKeyPair().get();
        Assert.assertNotNull(encryptKeyPair);
        String keyString = Helper.randomAlphaNumeric(LENGTH);
        byte[] cipherText = unregisteredSession.crypto.encrypt(encryptKeyPair.getPublicEncryptKey(),
                encryptKeyPair.getSecretEncryptKey(), keyString.getBytes()).get();
        Assert.assertEquals(keyString, new String(
                unregisteredSession.crypto.decrypt(encryptKeyPair.getPublicEncryptKey(),
                        encryptKeyPair.getSecretEncryptKey(), cipherText).get()));
    }

    // Create a session.
    // Simulate the disconnection event and verify that the callback is fired.
    @Test
    public void disconnectionTest() throws Exception {
        Session client = Session.createTestApp(APP_ID).get();
        client.setOnDisconnectListener(o -> {
            Assert.assertFalse(client.isConnected());
            try {
                client.reconnect().get();
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Unable to reconnect");
            }
        });
        client.testSimulateDisconnect().get();
    }

    // Create a session with access to _public container.
    // Fetch the list of container permissions and verify them.
    // Fetch MDataInfo for the _public container and verify that mutations are allowed.
    @Test
    public void containerTest() throws Exception {
        ContainerPermissions[] permissions = new ContainerPermissions[1];
        permissions[0] = new ContainerPermissions("_public", new PermissionSet(true,
                true, true, true, true));
        AuthReq authReq = new AuthReq(new AppExchangeInfo(APP_ID, "",
                Helper.randomAlphaNumeric(LENGTH), Helper.randomAlphaNumeric(LENGTH)),
                false, permissions, 1, 0);
        Session session = Session.createTestAppWithAccess(authReq).get();

        List<ContainerPermissions> list = session.getContainerPermissions().get();

        Assert.assertEquals(session.getAppContainerName(APP_ID).get(), "apps/" + APP_ID);
        Assert.assertEquals(list.get(0).getAccess().getRead(), true);
        Assert.assertEquals(list.get(0).getAccess().getInsert(), true);
        Assert.assertEquals(list.get(0).getAccess().getDelete(), true);
        Assert.assertEquals(list.get(0).getAccess().getUpdate(), true);
        Assert.assertEquals(list.get(0).getAccess().getManagePermission(), true);
        Assert.assertEquals(list.get(0).getContName(), "_public");

        MDataInfo containerMDataInfo = session.getContainerMDataInfo("_public").get();

        NativeHandle entriesHandle = session.mDataEntryAction.newEntryAction().get();
        String keyString = Helper.randomAlphaNumeric(LENGTH);
        String valueString = Helper.randomAlphaNumeric(LENGTH);
        session.mDataEntryAction.insert(entriesHandle, keyString.getBytes(), valueString.getBytes()).get();
        session.mData.mutateEntries(containerMDataInfo, entriesHandle).get();

    }

    //Create a temporary directory and copy the log.toml and safe_core.config files with
    // unlimited mutations set to true.
    // Set the path to the temporary directory as an additional search path.
    // Initialize logging to a Client.log file.
    // Create a session and perform some operations.
    // Verify that the log file exists and is not null.
    // Verify the increase in mutations done.
    // Verify that the number of mutations available is always 1000.
    @Test
    public void clientActionsTest() throws Exception {
        File generatedDir = new File("custom_config" + System.nanoTime());
        if (!generatedDir.mkdir()) {
            throw new IOException("Failed to create temp directory " + generatedDir.getName());
        }
        copyFile("log.toml", generatedDir, null);
        String appName = Session.getAppStem().get();
        copyFile("safe_core.config", generatedDir, appName);

        Session.setAdditionalSearchPath(generatedDir.getPath());
        Session.initLogging("Client.log").get();

        ContainerPermissions[] permissions = new ContainerPermissions[1];
        permissions[0] = new ContainerPermissions("_public", new PermissionSet(true,
                                        true, true, true, true));
        AuthReq authReq = new AuthReq(new AppExchangeInfo(APP_ID, "",
                              Helper.randomAlphaNumeric(LENGTH), Helper.randomAlphaNumeric(LENGTH)),
                             true, permissions, 1, 0);
        Session session = Session.createTestAppWithAccess(authReq).get();
        String logOutputPath = session.getLogOutputPath("Client.log").get();
        File file = new File(logOutputPath);
        BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
        String line = bufferedReader.readLine();
        Assert.assertNotEquals(line, "null");
        MDataInfo containerMDI = session.getContainerMDataInfo("_public").get();

        AccountInfo accountInfo = session.getAccountInfo().get();
        long mutationsDone =  accountInfo.getMutationsDone();

        String keyString = Helper.randomAlphaNumeric(LENGTH);
        String valueString = Helper.randomAlphaNumeric(LENGTH);

        accountInfo = session.getAccountInfo().get();
        long mutationAvailable = accountInfo.getMutationsAvailable();
        Assert.assertEquals(MUTATION_LIMIT, mutationAvailable);

        NativeHandle actionHandle = session.mDataEntryAction.newEntryAction().get();
        session.mDataEntryAction.insert(actionHandle, keyString.getBytes(), valueString.getBytes()).get();
        session.mData.mutateEntries(containerMDI, actionHandle).get();

        accountInfo = session.getAccountInfo().get();
        mutationAvailable = accountInfo.getMutationsAvailable();
        Assert.assertEquals(MUTATION_LIMIT, mutationAvailable);
        Assert.assertEquals(mutationsDone, accountInfo.getMutationsDone() - 1);
    }

    // Create a session with access to _public container.
    // Create additional permissions for _music container.
    // Refresh access info and insert entry into the container.
    @Test
    public void containerRequestTest() throws Exception {

        String locator = Helper.randomAlphaNumeric(LENGTH);
        String secret = Helper.randomAlphaNumeric(LENGTH);
        Authenticator authenticator = Authenticator.createAccount(locator, secret,
                Helper.randomAlphaNumeric(LENGTH)).get();

        ContainerPermissions[] permissions = new ContainerPermissions[1];
        permissions[0] = new ContainerPermissions("_public", new PermissionSet(true,
                true, true, true, true));
        AppExchangeInfo appExchangeInfo = new AppExchangeInfo(APP_ID, "", Helper.randomAlphaNumeric(LENGTH),
                                                Helper.randomAlphaNumeric(LENGTH));
        AuthReq authReq = new AuthReq(appExchangeInfo, true, permissions, 1, 0);
        Request ipcMessage = Session.encodeAuthReq(authReq).get();
        String encodedResponse = TestHelper.handleIpcRequest(authenticator, ipcMessage.getUri());
        DecodeResult decodeResult = Session.decodeIpcMessage(encodedResponse).get();
        AuthResponse authResponse = (AuthResponse) decodeResult;
        Session session = Session.connect(authReq.getApp().getId(), authResponse.getAuthGranted()).get();

        ContainerPermissions[] newPermissions = new ContainerPermissions[1];
        newPermissions[0] = new ContainerPermissions("_music", new PermissionSet(true,
                true, true, true, true));
        ContainersReq containersReq = new ContainersReq(appExchangeInfo, newPermissions, 1, 0);

        Request request = Session.getContainersReq(containersReq).get();
        String containersResp = TestHelper.handleIpcRequest(authenticator, request.getUri());
        decodeResult = session.decodeIpcMessage(containersResp).get();
        ContainerResponse containerResponse = (ContainerResponse) decodeResult;
        Assert.assertEquals(containerResponse.getReqId(), request.getReqId());
        session.refreshAccessInfo();

        NativeHandle actionHandle = session.mDataEntryAction.newEntryAction().get();
        String keyString = Helper.randomAlphaNumeric(LENGTH);
        String valueString = Helper.randomAlphaNumeric(LENGTH);
        session.mDataEntryAction.insert(actionHandle, keyString.getBytes(), valueString.getBytes()).get();
    }
}
