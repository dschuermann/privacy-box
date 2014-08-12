/*
 * Copyright (C) 2013 The Android Open Source Project
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

package org.sufficientlysecure.privacybox;

import static org.sufficientlysecure.privacybox.VaultProvider.TAG;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.database.MatrixCursor;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.provider.DocumentsContract.Document;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.OpenPgpMetadata;
import org.openintents.openpgp.util.OpenPgpApi;
import org.openintents.openpgp.util.OpenPgpServiceConnection;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.lang.reflect.Constructor;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Represents a single encrypted document stored on disk. Handles encryption,
 * decryption, and authentication of the document when requested.
 * <p/>
 * Not inherently thread safe.
 */
public class EncryptedDocument {

    private final long mDocId;
    private final File mFile;

    OpenPgpServiceConnection mServiceConnection;
    Context mContext;

    /**
     * Create an encrypted document.
     *
     * @param docId     the expected {@link Document#COLUMN_DOCUMENT_ID} to be
     *                  validated when reading metadata.
     * @param directory location on disk where the encrypted document is stored. May
     *                  not exist yet.
     */
    public EncryptedDocument(long docId, File directory, Context context, OpenPgpServiceConnection serviceConnection)
            throws GeneralSecurityException {
        mServiceConnection = serviceConnection;
        mContext = context;

        mDocId = docId;
        mFile = new File(directory, String.valueOf(docId) + ".gpg");
    }

    public File getFile() {
        return mFile;
    }

    @Override
    public String toString() {
        return mFile.getName();
    }

    /**
     * Decrypt and return parsed metadata section from this document.
     *
     * @throws DigestException if metadata fails MAC check, or if
     *                         {@link Document#COLUMN_DOCUMENT_ID} recorded in metadata is
     *                         unexpected.
     */
    public JSONObject readMetadata() throws IOException, GeneralSecurityException {
        InputStream fis = new FileInputStream(mFile);

        try {
            Intent data = new Intent();
            data.setAction(OpenPgpApi.ACTION_DECRYPT_METADATA);
            data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
            OpenPgpApi api = new OpenPgpApi(mContext, mServiceConnection.getService());
            Intent result = api.executeApi(data, fis, null);

            switch (result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
                case OpenPgpApi.RESULT_CODE_SUCCESS: {
                    Log.d(VaultProvider.TAG, "readMetadata RESULT_CODE_SUCCESS");

//                    tempFile.renameTo(mFile);


                    // TODO: better handling of errors
                    OpenPgpMetadata openPgpMeta;
                    if (result.hasExtra(OpenPgpApi.RESULT_METADATA)) {
                        openPgpMeta = result.getParcelableExtra(OpenPgpApi.RESULT_METADATA);
                    } else {
                        throw new IOException();
                    }

                    Log.d(TAG, "metadata for " + mDocId + ": " + openPgpMeta);

                    String filenameHeader = openPgpMeta.getFilename();
                    long size = openPgpMeta.getOriginalSize();
                    long modTime = openPgpMeta.getModificationTime();

                    final JSONObject meta = new JSONObject();

                    /*
                     * If the filename header of the encrypted pgp file contains
                     * JSON, we are dealing with a directory.
                     * Instead of the actual filename, directories include JSON encoded mime type
                     * and an array of all child documents.
                     */
                    if (filenameHeader.contains("{")) { // JSON with high probability
                        meta.put(Document.COLUMN_MIME_TYPE, Document.MIME_TYPE_DIR);

                        JSONObject json = new JSONObject(filenameHeader);
                        final String name = json.getString(Document.COLUMN_DISPLAY_NAME);
                        final JSONArray children = json.getJSONArray(VaultProvider.KEY_CHILDREN);

                        Log.d(VaultProvider.TAG, "json from filename header: " + json);
                        Log.d(VaultProvider.TAG, "name: " + name);
                        Log.d(VaultProvider.TAG, "children: " + children);

                        meta.put(Document.COLUMN_DISPLAY_NAME, name);
                        meta.put(VaultProvider.KEY_CHILDREN, children);
                    } else {
                        String mimeType = openPgpMeta.getMimeType();
                        meta.put(Document.COLUMN_MIME_TYPE, mimeType);

                        meta.put(Document.COLUMN_DISPLAY_NAME, filenameHeader);
                    }
                    meta.put(Document.COLUMN_DOCUMENT_ID, mDocId);
                    meta.put(Document.COLUMN_SIZE, size);
                    meta.put(Document.COLUMN_LAST_MODIFIED, modTime);

                    return meta;
                }
                case OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED: {
                    Log.d(VaultProvider.TAG, "readMetadata RESULT_CODE_USER_INTERACTION_REQUIRED");

                    // directly try again, something different needs user interaction again...
                    PendingIntent pi = result.getParcelableExtra(OpenPgpApi.RESULT_INTENT);

                    Handler handler = new Handler(mContext.getMainLooper(), new Handler.Callback() {
                        @Override
                        public boolean handleMessage(Message msg) {
                            Log.d(VaultProvider.TAG, "writeMetadataAndContent handleMessage");

                            // TODO: start again afterwards!!!
                            return true;
                        }
                    });
                    Messenger messenger = new Messenger(handler);

                    // start proxy activity and wait here for it finishing...
                    Intent proxy = new Intent(mContext, KeychainProxyActivity.class);
                    proxy.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    proxy.putExtra(KeychainProxyActivity.EXTRA_MESSENGER, messenger);
                    proxy.putExtra(KeychainProxyActivity.EXTRA_PENDING_INTENT, pi);

                    mContext.startActivity(proxy);
                    break;
                }
                case OpenPgpApi.RESULT_CODE_ERROR: {
                    Log.d(VaultProvider.TAG, "readMetadata RESULT_CODE_ERROR");

                    // TODO
                    OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
                    Log.e(VaultProvider.TAG, "error: " + error.getMessage());

//                handleError(error);
                    break;
                }
            }

            return null;
        } catch (JSONException e) {
            throw new IOException(e);
        } finally {
            fis.close();
        }
    }

    /**
     * Decrypt and read content section of this document, writing it into the
     * given pipe.
     * <p/>
     * Pipe is left open, so caller is responsible for calling
     * {@link ParcelFileDescriptor#close()} or
     * {@link ParcelFileDescriptor#closeWithError(String)}.
     *
     * @param contentOut write end of a pipe.
     * @throws DigestException if content fails MAC check. Some or all content
     *                         may have already been written to the pipe when the MAC is
     *                         validated.
     */
    public void readContent(ParcelFileDescriptor contentOut)
            throws IOException, GeneralSecurityException {
//        final RandomAccessFile f = new RandomAccessFile(mFile, "r");
//        try {
//            assertMagic(f);
//
//            if (f.length() <= CONTENT_OFFSET) {
//                throw new IOException("Document has no content");
//            }
//
//            // Skip over metadata section
//            f.seek(CONTENT_OFFSET);
//            readSection(f, new FileOutputStream(contentOut.getFileDescriptor()));
//
//        } finally {
//            f.close();
//        }
    }

    /**
     * Encrypt and write both the metadata and content sections of this
     * document, reading the content from the given pipe. Internally uses
     * {@link ParcelFileDescriptor#checkError()} to verify that content arrives
     * without errors. Writes to temporary file to keep atomic view of contents,
     * swapping into place only when write is successful.
     * <p/>
     * Pipe is left open, so caller is responsible for calling
     * {@link ParcelFileDescriptor#close()} or
     * {@link ParcelFileDescriptor#closeWithError(String)}.
     *
     * @param contentIn read end of a pipe.
     */
    public void writeMetadataAndContent(JSONObject meta, ParcelFileDescriptor contentIn)
            throws IOException, GeneralSecurityException {
        // Write into temporary file to provide an atomic view of existing
        // contents during write, and also to recover from failed writes.
        final String tempName = mFile.getName() + ".tmp_" + Thread.currentThread().getId();
        final File tempFile = new File(mFile.getParentFile(), tempName);

//        RandomAccessFile f = new RandomAccessFile(tempFile, "rw");
        try {


            // TODO: while not == RESULT_CODE_SUCCESS wait notify and stuff...
            // make this blocking!
            Intent data = new Intent();
            data.setAction(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT);

            InputStream is;
            String mimeType = meta.getString(Document.COLUMN_MIME_TYPE);
            if (Document.MIME_TYPE_DIR.equals(mimeType)) {
                // this is a directory! write only dir into content...
                is = new ByteArrayInputStream("dir".getBytes());

                /*
                  * combine mime type, display name, and children into one json!
                  */
                JSONObject json = new JSONObject();
                json.put(Document.COLUMN_MIME_TYPE, Document.MIME_TYPE_DIR);
                json.put(Document.COLUMN_DISPLAY_NAME, meta.getString(Document.COLUMN_DISPLAY_NAME));
                json.put(VaultProvider.KEY_CHILDREN, meta.getJSONArray(VaultProvider.KEY_CHILDREN));

                Log.d(VaultProvider.TAG, "json: " + json.toString());

                // write json into
                data.putExtra(OpenPgpApi.EXTRA_ORIGINAL_FILENAME, json.toString());
            } else {
                is = new FileInputStream(contentIn.getFileDescriptor());

                // TODO: no possibility to write mime type to pgp header, currently
                data.putExtra(OpenPgpApi.EXTRA_ORIGINAL_FILENAME, meta.getString(Document.COLUMN_DISPLAY_NAME));
            }


            data.putExtra(OpenPgpApi.EXTRA_USER_IDS, new String[]{"nopass@example.com"});
            data.putExtra(OpenPgpApi.EXTRA_ACCOUNT_NAME, "default");
            data.putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true); // TODO: fix later to false!
            OpenPgpApi api = new OpenPgpApi(mContext, mServiceConnection.getService());


            Intent result = api.executeApi(data, is, new FileOutputStream(tempFile));

            switch (result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
                case OpenPgpApi.RESULT_CODE_SUCCESS: {
                    Log.d(VaultProvider.TAG, "writeMetadataAndContent RESULT_CODE_SUCCESS");

                    tempFile.renameTo(mFile);

                    break;
                }
                case OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED: {
                    Log.d(VaultProvider.TAG, "writeMetadataAndContent RESULT_CODE_USER_INTERACTION_REQUIRED");

                    // directly try again, something different needs user interaction again...
                    PendingIntent pi = result.getParcelableExtra(OpenPgpApi.RESULT_INTENT);

                    Handler handler = new Handler(mContext.getMainLooper(), new Handler.Callback() {
                        @Override
                        public boolean handleMessage(Message msg) {
                            Log.d(VaultProvider.TAG, "writeMetadataAndContent handleMessage");

                            // TODO: start again afterwards!!!
                            return true;
                        }
                    });
                    Messenger messenger = new Messenger(handler);

                    // start proxy activity and wait here for it finishing...
                    Intent proxy = new Intent(mContext, KeychainProxyActivity.class);
                    proxy.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    proxy.putExtra(KeychainProxyActivity.EXTRA_MESSENGER, messenger);
                    proxy.putExtra(KeychainProxyActivity.EXTRA_PENDING_INTENT, pi);

                    mContext.startActivity(proxy);
                    break;
                }
                case OpenPgpApi.RESULT_CODE_ERROR: {
                    Log.d(VaultProvider.TAG, "writeMetadataAndContent RESULT_CODE_ERROR");

                    // TODO
                    OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
                    Log.e(VaultProvider.TAG, "error: " + error.getMessage());
                    break;
                }
            }

            // Truncate any existing data
//            f.setLength(0);

            // Write content first to detect size
//            if (contentIn != null) {
//                f.seek(CONTENT_OFFSET);
//                final int plainLength = writeSection(
//                        f, new FileInputStream(contentIn.getFileDescriptor()));
//                meta.put(Document.COLUMN_SIZE, plainLength);
//
//                // Verify that remote side of pipe finished okay; if they
//                // crashed or indicated an error then this throws and we
//                // leave the original file intact and clean up temp below.
//                contentIn.checkError();
//            }

//            meta.put(Document.COLUMN_DOCUMENT_ID, mDocId);
//            meta.put(Document.COLUMN_LAST_MODIFIED, System.currentTimeMillis());

            // Rewind and write metadata section
//            f.seek(0);
//            f.writeInt(MAGIC_NUMBER);

//            final ByteArrayInputStream metaIn = new ByteArrayInputStream(
//                    meta.toString().getBytes(StandardCharsets.UTF_8));
//            writeSection(f, metaIn);
//
//            if (f.getFilePointer() > CONTENT_OFFSET) {
//                throw new IOException("Metadata section was too large");
//            }

            // Everything written fine, atomically swap new data into place.
            // fsync() before close would be overkill, since rename() is an
            // atomic barrier.
//            f.close();

        } catch (JSONException e) {
            throw new IOException(e);
        } finally {
            // Regardless of what happens, always try cleaning up.
//            f.close();
            tempFile.delete();
        }
    }

    /**
     * Read and decrypt the section starting at the current file offset.
     * Validates MAC of decrypted data, throwing if mismatch. When finished,
     * file offset is at the end of the entire section.
     */
//    private void readSection(RandomAccessFile f, OutputStream out)
//            throws IOException, GeneralSecurityException {
//        final long start = f.getFilePointer();
//
//        final Section section = new Section();
//        section.read(f);
//
//        final IvParameterSpec ivSpec = new IvParameterSpec(section.iv);
//        mCipher.init(Cipher.DECRYPT_MODE, mDataKey, ivSpec);
//        mMac.init(mMacKey);
//
//        byte[] inbuf = new byte[8192];
//        byte[] outbuf;
//        int n;
//        while ((n = f.read(inbuf, 0, (int) Math.min(section.length, inbuf.length))) != -1) {
//            section.length -= n;
//            mMac.update(inbuf, 0, n);
//            outbuf = mCipher.update(inbuf, 0, n);
//            if (outbuf != null) {
//                out.write(outbuf);
//            }
//            if (section.length == 0) break;
//        }
//
//        section.assertMac(mMac.doFinal());
//
//        outbuf = mCipher.doFinal();
//        if (outbuf != null) {
//            out.write(outbuf);
//        }
//    }

    /**
     * Encrypt and write the given stream as a full section. Writes section
     * header and encrypted data starting at the current file offset. When
     * finished, file offset is at the end of the entire section.
     */
//    private int writeSection(RandomAccessFile f, InputStream in)
//            throws IOException, GeneralSecurityException {
//        final long start = f.getFilePointer();
//
//        // Write header; we'll come back later to finalize details
//        final Section section = new Section();
//        section.write(f);
//
//        final long dataStart = f.getFilePointer();
//
//        mRandom.nextBytes(section.iv);
//
//        final IvParameterSpec ivSpec = new IvParameterSpec(section.iv);
//        mCipher.init(Cipher.ENCRYPT_MODE, mDataKey, ivSpec);
//        mMac.init(mMacKey);
//
//        int plainLength = 0;
//        byte[] inbuf = new byte[8192];
//        byte[] outbuf;
//        int n;
//        while ((n = in.read(inbuf)) != -1) {
//            plainLength += n;
//            outbuf = mCipher.update(inbuf, 0, n);
//            if (outbuf != null) {
//                mMac.update(outbuf);
//                f.write(outbuf);
//            }
//        }
//
//        outbuf = mCipher.doFinal();
//        if (outbuf != null) {
//            mMac.update(outbuf);
//            f.write(outbuf);
//        }
//
//        section.setMac(mMac.doFinal());
//
//        final long dataEnd = f.getFilePointer();
//        section.length = dataEnd - dataStart;
//
//        // Rewind and update header
//        f.seek(start);
//        section.write(f);
//        f.seek(dataEnd);
//
//        return plainLength;
//    }

    /**
     * Header of a single file section.
     */
//    private static class Section {
//        long length;
//        final byte[] iv = new byte[DATA_KEY_LENGTH];
//        final byte[] mac = new byte[MAC_KEY_LENGTH];
//
//        public void read(RandomAccessFile f) throws IOException {
//            length = f.readLong();
//            f.readFully(iv);
//            f.readFully(mac);
//        }
//
//        public void write(RandomAccessFile f) throws IOException {
//            f.writeLong(length);
//            f.write(iv);
//            f.write(mac);
//        }
//
//        public void setMac(byte[] mac) {
//            if (mac.length != this.mac.length) {
//                throw new IllegalArgumentException("Unexpected MAC length");
//            }
//            System.arraycopy(mac, 0, this.mac, 0, this.mac.length);
//        }
//
//        public void assertMac(byte[] mac) throws DigestException {
//            if (mac.length != this.mac.length) {
//                throw new IllegalArgumentException("Unexpected MAC length");
//            }
//            byte result = 0;
//            for (int i = 0; i < mac.length; i++) {
//                result |= mac[i] ^ this.mac[i];
//            }
//            if (result != 0) {
//                throw new DigestException();
//            }
//        }
//    }

//    private static void assertMagic(RandomAccessFile f) throws IOException {
//        final int magic = f.readInt();
//        if (magic != MAGIC_NUMBER) {
//            throw new ProtocolException("Bad magic number: " + Integer.toHexString(magic));
//        }
//    }

}
